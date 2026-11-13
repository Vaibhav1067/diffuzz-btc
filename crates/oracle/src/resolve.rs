//! Locate adapter executables by implementation name.
//!
//! Lookup order for implementation `<name>`:
//!
//! 1. the environment variable `DIFFUZZ_ADAPTER_<NAME>` (upper-cased), an explicit path;
//! 2. `diffuzz-adapter-<name>[.exe]` next to the running executable (Cargo puts the Rust
//!    adapters there);
//! 3. `target/adapters/diffuzz-adapter-<name>[.exe]` under the current directory
//!    (`scripts/build_adapters.sh` puts the non-Rust adapters there).

use std::path::{Path, PathBuf};

use crate::adapter::AdapterConfig;

/// File name of the adapter executable for `name` on this platform.
pub fn executable_name(name: &str) -> String {
    format!("diffuzz-adapter-{name}{}", std::env::consts::EXE_SUFFIX)
}

/// Pure lookup: an explicit override wins, otherwise the first directory containing the
/// executable. Returns the list of places tried on failure.
pub fn resolve_in(
    name: &str,
    override_path: Option<PathBuf>,
    dirs: &[PathBuf],
) -> Result<AdapterConfig, String> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(format!("invalid implementation name {name:?}"));
    }
    if let Some(p) = override_path {
        return if p.is_file() {
            Ok(AdapterConfig::new(name, p))
        } else {
            Err(format!(
                "adapter override for {name} does not exist: {}",
                p.display()
            ))
        };
    }
    let exe = executable_name(name);
    let mut tried = Vec::new();
    for d in dirs {
        let p = d.join(&exe);
        if p.is_file() {
            return Ok(AdapterConfig::new(name, p));
        }
        tried.push(p.display().to_string());
    }
    Err(format!(
        "adapter for {name} not found (set DIFFUZZ_ADAPTER_{} or build it); tried: {}",
        name.to_ascii_uppercase().replace('-', "_"),
        tried.join(", ")
    ))
}

/// Resolve an adapter using the environment and standard locations (see module docs).
pub fn resolve(name: &str) -> Result<AdapterConfig, String> {
    let var = format!(
        "DIFFUZZ_ADAPTER_{}",
        name.to_ascii_uppercase().replace('-', "_")
    );
    let override_path = std::env::var_os(var).map(PathBuf::from);
    let mut dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        dirs.push(dir.to_path_buf());
    }
    dirs.push(Path::new("target").join("adapters"));
    resolve_in(name, override_path, &dirs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_in_directory_and_honours_override() {
        let dir = std::env::temp_dir().join(format!("diffuzz-resolve-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join(executable_name("abc"));
        std::fs::write(&exe, b"").unwrap();

        let cfg = resolve_in("abc", None, &[PathBuf::from("no-such-dir"), dir.clone()]).unwrap();
        assert_eq!(cfg.program, exe);
        assert_eq!(cfg.name, "abc");

        let cfg = resolve_in("other", Some(exe.clone()), &[]).unwrap();
        assert_eq!(cfg.program, exe);

        let e =
            resolve_in("abc", Some(dir.join("missing")), std::slice::from_ref(&dir)).unwrap_err();
        assert!(e.contains("does not exist"));
        let e = resolve_in("zzz", None, std::slice::from_ref(&dir)).unwrap_err();
        assert!(e.contains("DIFFUZZ_ADAPTER_ZZZ"), "{e}");
        assert!(resolve_in("../evil", None, std::slice::from_ref(&dir)).is_err());
        assert!(resolve_in("", None, &[]).is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolve_reports_missing() {
        assert!(resolve("surely-not-built").is_err());
    }
}
