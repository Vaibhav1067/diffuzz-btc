//! `diffuzz` command-line entry point. Subcommands arrive in later phases.

#![forbid(unsafe_code)]

fn main() {
    println!("diffuzz {}", env!("CARGO_PKG_VERSION"));
}
