//! A scriptable fake adapter used only by tests.
//!
//! Baseline rule: a case is "valid" iff its `tx_hex` starts with `01`. Each argument adds a
//! behaviour triggered when `tx_hex` contains the given substring:
//!
//! * `lie-on:<s>`: answer the opposite of the baseline rule
//! * `crash-on:<s>`: exit with status 3 without answering
//! * `hang-on:<s>`: never answer
//! * `garbage-on:<s>`: print a non-JSON line
//! * `wrong-id-on:<s>`: answer with a wrong id
//! * `name:<n>`: report `<n>` as the implementation name
//!
//! Auxiliary `txinfo` requests echo `tx_hex` as `hex`; the triggers above apply to them too.

#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};

use diffuzz_types::auxop::{AuxOp, AuxRequest, AuxResponse};
use diffuzz_types::{ErrorClass, Request, Response};

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |key: &str| -> Vec<&str> {
        args.iter()
            .filter_map(|a| a.strip_prefix(key))
            .collect::<Vec<_>>()
    };
    let name = arg("name:").first().copied().unwrap_or("fake").to_string();
    let hit = |key: &str, tx: &str| arg(key).iter().any(|s| tx.contains(s));

    let stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    for line in stdin.lines() {
        let line = line?;
        if let Ok(aux) = serde_json::from_str::<AuxRequest>(&line) {
            let AuxOp::Txinfo { tx_hex } = &aux.op else {
                serde_json::to_writer(&mut stdout, &AuxResponse::unsupported(aux.id, "fake"))?;
                writeln!(stdout)?;
                stdout.flush()?;
                continue;
            };
            if hit("crash-on:", tx_hex) {
                std::process::exit(3);
            }
            let resp = AuxResponse {
                id: aux.id,
                ok: true,
                hex: Some(tx_hex.clone()),
                ..AuxResponse::default()
            };
            serde_json::to_writer(&mut stdout, &resp)?;
            writeln!(stdout)?;
            stdout.flush()?;
            continue;
        }
        let Ok(req) = serde_json::from_str::<Request>(&line) else {
            writeln!(
                stdout,
                "{{\"id\":0,\"ok\":false,\"impl\":\"{name}\",\"impl_version\":\"0\"}}"
            )?;
            stdout.flush()?;
            continue;
        };
        let tx = req.tx_hex.as_str();
        if hit("crash-on:", tx) {
            eprintln!("fake adapter: simulated crash");
            std::process::exit(3);
        }
        if hit("hang-on:", tx) {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        if hit("garbage-on:", tx) {
            writeln!(stdout, "this is not json")?;
            stdout.flush()?;
            continue;
        }
        let mut ok = tx.starts_with("01");
        if hit("lie-on:", tx) {
            ok = !ok;
        }
        let resp = Response {
            id: if hit("wrong-id-on:", tx) {
                req.id + 1000
            } else {
                req.id
            },
            ok,
            error_class: (!ok).then_some(ErrorClass::EvalFalse),
            raw_error: (!ok).then(|| "fake rejection".to_string()),
            impl_name: name.clone(),
            impl_version: "fake-1".to_string(),
        };
        serde_json::to_writer(&mut stdout, &resp)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}
