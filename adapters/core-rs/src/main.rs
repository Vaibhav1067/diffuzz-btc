//! `diffuzz-adapter-core`: protocol v1 over stdin/stdout. The logic lives in the library crate.

#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};

use diffuzz_adapter_core::{handle_aux_line, handle_line};

fn main() -> io::Result<()> {
    let stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    for line in stdin.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if diffuzz_types::auxop::is_aux(&line) {
            serde_json::to_writer(&mut stdout, &handle_aux_line(&line))?;
        } else {
            serde_json::to_writer(&mut stdout, &handle_line(&line))?;
        }
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}
