//! `diffuzz-adapter-rust-bitcoin`: protocol v1 over stdin/stdout. Logic lives in the library.

#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};

use diffuzz_adapter_rust_bitcoin::handle_line;

fn main() -> io::Result<()> {
    let stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    for line in stdin.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        stdout.write_all(handle_line(&line).as_bytes())?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}
