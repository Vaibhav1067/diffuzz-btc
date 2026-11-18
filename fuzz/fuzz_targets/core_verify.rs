//! Structured inputs to the Core adapter's verify path (libbitcoinconsensus 26.0): any
//! transaction bytes, prevouts, input index and flag subset. Must never panic or abort. The C++
//! library is not coverage-instrumented; this target guards the adapter boundary.

#![no_main]

use arbitrary::Arbitrary;
use diffuzz_types::{Flag, Prevout, Request, hex};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Input {
    tx: Vec<u8>,
    input_index: u32,
    prevouts: Vec<(Vec<u8>, u64)>,
    flags: u8,
}

fuzz_target!(|inp: Input| {
    let flags = Flag::CONSENSUS
        .iter()
        .enumerate()
        .filter(|(i, _)| inp.flags & (1 << i) != 0)
        .map(|(_, f)| *f)
        .collect();
    let req = Request {
        id: 1,
        tx_hex: hex::encode(&inp.tx),
        input_index: inp.input_index,
        prevouts: inp
            .prevouts
            .iter()
            .map(|(s, a)| Prevout {
                script_pubkey_hex: hex::encode(s),
                amount_sats: *a,
            })
            .collect(),
        flags,
    };
    let _ = diffuzz_adapter_core::verify(&req);
});
