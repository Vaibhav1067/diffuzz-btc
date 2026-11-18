//! Our transaction parser vs rust-bitcoin's. Ours is deliberately lenient, so anything
//! rust-bitcoin decodes must decode here too, to the same txid and wtxid; and whatever ours
//! decodes must survive a serialize/deserialize round trip.

#![no_main]

use bitcoin::hashes::Hash;
use diffuzz_types::tx::Tx;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let ours = Tx::deserialize(data);
    if let Ok(tx) = &ours {
        // A 0-input witness-less tx serializes as "00", which reads back as the segwit marker.
        if !tx.inputs.is_empty() {
            let again = Tx::deserialize(&tx.serialize()).expect("round trip decodes");
            assert_eq!(&again, tx, "round trip changed the transaction");
        }
    }
    if let Ok(theirs) = bitcoin::consensus::deserialize::<bitcoin::Transaction>(data) {
        // rust-bitcoin accepts 0-input segwit-flagged txs by design; see docs/aux-protocol.md.
        if theirs.input.is_empty() {
            return;
        }
        let tx = ours.expect("rust-bitcoin decodes this transaction, ours must too");
        assert_eq!(tx.txid(), theirs.compute_txid().to_byte_array(), "txid");
        assert_eq!(tx.wtxid(), theirs.compute_wtxid().to_byte_array(), "wtxid");
    }
});
