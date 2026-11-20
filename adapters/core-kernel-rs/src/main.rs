//! `diffuzz-adapter-core-kernel`: protocol v1 over stdin/stdout, verifying with current Bitcoin
//! Core through `libbitcoinkernel` (the successor of `libbitcoinconsensus`, which Core removed
//! after 26.x). The `bitcoinkernel` crate wraps the C API safely, so no `unsafe` is needed here.

use std::io::{self, BufRead, Write};

use bitcoinkernel::prelude::*;
use bitcoinkernel::{
    KernelError, PrecomputedTransactionData, ScriptPubkey, ScriptVerifyError, Transaction, TxOut,
    VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY, VERIFY_DERSIG, VERIFY_NULLDUMMY,
    VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS, verify as kernel_verify,
};
use diffuzz_types::auxop::{AuxResponse, is_aux};
use diffuzz_types::{ErrorClass, Flag, Request, Response, hex};

/// Implementation name reported in responses.
const IMPL_NAME: &str = "core-kernel";
/// Pinned implementation version reported in responses.
const IMPL_VERSION: &str =
    "Bitcoin Core master 70d9ec7f3d4 (31.99, libbitcoinkernel via bitcoinkernel 0.3.2)";

/// A rejection: normalized class and raw detail.
type Failure = (ErrorClass, String);

fn fail(class: ErrorClass, msg: impl Into<String>) -> Failure {
    (class, msg.into())
}

/// Map an abstract flag to the kernel's flag bits. Policy flags have no mapping.
fn map_flag(flag: Flag) -> Option<u32> {
    let bits = match flag {
        Flag::P2sh => VERIFY_P2SH,
        Flag::Dersig => VERIFY_DERSIG,
        Flag::Nulldummy => VERIFY_NULLDUMMY,
        Flag::Cltv => VERIFY_CHECKLOCKTIMEVERIFY,
        Flag::Csv => VERIFY_CHECKSEQUENCEVERIFY,
        Flag::Witness => VERIFY_WITNESS,
        Flag::Taproot => VERIFY_TAPROOT,
        _ => return None,
    };
    Some(bits)
}

fn kernel_failure(e: KernelError) -> Failure {
    let class = match &e {
        KernelError::ScriptVerify(v) => match v {
            ScriptVerifyError::Invalid => ErrorClass::ScriptFail,
            ScriptVerifyError::TxInputIndex => ErrorClass::TxIndex,
            ScriptVerifyError::InvalidFlags | ScriptVerifyError::InvalidFlagsCombination => {
                ErrorClass::InvalidFlags
            }
            _ => ErrorClass::Deserialize,
        },
        KernelError::MismatchedOutputsSize | KernelError::SerializationFailed => {
            ErrorClass::Deserialize
        }
        _ => ErrorClass::Unknown,
    };
    fail(class, e.to_string())
}

/// Verify one request. `Ok(())` means the input was accepted.
fn verify(req: &Request) -> Result<(), Failure> {
    let mut flags = 0u32;
    for f in &req.flags {
        flags |= map_flag(*f).ok_or_else(|| {
            fail(
                ErrorClass::InvalidFlags,
                format!("policy flag {f} unsupported"),
            )
        })?;
    }
    // Refuse before decoding, in the same order as the core adapter, so both abstain on the same
    // requests. The kernel would also refuse (InvalidFlagsCombination).
    if flags & VERIFY_WITNESS != 0 && flags & VERIFY_P2SH == 0 {
        return Err(fail(ErrorClass::InvalidFlags, "WITNESS requires P2SH"));
    }
    let tx_bytes = hex::decode(&req.tx_hex)
        .ok_or_else(|| fail(ErrorClass::Deserialize, "tx_hex is not valid hex"))?;
    let tx = Transaction::new(&tx_bytes)
        .map_err(|e| fail(ErrorClass::Deserialize, format!("tx decode: {e}")))?;
    // The kernel decodes a transaction from the front of the buffer and ignores what follows;
    // libbitcoinconsensus rejected that (ERR_TX_SIZE_MISMATCH), as do the other adapters.
    if tx.consensus_encode().map_err(kernel_failure)?.len() != tx_bytes.len() {
        return Err(fail(
            ErrorClass::Deserialize,
            "trailing bytes after transaction",
        ));
    }
    let index = req.input_index as usize;
    if req.prevouts.len() != tx.input_count() {
        return Err(fail(
            ErrorClass::Deserialize,
            "prevouts do not match the transaction's inputs",
        ));
    }
    let mut scripts = Vec::with_capacity(req.prevouts.len());
    let mut outputs = Vec::with_capacity(req.prevouts.len());
    for (i, p) in req.prevouts.iter().enumerate() {
        let bytes = hex::decode(&p.script_pubkey_hex).ok_or_else(|| {
            fail(
                ErrorClass::Deserialize,
                format!("prevout {i} script is not valid hex"),
            )
        })?;
        let amount = i64::try_from(p.amount_sats)
            .map_err(|_| fail(ErrorClass::Deserialize, "prevout amount exceeds int64"))?;
        let script = ScriptPubkey::new(&bytes).map_err(kernel_failure)?;
        outputs.push(TxOut::new(&script, amount));
        scripts.push((script, amount));
    }
    let (script, amount) = scripts
        .get(index)
        .ok_or_else(|| fail(ErrorClass::TxIndex, "input_index has no matching prevout"))?;
    let data = PrecomputedTransactionData::new(&tx, &outputs).map_err(kernel_failure)?;
    kernel_verify(script, Some(*amount), &tx, index, Some(flags), &data).map_err(kernel_failure)
}

fn respond(id: u64, result: Result<(), Failure>) -> Response {
    let (ok, error_class, raw_error) = match result {
        Ok(()) => (true, None, None),
        Err((class, raw)) => (false, Some(class), Some(raw)),
    };
    Response {
        id,
        ok,
        error_class,
        raw_error,
        impl_name: IMPL_NAME.to_string(),
        impl_version: IMPL_VERSION.to_string(),
    }
}

fn line_id(line: &str) -> u64 {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v.get("id").and_then(serde_json::Value::as_u64))
        .unwrap_or(0)
}

/// Answer one protocol line (never panics on malformed input).
fn handle_line(line: &str) -> Response {
    match serde_json::from_str::<Request>(line) {
        Ok(req) => respond(req.id, verify(&req)),
        Err(e) => respond(
            line_id(line),
            Err(fail(ErrorClass::Deserialize, format!("bad request: {e}"))),
        ),
    }
}

// shortcut: no per-request watchdog (libbitcoin's adapter uses alarm()), so a hung request
// leaves its container running after the orchestrator's timeout; add one if timeouts appear.
fn main() -> io::Result<()> {
    let stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    for line in stdin.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if is_aux(&line) {
            let r = AuxResponse::unsupported(line_id(&line), "core-kernel adapter: script only");
            serde_json::to_writer(&mut stdout, &r)?;
        } else {
            serde_json::to_writer(&mut stdout, &handle_line(&line))?;
        }
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffuzz_types::Prevout;

    // Mainnet tx aca326a7... spending a P2PKH output (same vector as the core adapter's tests).
    const SPENDING: &str = "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700";
    const SPENT: &str = "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac";

    fn request(spk: &str, flags: Vec<Flag>) -> Request {
        Request {
            id: 7,
            tx_hex: SPENDING.to_string(),
            input_index: 0,
            prevouts: vec![Prevout {
                script_pubkey_hex: spk.to_string(),
                amount_sats: 630_482_530,
            }],
            flags,
        }
    }

    #[test]
    fn accepts_real_spend_under_all_consensus_flags() {
        assert_eq!(verify(&request(SPENT, Flag::CONSENSUS.to_vec())), Ok(()));
        assert_eq!(verify(&request(SPENT, vec![])), Ok(()));
    }

    #[test]
    fn rejects_wrong_script() {
        let wrong = SPENT.replace("4bfb", "4bfc");
        let e = verify(&request(&wrong, Flag::CONSENSUS.to_vec())).unwrap_err();
        assert_eq!(e.0, ErrorClass::ScriptFail);
    }

    #[test]
    fn rejects_bad_requests_without_crashing() {
        let mut r = request(SPENT, vec![]);
        r.tx_hex = "zz".into();
        assert_eq!(verify(&r).unwrap_err().0, ErrorClass::Deserialize);

        let mut r = request(SPENT, vec![]);
        r.tx_hex = "0200".into();
        assert_eq!(verify(&r).unwrap_err().0, ErrorClass::Deserialize);

        let mut r = request(SPENT, vec![]);
        r.tx_hex.push_str("00");
        assert_eq!(verify(&r).unwrap_err().0, ErrorClass::Deserialize);

        let mut r = request(SPENT, vec![]);
        r.input_index = 5;
        assert!(verify(&r).is_err());

        let mut r = request(SPENT, vec![]);
        r.prevouts.push(r.prevouts[0].clone());
        assert!(verify(&r).is_err());

        assert_eq!(
            verify(&request(SPENT, vec![Flag::LowS])).unwrap_err().0,
            ErrorClass::InvalidFlags
        );
        assert_eq!(
            verify(&request(SPENT, vec![Flag::Witness])).unwrap_err().0,
            ErrorClass::InvalidFlags
        );
    }

    #[test]
    fn line_handling() {
        let line = serde_json::to_string(&request(SPENT, vec![Flag::P2sh])).unwrap();
        let resp = handle_line(&line);
        assert!(resp.ok);
        assert_eq!(resp.id, 7);
        assert_eq!(resp.impl_name, "core-kernel");

        let resp = handle_line(r#"{"id": 9, "tx_hex": 5}"#);
        assert!(!resp.ok);
        assert_eq!(resp.id, 9);
        assert_eq!(resp.error_class, Some(ErrorClass::Deserialize));

        let resp = handle_line("not json");
        assert_eq!(resp.id, 0);
        assert!(!resp.ok);
    }
}
