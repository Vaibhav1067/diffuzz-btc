//! diffuzz adapter for Bitcoin Core.
//!
//! Speaks protocol v1 (one JSON request per stdin line, one JSON response per stdout line) and
//! verifies with `libbitcoinconsensus` from Bitcoin Core 26.0, built from source by the
//! `bitcoinconsensus` crate. See `docs/flag-mapping.md` for the binding choice and its limits.
//!
//! No `unsafe` is needed here: the crate's safe wrapper takes slices, and we only construct the
//! raw-pointer `Utxo` records it forwards (creating raw pointers is safe).

#![forbid(unsafe_code)]

use bitcoinconsensus as bc;
use diffuzz_types::{ErrorClass, Flag, Request, Response, hex};

/// Implementation name reported in responses.
pub const IMPL_NAME: &str = "core";
/// Pinned implementation version reported in responses.
pub const IMPL_VERSION: &str = "libbitcoinconsensus 26.0 (bitcoinconsensus 0.106.0+26.0)";

/// Map an abstract flag to libbitcoinconsensus. Policy flags have no mapping: the library
/// rejects anything outside its consensus set.
fn map_flag(flag: Flag) -> Option<u32> {
    match flag {
        Flag::P2sh => Some(bc::VERIFY_P2SH),
        Flag::Dersig => Some(bc::VERIFY_DERSIG),
        Flag::Nulldummy => Some(bc::VERIFY_NULLDUMMY),
        Flag::Cltv => Some(bc::VERIFY_CHECKLOCKTIMEVERIFY),
        Flag::Csv => Some(bc::VERIFY_CHECKSEQUENCEVERIFY),
        Flag::Witness => Some(bc::VERIFY_WITNESS),
        Flag::Taproot => Some(bc::VERIFY_TAPROOT),
        _ => None,
    }
}

/// A rejection: normalized class and raw detail.
pub type Failure = (ErrorClass, String);

fn fail(class: ErrorClass, msg: impl Into<String>) -> Failure {
    (class, msg.into())
}

/// Verify one request. `Ok(())` means the input was accepted.
pub fn verify(req: &Request) -> Result<(), Failure> {
    let mut flags = 0u32;
    for f in &req.flags {
        flags |= map_flag(*f).ok_or_else(|| {
            fail(
                ErrorClass::InvalidFlags,
                format!("policy flag {f} unsupported"),
            )
        })?;
    }
    // Core's interpreter asserts P2SH whenever WITNESS is set; refuse instead of aborting.
    if flags & bc::VERIFY_WITNESS != 0 && flags & bc::VERIFY_P2SH == 0 {
        return Err(fail(ErrorClass::InvalidFlags, "WITNESS requires P2SH"));
    }

    let tx = hex::decode(&req.tx_hex)
        .ok_or_else(|| fail(ErrorClass::Deserialize, "tx_hex is not valid hex"))?;
    let mut scripts = Vec::with_capacity(req.prevouts.len());
    for (i, p) in req.prevouts.iter().enumerate() {
        scripts.push(hex::decode(&p.script_pubkey_hex).ok_or_else(|| {
            fail(
                ErrorClass::Deserialize,
                format!("prevout {i} script is not valid hex"),
            )
        })?);
    }
    let index = req.input_index as usize;
    let spent = req
        .prevouts
        .get(index)
        .ok_or_else(|| fail(ErrorClass::TxIndex, "input_index has no matching prevout"))?;
    if req.prevouts.iter().any(|p| p.amount_sats > i64::MAX as u64) {
        return Err(fail(
            ErrorClass::Deserialize,
            "prevout amount exceeds int64",
        ));
    }

    let utxos: Vec<bc::Utxo> = scripts
        .iter()
        .zip(&req.prevouts)
        .map(|(s, p)| bc::Utxo {
            script_pubkey: s.as_ptr(),
            script_pubkey_len: s.len() as u32,
            value: p.amount_sats as i64,
        })
        .collect();

    bc::verify_with_flags(
        &scripts[index],
        spent.amount_sats,
        &tx,
        Some(&utxos),
        index,
        flags,
    )
    .map_err(|e| {
        let class = match e {
            bc::Error::ERR_SCRIPT => ErrorClass::ScriptFail,
            bc::Error::ERR_TX_INDEX => ErrorClass::TxIndex,
            bc::Error::ERR_TX_SIZE_MISMATCH | bc::Error::ERR_TX_DESERIALIZE => {
                ErrorClass::Deserialize
            }
            bc::Error::ERR_SPENT_OUTPUTS_MISMATCH => ErrorClass::Deserialize,
            bc::Error::ERR_INVALID_FLAGS => ErrorClass::InvalidFlags,
            _ => ErrorClass::Unknown,
        };
        fail(class, format!("{e:?}"))
    })
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

/// Answer one protocol line (never panics on malformed input).
pub fn handle_line(line: &str) -> Response {
    match serde_json::from_str::<Request>(line) {
        Ok(req) => respond(req.id, verify(&req)),
        Err(e) => {
            // Echo the id if the line is at least JSON with one, so the caller stays in sync.
            let id = serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|v| v.get("id").and_then(serde_json::Value::as_u64))
                .unwrap_or(0);
            respond(
                id,
                Err(fail(ErrorClass::Deserialize, format!("bad request: {e}"))),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffuzz_types::Prevout;

    // From the bitcoinconsensus crate docs: mainnet tx aca326a7... spending a P2PKH output.
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
        r.input_index = 5;
        assert_eq!(verify(&r).unwrap_err().0, ErrorClass::TxIndex);

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
        assert_eq!(resp.impl_name, "core");

        let resp = handle_line(r#"{"id": 9, "tx_hex": 5}"#);
        assert!(!resp.ok);
        assert_eq!(resp.id, 9);
        assert_eq!(resp.error_class, Some(ErrorClass::Deserialize));

        let resp = handle_line("not json");
        assert_eq!(resp.id, 0);
        assert!(!resp.ok);
    }
}
