//! diffuzz auxiliary adapter for rust-bitcoin: transaction (de)serialization and signature
//! hashes. See `README.md` for what is and is not delegated to the library.

#![forbid(unsafe_code)]

use bitcoin::hashes::Hash;
use bitcoin::sighash::{Annex, EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TapLeafHash;
use bitcoin::{Amount, Script, ScriptBuf, Transaction, TxOut, consensus};
use diffuzz_types::auxop::{AuxOp, AuxRequest, AuxResponse, SighashKind, is_aux};
use diffuzz_types::{ErrorClass, Prevout, Response, hex};

/// Implementation name reported in responses.
pub const IMPL_NAME: &str = "rust-bitcoin";
/// Pinned implementation version reported in responses.
pub const IMPL_VERSION: &str = "bitcoin 0.32.102";

const OP_CODESEPARATOR: u8 = 0xab;

/// Remove `OP_CODESEPARATOR`s from a scriptCode the way Core's `SerializeScriptCode` does:
/// walk opcodes, drop each separator, and copy everything from the first unparsable opcode on.
pub fn strip_codeseparators(script: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(script.len());
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        let (header, len_bytes) = match op {
            0x4c => (2, 1),
            0x4d => (3, 2),
            0x4e => (5, 4),
            _ => (1, 0),
        };
        if i + header > script.len() {
            break;
        }
        let push = match op {
            0x01..=0x4b => op as usize,
            0x4c..=0x4e => script[i + 1..i + 1 + len_bytes]
                .iter()
                .rev()
                .fold(0usize, |acc, b| (acc << 8) | *b as usize),
            _ => 0,
        };
        let Some(end) = (i + header)
            .checked_add(push)
            .filter(|e| *e <= script.len())
        else {
            break;
        };
        if op != OP_CODESEPARATOR {
            out.extend_from_slice(&script[i..end]);
        }
        i = end;
    }
    out.extend_from_slice(&script[i..]);
    out
}

fn decode_tx(tx_hex: &str) -> Result<Transaction, String> {
    let raw = hex::decode(tx_hex).ok_or("tx_hex is not valid hex")?;
    consensus::deserialize::<Transaction>(&raw).map_err(|e| format!("tx decode: {e}"))
}

fn decode_hex(what: &str, s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).ok_or_else(|| format!("{what} is not valid hex"))
}

fn txout(p: &Prevout) -> Result<TxOut, String> {
    Ok(TxOut {
        value: Amount::from_sat(p.amount_sats),
        script_pubkey: ScriptBuf::from_bytes(decode_hex("prevout script", &p.script_pubkey_hex)?),
    })
}

/// Outcome of one operation: a filled response, a plain failure, or "cannot do this".
enum Done {
    Ok(AuxResponse),
    Failed(String),
    Unsupported(String),
}

fn txinfo(tx_hex: &str) -> Done {
    match decode_tx(tx_hex) {
        // Documented design (`Transaction` docs, "to avoid deserialization ambiguity"): 0-input
        // transactions use BIP141 serialization, so the decoder accepts a witness flag with no
        // inputs, which Core rejects as a superfluous witness record. Not comparable.
        Ok(tx) if tx.input.is_empty() => Done::Unsupported(
            "rust-bitcoin serializes 0-input transactions in BIP141 format by design".into(),
        ),
        Ok(tx) => Done::Ok(AuxResponse {
            ok: true,
            txid: Some(hex::encode(&tx.compute_txid().to_byte_array())),
            wtxid: Some(hex::encode(&tx.compute_wtxid().to_byte_array())),
            weight: Some(tx.weight().to_wu()),
            hex: Some(hex::encode(&consensus::serialize(&tx))),
            ..AuxResponse::default()
        }),
        Err(e) => Done::Failed(e),
    }
}

#[allow(clippy::too_many_arguments)]
fn sighash(
    kind: SighashKind,
    tx_hex: &str,
    input_index: u32,
    script_hex: &str,
    hash_type: u32,
    amount_sats: u64,
    prevouts: &[Prevout],
    annex_hex: Option<&str>,
    leaf_hash_hex: Option<&str>,
    codesep_pos: u32,
) -> Result<Done, String> {
    let tx = decode_tx(tx_hex)?;
    let idx = input_index as usize;
    // taproot_encode_signing_data_to (0.32.102 and master 271f662a) checks the index only for
    // ANYONECANPAY, so the adapter checks it for every kind.
    if idx >= tx.input.len() {
        return Err("input index out of range".into());
    }
    let script = decode_hex("script_hex", script_hex)?;
    let cache = SighashCache::new(&tx);
    let digest: [u8; 32] = match kind {
        SighashKind::Legacy => {
            let code = strip_codeseparators(&script);
            cache
                .legacy_signature_hash(idx, Script::from_bytes(&code), hash_type)
                .map_err(|e| e.to_string())?
                .to_byte_array()
        }
        SighashKind::Bip143 => {
            let ty = EcdsaSighashType::from_consensus(hash_type);
            if ty.to_u32() != hash_type {
                return Ok(Done::Unsupported(
                    "p2wsh_signature_hash hashes the normalized hash type, not the raw value"
                        .into(),
                ));
            }
            let mut cache = cache;
            cache
                .p2wsh_signature_hash(
                    idx,
                    Script::from_bytes(&script),
                    Amount::from_sat(amount_sats),
                    ty,
                )
                .map_err(|e| e.to_string())?
                .to_byte_array()
        }
        SighashKind::Bip341 => {
            let byte = u8::try_from(hash_type).map_err(|_| "taproot hash type is one byte")?;
            let ty = TapSighashType::from_consensus_u8(byte).map_err(|e| e.to_string())?;
            let outs = prevouts.iter().map(txout).collect::<Result<Vec<_>, _>>()?;
            let annex_bytes = annex_hex.map(|a| decode_hex("annex_hex", a)).transpose()?;
            let annex = annex_bytes
                .as_deref()
                .map(Annex::new)
                .transpose()
                .map_err(|e| e.to_string())?;
            let leaf = leaf_hash_hex
                .map(|h| {
                    let b = decode_hex("leaf_hash_hex", h)?;
                    TapLeafHash::from_slice(&b).map_err(|e| e.to_string())
                })
                .transpose()?
                .map(|l| (l, codesep_pos));
            let mut cache = cache;
            cache
                .taproot_signature_hash(idx, &Prevouts::All(&outs), annex, leaf, ty)
                .map_err(|e| e.to_string())?
                .to_byte_array()
        }
    };
    Ok(Done::Ok(AuxResponse {
        ok: true,
        digest: Some(hex::encode(&digest)),
        ..AuxResponse::default()
    }))
}

/// Answer one auxiliary request.
pub fn handle_aux(req: &AuxRequest) -> AuxResponse {
    let done = match &req.op {
        AuxOp::Txinfo { tx_hex } => txinfo(tx_hex),
        AuxOp::Sighash {
            kind,
            tx_hex,
            input_index,
            script_hex,
            hash_type,
            amount_sats,
            prevouts,
            annex_hex,
            leaf_hash_hex,
            codesep_pos,
        } => sighash(
            *kind,
            tx_hex,
            *input_index,
            script_hex,
            *hash_type,
            *amount_sats,
            prevouts,
            annex_hex.as_deref(),
            leaf_hash_hex.as_deref(),
            *codesep_pos,
        )
        .unwrap_or_else(Done::Failed),
    };
    match done {
        Done::Ok(r) => AuxResponse { id: req.id, ..r },
        Done::Failed(e) => AuxResponse::failed(req.id, e),
        Done::Unsupported(e) => AuxResponse::unsupported(req.id, e),
    }
}

fn line_id(line: &str) -> u64 {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v.get("id").and_then(serde_json::Value::as_u64))
        .unwrap_or(0)
}

fn to_json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_else(|e| format!(r#"{{"id":0,"ok":false,"error":"{e}"}}"#))
}

/// Answer one protocol line as a JSON string (never panics on malformed input).
///
/// Script-verification requests are answered `UNSUPPORTED`: rust-bitcoin has no interpreter.
pub fn handle_line(line: &str) -> String {
    if is_aux(line) {
        let resp = match serde_json::from_str::<AuxRequest>(line) {
            Ok(req) => handle_aux(&req),
            Err(e) => {
                // An unknown op is "cannot do this"; anything else is a malformed request.
                let op = serde_json::from_str::<serde_json::Value>(line)
                    .ok()
                    .and_then(|v| v.get("op").and_then(|o| o.as_str().map(str::to_owned)));
                match op.as_deref() {
                    Some("txinfo" | "sighash") => {
                        AuxResponse::failed(line_id(line), format!("bad request: {e}"))
                    }
                    _ => AuxResponse::unsupported(line_id(line), format!("unknown op: {e}")),
                }
            }
        };
        return to_json(&resp);
    }
    to_json(&Response {
        id: line_id(line),
        ok: false,
        error_class: Some(ErrorClass::Unsupported),
        raw_error: Some("rust-bitcoin has no script interpreter".into()),
        impl_name: IMPL_NAME.into(),
        impl_version: IMPL_VERSION.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mainnet tx aca326a7... spending a P2PKH output (same fixture as the other adapters).
    const SPENDING: &str = "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700";
    const SPENT: &str = "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac";

    fn parse(line: &str) -> AuxResponse {
        serde_json::from_str(&handle_line(line)).unwrap()
    }

    #[test]
    fn strips_codeseparators_like_core() {
        assert_eq!(strip_codeseparators(&[0xab, 0x51, 0xab]), vec![0x51]);
        // A push containing 0xab is data, not an opcode.
        assert_eq!(strip_codeseparators(&[0x01, 0xab, 0xab]), vec![0x01, 0xab]);
        // Truncated push: separators before it go, the raw tail is kept.
        assert_eq!(
            strip_codeseparators(&[0xab, 0x4c, 0x05, 0xab]),
            vec![0x4c, 0x05, 0xab]
        );
        assert_eq!(strip_codeseparators(&[0x4d, 0x01]), vec![0x4d, 0x01]);
    }

    #[test]
    fn txinfo_matches_known_txid() {
        let r = parse(&format!(
            r#"{{"id":1,"op":"txinfo","tx_hex":"{SPENDING}"}}"#
        ));
        assert!(r.ok, "{r:?}");
        assert_eq!(
            r.txid.as_deref(),
            Some("5dd4a20ef896b92f86c3260ff1277baed5ec3465870ac161a4a9ed24a726a3ac")
        );
        assert_eq!(r.hex.as_deref(), Some(SPENDING));
        assert_eq!(r.weight, Some(SPENDING.len() as u64 / 2 * 4));
        let r = parse(&format!(
            r#"{{"id":2,"op":"txinfo","tx_hex":"{SPENDING}00"}}"#
        ));
        assert!(!r.ok && !r.unsupported);
        // version, marker+flag, 0 inputs, 1 output (0 sats, empty script), locktime.
        let zero_in = "020000000001000100000000000000000000000000";
        let r = parse(&format!(r#"{{"id":3,"op":"txinfo","tx_hex":"{zero_in}"}}"#));
        assert!(r.unsupported, "{r:?}");
    }

    #[test]
    fn sighash_kinds() {
        let req = |kind: &str, ht: u32| {
            format!(
                r#"{{"id":3,"op":"sighash","kind":"{kind}","tx_hex":"{SPENDING}","input_index":0,"script_hex":"{SPENT}","hash_type":{ht},"amount_sats":5,"prevouts":[{{"script_pubkey_hex":"{SPENT}","amount_sats":5}}],"codesep_pos":4294967295}}"#
            )
        };
        let r = parse(&req("legacy", 1));
        assert!(
            r.ok && r.digest.as_ref().is_some_and(|d| d.len() == 64),
            "{r:?}"
        );
        assert!(parse(&req("bip143", 1)).ok);
        let r = parse(&req("bip143", 0x41));
        assert!(!r.ok && r.unsupported, "{r:?}");
        assert!(parse(&req("bip341", 0)).ok);
        let oob = req("bip341", 0).replace(r#""input_index":0"#, r#""input_index":1"#);
        let r = parse(&oob);
        assert!(!r.ok && !r.unsupported, "out-of-range index: {r:?}");
        let r = parse(&req("bip341", 4));
        assert!(
            !r.ok && !r.unsupported,
            "undefined taproot hash type: {r:?}"
        );
    }

    #[test]
    fn malformed_and_verify_requests() {
        let r = parse(r#"{"id":4,"op":"nope"}"#);
        assert!(r.unsupported && r.id == 4);
        let r = parse(r#"{"id":5,"op":"txinfo"}"#);
        assert!(!r.ok && !r.unsupported && r.id == 5);
        let v: Response = serde_json::from_str(&handle_line(r#"{"id":6,"tx_hex":""}"#)).unwrap();
        assert_eq!(v.error_class, Some(ErrorClass::Unsupported));
        assert_eq!(v.id, 6);
    }
}
