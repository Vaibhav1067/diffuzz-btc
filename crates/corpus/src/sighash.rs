//! Loader for Bitcoin Core's `sighash.json` (legacy signature-hash vectors).
//!
//! Entries are `[raw_tx_hex, script_hex, input_index, hash_type, expected_sighash_hex]`. They
//! test the sighash algorithm directly, so they cannot be expressed as script-verification
//! cases; the sighash differential (Phase 7) consumes them.

use diffuzz_types::hex;
use serde_json::Value;

use crate::{LoadError, err};

/// One legacy sighash vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SighashVector {
    /// `sighash.json#<index>`.
    pub name: String,
    /// Serialized transaction.
    pub tx: Vec<u8>,
    /// scriptCode.
    pub script: Vec<u8>,
    /// Input being signed.
    pub input_index: u32,
    /// Raw 32-bit hash type (the vectors use arbitrary values, including negative ones).
    pub hash_type: i32,
    /// Expected digest as displayed by Core (`uint256::GetHex`, i.e. byte-reversed).
    pub expected_hex: String,
}

/// Load `sighash.json` from its JSON text.
pub fn load(json: &str) -> Result<Vec<SighashVector>, LoadError> {
    let file = "sighash.json";
    let root: Vec<Value> = serde_json::from_str(json).map_err(|e| err(file, e.to_string()))?;
    let mut out = Vec::new();
    for (idx, entry) in root.iter().enumerate() {
        let name = format!("{file}#{idx}");
        let loc = name.as_str();
        let e = entry
            .as_array()
            .ok_or_else(|| err(loc, "entry is not an array"))?;
        if e.len() == 1 {
            continue; // header comment
        }
        if e.len() != 5 {
            return Err(err(loc, "expected 5 fields"));
        }
        let hex_at = |i: usize| {
            e[i].as_str()
                .and_then(hex::decode)
                .ok_or_else(|| err(loc, format!("field {i}: bad hex")))
        };
        let tx = hex_at(0)?;
        let script = hex_at(1)?;
        let input_index = e[2]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| err(loc, "bad input index"))?;
        let hash_type = e[3]
            .as_i64()
            .and_then(|n| i32::try_from(n).ok())
            .ok_or_else(|| err(loc, "bad hash type"))?;
        let expected_hex = e[4]
            .as_str()
            .ok_or_else(|| err(loc, "bad digest"))?
            .to_string();
        if expected_hex.len() != 64 || hex::decode(&expected_hex).is_none() {
            return Err(err(loc, "digest is not 32 bytes of hex"));
        }
        out.push(SighashVector {
            name,
            tx,
            script,
            input_index,
            hash_type,
            expected_hex,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads() {
        let json = r#"[
          ["raw_transaction, script, input_index, hashType, signature_hash (result)"],
          ["0100", "ab65", 2, 1864164639, "31af167a6cf3f9d5f6875caa4d31704ceb0eba078d132b78dab52c3b8997317e"],
          ["0100", "", 0, -1391424484, "48d6a1bd2cd9eec54eb866fc71209418a950402b5d7e52363bfb75c98e141175"]
        ]"#;
        let v = load(json).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].name, "sighash.json#1");
        assert_eq!(v[0].script, vec![0xab, 0x65]);
        assert_eq!(v[0].input_index, 2);
        assert_eq!(v[1].hash_type, -1391424484);
        assert!(load(r#"[["zz", "", 0, 1, "00"]]"#).is_err());
        assert!(load(r#"[["00", "", 0, 1, "00"]]"#).is_err());
    }
}
