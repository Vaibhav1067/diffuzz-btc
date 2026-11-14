//! Loader for the BIP341 wallet test vectors (`bip-0341/wallet-test-vectors.json`), key-path
//! signature hashes only.
//!
//! Each `keyPathSpending[].inputSpending[]` entry gives an input index, a hash type and the
//! expected `sigHash` (the raw tagged-hash output, not byte-reversed).

use diffuzz_types::{Prevout, hex};
use serde_json::Value;

use crate::{LoadError, err};

/// One BIP341 key-path signature-hash vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaprootSighashVector {
    /// `wallet-test-vectors.json#keyPathSpending[<i>].inputSpending[<j>]`.
    pub name: String,
    /// Unsigned transaction, hex.
    pub tx_hex: String,
    /// All spent outputs, aligned with the inputs.
    pub prevouts: Vec<Prevout>,
    /// Input being signed.
    pub input_index: u32,
    /// Hash type byte.
    pub hash_type: u8,
    /// Expected digest, raw byte order, hex.
    pub expected_hex: String,
}

/// Load the key-path sighash vectors from the file's JSON text.
pub fn load(json: &str) -> Result<Vec<TaprootSighashVector>, LoadError> {
    let file = "wallet-test-vectors.json";
    let root: Value = serde_json::from_str(json).map_err(|e| err(file, e.to_string()))?;
    let groups = root["keyPathSpending"]
        .as_array()
        .ok_or_else(|| err(file, "no keyPathSpending array"))?;
    let mut out = Vec::new();
    for (i, g) in groups.iter().enumerate() {
        let loc = format!("{file}#keyPathSpending[{i}]");
        let tx_hex = g["given"]["rawUnsignedTx"]
            .as_str()
            .filter(|s| hex::decode(s).is_some())
            .ok_or_else(|| err(&loc, "bad rawUnsignedTx"))?
            .to_string();
        let mut prevouts = Vec::new();
        for u in g["given"]["utxosSpent"]
            .as_array()
            .ok_or_else(|| err(&loc, "no utxosSpent"))?
        {
            prevouts.push(Prevout {
                script_pubkey_hex: u["scriptPubKey"]
                    .as_str()
                    .filter(|s| hex::decode(s).is_some())
                    .ok_or_else(|| err(&loc, "bad scriptPubKey"))?
                    .to_string(),
                amount_sats: u["amountSats"]
                    .as_u64()
                    .ok_or_else(|| err(&loc, "bad amountSats"))?,
            });
        }
        for (j, s) in g["inputSpending"]
            .as_array()
            .ok_or_else(|| err(&loc, "no inputSpending"))?
            .iter()
            .enumerate()
        {
            let name = format!("{loc}.inputSpending[{j}]");
            let input_index = s["given"]["txinIndex"]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| err(&name, "bad txinIndex"))?;
            let hash_type = s["given"]["hashType"]
                .as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or_else(|| err(&name, "bad hashType"))?;
            let expected_hex = s["intermediary"]["sigHash"]
                .as_str()
                .filter(|h| h.len() == 64 && hex::decode(h).is_some())
                .ok_or_else(|| err(&name, "bad sigHash"))?
                .to_string();
            out.push(TaprootSighashVector {
                name,
                tx_hex: tx_hex.clone(),
                prevouts: prevouts.clone(),
                input_index,
                hash_type,
                expected_hex,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads() {
        let json = r#"{"keyPathSpending":[{"given":{"rawUnsignedTx":"0200",
          "utxosSpent":[{"scriptPubKey":"5120aa","amountSats":7}]},
          "inputSpending":[{"given":{"txinIndex":0,"hashType":131},
          "intermediary":{"sigHash":"2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555"}}]}]}"#;
        let v = load(json).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].hash_type, 131);
        assert_eq!(v[0].prevouts[0].amount_sats, 7);
        assert!(v[0].name.ends_with("keyPathSpending[0].inputSpending[0]"));
        assert!(load(r#"{"keyPathSpending":[{"given":{}}]}"#).is_err());
        assert!(load("{}").is_err());
    }
}
