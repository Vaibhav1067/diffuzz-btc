//! Protocol v1 extension for the secondary surface: transaction serialization and signature
//! hashes.
//!
//! A request with an `"op"` field is an auxiliary request; adapters that do not implement an
//! operation answer `{"ok": false, "unsupported": true}`. All hashes are hex of the 32 raw
//! digest bytes in the order SHA-256 produces them (not the reversed "display" order).

use serde::{Deserialize, Serialize};

use crate::Prevout;

/// Which signature-hash algorithm to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SighashKind {
    /// Pre-segwit algorithm.
    Legacy,
    /// BIP143 (segwit v0).
    Bip143,
    /// BIP341 (taproot key path and script path).
    Bip341,
}

/// An auxiliary operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AuxOp {
    /// Decode a transaction and report its ids, weight and canonical re-serialization.
    Txinfo {
        /// Raw transaction, hex.
        tx_hex: String,
    },
    /// Compute a signature hash.
    Sighash {
        /// Algorithm.
        kind: SighashKind,
        /// Raw transaction, hex.
        tx_hex: String,
        /// Input being signed.
        input_index: u32,
        /// scriptCode (legacy and BIP143 only), hex.
        script_hex: String,
        /// Hash type: the full 32-bit value for legacy/BIP143, the byte for BIP341.
        hash_type: u32,
        /// Amount of the spent output (BIP143).
        amount_sats: u64,
        /// All spent outputs (BIP341).
        prevouts: Vec<Prevout>,
        /// Annex including its 0x50 prefix (BIP341), hex.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annex_hex: Option<String>,
        /// Tapleaf hash for a script-path signature (BIP341), hex.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        leaf_hash_hex: Option<String>,
        /// Position of the last executed OP_CODESEPARATOR (BIP341 script path).
        codesep_pos: u32,
    },
}

/// An auxiliary request line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuxRequest {
    /// Correlation id echoed in the response.
    pub id: u64,
    /// The operation.
    #[serde(flatten)]
    pub op: AuxOp,
}

/// An auxiliary response line.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuxResponse {
    /// Correlation id copied from the request.
    pub id: u64,
    /// The operation succeeded (the transaction decoded / the hash is defined).
    pub ok: bool,
    /// The implementation cannot perform this operation on this input at all. Not a verdict.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unsupported: bool,
    /// Implementation-specific error text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Transaction id (txinfo).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
    /// Witness transaction id (txinfo).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wtxid: Option<String>,
    /// BIP141 weight (txinfo).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u64>,
    /// Re-serialized transaction (txinfo), hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
    /// Signature hash (sighash).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

impl AuxResponse {
    /// A failed response.
    pub fn failed(id: u64, error: impl Into<String>) -> AuxResponse {
        AuxResponse {
            id,
            error: Some(error.into()),
            ..AuxResponse::default()
        }
    }

    /// An "I cannot do this" response.
    pub fn unsupported(id: u64, why: impl Into<String>) -> AuxResponse {
        AuxResponse {
            id,
            unsupported: true,
            error: Some(why.into()),
            ..AuxResponse::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format() {
        let req = AuxRequest {
            id: 3,
            op: AuxOp::Txinfo {
                tx_hex: "00".into(),
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"id":3,"op":"txinfo","tx_hex":"00"}"#);
        assert_eq!(serde_json::from_str::<AuxRequest>(&json).unwrap(), req);

        let req = AuxRequest {
            id: 4,
            op: AuxOp::Sighash {
                kind: SighashKind::Bip341,
                tx_hex: "01".into(),
                input_index: 1,
                script_hex: String::new(),
                hash_type: 0x83,
                amount_sats: 5,
                prevouts: vec![],
                annex_hex: None,
                leaf_hash_hex: Some("ab".into()),
                codesep_pos: 0xffff_ffff,
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""op":"sighash""#) && json.contains(r#""kind":"bip341""#));
        assert!(!json.contains("annex_hex"));
        assert_eq!(serde_json::from_str::<AuxRequest>(&json).unwrap(), req);
    }

    #[test]
    fn responses() {
        let r: AuxResponse = serde_json::from_str(r#"{"id":1,"ok":true,"digest":"aa"}"#).unwrap();
        assert!(r.ok && !r.unsupported);
        assert_eq!(r.digest.as_deref(), Some("aa"));
        let u = AuxResponse::unsupported(2, "no");
        let json = serde_json::to_string(&u).unwrap();
        assert!(json.contains(r#""unsupported":true"#));
        assert_eq!(serde_json::from_str::<AuxResponse>(&json).unwrap(), u);
        assert!(
            !serde_json::to_string(&AuxResponse::failed(1, "x"))
                .unwrap()
                .contains("unsupported")
        );
    }
}
