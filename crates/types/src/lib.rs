//! Shared case and wire-protocol types for diffuzz-btc.
//!
//! A [`Case`] is everything needed to verify one transaction input. Adapters receive it as a
//! [`Request`] (one JSON object per line) and answer with a [`Response`]. The orchestrator turns
//! responses, crashes and timeouts into a [`Verdict`].

#![forbid(unsafe_code)]

use std::fmt;

use serde::{Deserialize, Serialize};

pub mod auxop;
pub mod hex;
pub mod script;
pub mod taproot;
pub mod tx;

/// Abstract script verification flag. Each adapter maps these to its implementation's flags.
///
/// The first seven variants are consensus flags (soft-fork deployments). Everything else is
/// policy/standardness and must never be used by the main oracle; see [`Flag::is_consensus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Flag {
    // ---- consensus ----
    /// BIP16 pay-to-script-hash evaluation.
    #[serde(rename = "P2SH")]
    P2sh,
    /// BIP66 strict DER signatures.
    #[serde(rename = "DERSIG")]
    Dersig,
    /// BIP147 CHECKMULTISIG dummy must be empty.
    #[serde(rename = "NULLDUMMY")]
    Nulldummy,
    /// BIP65 OP_CHECKLOCKTIMEVERIFY.
    #[serde(rename = "CLTV", alias = "CHECKLOCKTIMEVERIFY")]
    Cltv,
    /// BIP112 OP_CHECKSEQUENCEVERIFY.
    #[serde(rename = "CSV", alias = "CHECKSEQUENCEVERIFY")]
    Csv,
    /// BIP141 segregated witness.
    #[serde(rename = "WITNESS")]
    Witness,
    /// BIP341/342 taproot and tapscript.
    #[serde(rename = "TAPROOT")]
    Taproot,
    // ---- policy only ----
    /// Policy: strict signature and pubkey encodings.
    #[serde(rename = "STRICTENC")]
    StrictEnc,
    /// Policy: low-S signatures.
    #[serde(rename = "LOW_S")]
    LowS,
    /// Policy: scriptSig must be push-only.
    #[serde(rename = "SIGPUSHONLY")]
    SigPushOnly,
    /// Policy: minimal push and number encodings.
    #[serde(rename = "MINIMALDATA")]
    MinimalData,
    /// Policy: reject upgradable NOPs.
    #[serde(rename = "DISCOURAGE_UPGRADABLE_NOPS")]
    DiscourageUpgradableNops,
    /// Policy: exactly one stack element after evaluation.
    #[serde(rename = "CLEANSTACK")]
    CleanStack,
    /// Policy: minimal OP_IF argument in segwit v0.
    #[serde(rename = "MINIMALIF")]
    MinimalIf,
    /// Policy: failed signature checks must use empty signatures.
    #[serde(rename = "NULLFAIL")]
    NullFail,
    /// Policy: compressed pubkeys only in segwit v0.
    #[serde(rename = "WITNESS_PUBKEYTYPE")]
    WitnessPubkeyType,
    /// Policy: reject unknown witness program versions.
    #[serde(rename = "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM")]
    DiscourageUpgradableWitnessProgram,
    /// Policy: OP_CODESEPARATOR and FindAndDelete restrictions.
    #[serde(rename = "CONST_SCRIPTCODE")]
    ConstScriptcode,
    /// Policy: reject unknown taproot leaf versions.
    #[serde(rename = "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION")]
    DiscourageUpgradableTaprootVersion,
    /// Policy: reject OP_SUCCESSx.
    #[serde(rename = "DISCOURAGE_OP_SUCCESS")]
    DiscourageOpSuccess,
    /// Policy: reject unknown tapscript pubkey types.
    #[serde(rename = "DISCOURAGE_UPGRADABLE_PUBKEYTYPE")]
    DiscourageUpgradablePubkeyType,
}

impl Flag {
    /// The seven consensus flags, in canonical order.
    pub const CONSENSUS: [Flag; 7] = [
        Flag::P2sh,
        Flag::Dersig,
        Flag::Nulldummy,
        Flag::Cltv,
        Flag::Csv,
        Flag::Witness,
        Flag::Taproot,
    ];

    /// Every flag, consensus first.
    pub const ALL: [Flag; 21] = [
        Flag::P2sh,
        Flag::Dersig,
        Flag::Nulldummy,
        Flag::Cltv,
        Flag::Csv,
        Flag::Witness,
        Flag::Taproot,
        Flag::StrictEnc,
        Flag::LowS,
        Flag::SigPushOnly,
        Flag::MinimalData,
        Flag::DiscourageUpgradableNops,
        Flag::CleanStack,
        Flag::MinimalIf,
        Flag::NullFail,
        Flag::WitnessPubkeyType,
        Flag::DiscourageUpgradableWitnessProgram,
        Flag::ConstScriptcode,
        Flag::DiscourageUpgradableTaprootVersion,
        Flag::DiscourageOpSuccess,
        Flag::DiscourageUpgradablePubkeyType,
    ];

    /// True for soft-fork consensus flags, false for policy/standardness flags.
    pub fn is_consensus(self) -> bool {
        Flag::CONSENSUS.contains(&self)
    }

    /// Canonical wire name, e.g. `"P2SH"`.
    pub fn name(self) -> &'static str {
        match self {
            Flag::P2sh => "P2SH",
            Flag::Dersig => "DERSIG",
            Flag::Nulldummy => "NULLDUMMY",
            Flag::Cltv => "CLTV",
            Flag::Csv => "CSV",
            Flag::Witness => "WITNESS",
            Flag::Taproot => "TAPROOT",
            Flag::StrictEnc => "STRICTENC",
            Flag::LowS => "LOW_S",
            Flag::SigPushOnly => "SIGPUSHONLY",
            Flag::MinimalData => "MINIMALDATA",
            Flag::DiscourageUpgradableNops => "DISCOURAGE_UPGRADABLE_NOPS",
            Flag::CleanStack => "CLEANSTACK",
            Flag::MinimalIf => "MINIMALIF",
            Flag::NullFail => "NULLFAIL",
            Flag::WitnessPubkeyType => "WITNESS_PUBKEYTYPE",
            Flag::DiscourageUpgradableWitnessProgram => "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
            Flag::ConstScriptcode => "CONST_SCRIPTCODE",
            Flag::DiscourageUpgradableTaprootVersion => "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION",
            Flag::DiscourageOpSuccess => "DISCOURAGE_OP_SUCCESS",
            Flag::DiscourageUpgradablePubkeyType => "DISCOURAGE_UPGRADABLE_PUBKEYTYPE",
        }
    }

    /// Parse a wire name or one of Bitcoin Core's test-vector spellings
    /// (`CHECKLOCKTIMEVERIFY`, `CHECKSEQUENCEVERIFY`).
    pub fn from_name(name: &str) -> Option<Flag> {
        match name {
            "CHECKLOCKTIMEVERIFY" => Some(Flag::Cltv),
            "CHECKSEQUENCEVERIFY" => Some(Flag::Csv),
            _ => Flag::ALL.iter().copied().find(|f| f.name() == name),
        }
    }
}

impl fmt::Display for Flag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Sort and deduplicate a flag list so equal sets serialize identically.
pub fn normalize_flags(flags: &mut Vec<Flag>) {
    flags.sort();
    flags.dedup();
}

/// True if every flag in `flags` is a consensus flag.
pub fn all_consensus(flags: &[Flag]) -> bool {
    flags.iter().all(|f| f.is_consensus())
}

/// An output being spent: its script and amount.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Prevout {
    /// The output's scriptPubKey, hex encoded.
    pub script_pubkey_hex: String,
    /// The output's value in satoshis.
    pub amount_sats: u64,
}

/// One self-contained verification case: "does input `input_index` of `tx_hex` validly spend
/// `prevouts[input_index]` under `flags`?"
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Case {
    /// The spending transaction in network serialization, hex encoded.
    pub tx_hex: String,
    /// Index of the input under test.
    pub input_index: u32,
    /// All outputs spent by the transaction, aligned with its inputs.
    pub prevouts: Vec<Prevout>,
    /// Verification flags.
    pub flags: Vec<Flag>,
    /// Free-form provenance (vector file and index, generator name, seed...). Not sent to adapters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

impl Case {
    /// Build the wire request for this case.
    pub fn to_request(&self, id: u64) -> Request {
        Request {
            id,
            tx_hex: self.tx_hex.clone(),
            input_index: self.input_index,
            prevouts: self.prevouts.clone(),
            flags: self.flags.clone(),
        }
    }

    /// True if the case uses only consensus flags and is therefore valid for the main oracle.
    pub fn is_consensus_only(&self) -> bool {
        all_consensus(&self.flags)
    }
}

/// Protocol v1 request: one JSON object per line on the adapter's stdin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Correlation id echoed in the response.
    pub id: u64,
    /// See [`Case::tx_hex`].
    pub tx_hex: String,
    /// See [`Case::input_index`].
    pub input_index: u32,
    /// See [`Case::prevouts`].
    pub prevouts: Vec<Prevout>,
    /// See [`Case::flags`].
    pub flags: Vec<Flag>,
}

/// Protocol v1 response: one JSON object per line on the adapter's stdout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// Correlation id copied from the request.
    pub id: u64,
    /// Accept/reject. The only field the oracle compares.
    pub ok: bool,
    /// Normalized failure category; `None` when `ok` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_class: Option<ErrorClass>,
    /// Implementation-specific error text for humans.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_error: Option<String>,
    /// Implementation name, e.g. `"core"` or `"btcd"`.
    #[serde(rename = "impl")]
    pub impl_name: String,
    /// Pinned implementation version.
    pub impl_version: String,
}

/// Normalized, informational failure category. Never compared by the main oracle.
///
/// Names follow Bitcoin Core's `ScriptError` where one exists. Unknown strings deserialize to
/// [`ErrorClass::Unknown`] so a newer adapter cannot break an older orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(missing_docs)]
pub enum ErrorClass {
    /// Script failed; the implementation gave no finer category (libbitcoinconsensus).
    ScriptFail,
    /// The request itself was malformed (bad hex, undecodable transaction, bad prevout count).
    Deserialize,
    /// `input_index` out of range.
    TxIndex,
    /// The adapter cannot express the requested flag set. Treated as an abstention.
    InvalidFlags,
    /// The adapter cannot faithfully evaluate this case (a documented adapter limitation, not a
    /// verdict of the implementation). Treated as an abstention.
    Unsupported,
    /// The implementation panicked and the adapter recovered. Becomes [`Outcome::Crash`].
    Crash,
    EvalFalse,
    OpReturn,
    ScriptSize,
    PushSize,
    OpCount,
    StackSize,
    SigCount,
    PubkeyCount,
    Verify,
    Equalverify,
    Checkmultisigverify,
    Checksigverify,
    Numequalverify,
    BadOpcode,
    DisabledOpcode,
    InvalidStackOperation,
    InvalidAltstackOperation,
    UnbalancedConditional,
    NegativeLocktime,
    UnsatisfiedLocktime,
    /// Script number overflow or non-minimal number.
    ScriptNum,
    SigHashtype,
    SigDer,
    Minimaldata,
    SigPushonly,
    SigHighS,
    SigNulldummy,
    Pubkeytype,
    Cleanstack,
    Minimalif,
    SigNullfail,
    DiscourageUpgradableNops,
    DiscourageUpgradableWitnessProgram,
    DiscourageUpgradableTaprootVersion,
    DiscourageOpSuccess,
    DiscourageUpgradablePubkeytype,
    WitnessProgramWrongLength,
    WitnessProgramWitnessEmpty,
    WitnessProgramMismatch,
    WitnessMalleated,
    WitnessMalleatedP2sh,
    WitnessUnexpected,
    WitnessPubkeytype,
    SchnorrSigSize,
    SchnorrSigHashtype,
    SchnorrSig,
    TaprootWrongControlSize,
    TapscriptValidationWeight,
    TapscriptCheckmultisig,
    TapscriptMinimalif,
    TapscriptEmptyPubkey,
    OpCodeseparator,
    SigFindanddelete,
    /// Anything the adapter could not categorize.
    #[serde(other)]
    Unknown,
}

impl ErrorClass {
    /// True if the adapter declined to give a verdict (unsupported flags or case shape) rather
    /// than reporting what the implementation decided.
    pub fn is_abstention(self) -> bool {
        matches!(self, ErrorClass::InvalidFlags | ErrorClass::Unsupported)
    }

    /// Wire name, e.g. `"EVAL_FALSE"`.
    pub fn name(self) -> String {
        match serde_json::to_value(self) {
            Ok(serde_json::Value::String(s)) => s,
            _ => "UNKNOWN".to_string(),
        }
    }
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name())
    }
}

/// What happened when one adapter was asked about one case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Outcome {
    /// The implementation accepted the input.
    Ok,
    /// The implementation rejected the input.
    Fail {
        /// Normalized category.
        error_class: ErrorClass,
        /// Implementation-specific text.
        raw_error: String,
    },
    /// The adapter process died or returned garbage while handling the case.
    Crash {
        /// What the orchestrator observed.
        detail: String,
    },
    /// The adapter did not answer in time.
    Timeout,
}

impl Outcome {
    /// `Some(true/false)` for accept/reject, `None` for crash or timeout.
    pub fn accepted(&self) -> Option<bool> {
        match self {
            Outcome::Ok => Some(true),
            Outcome::Fail { .. } => Some(false),
            Outcome::Crash { .. } | Outcome::Timeout => None,
        }
    }
}

/// An adapter's outcome for a case, with the adapter's identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    /// Implementation name.
    #[serde(rename = "impl")]
    pub impl_name: String,
    /// Implementation version ("" if the adapter never answered).
    pub impl_version: String,
    /// What happened.
    #[serde(flatten)]
    pub outcome: Outcome,
}

impl Verdict {
    /// Convert a well-formed adapter response into a verdict.
    pub fn from_response(resp: Response) -> Verdict {
        let outcome = if resp.ok {
            Outcome::Ok
        } else if resp.error_class == Some(ErrorClass::Crash) {
            Outcome::Crash {
                detail: resp.raw_error.unwrap_or_default(),
            }
        } else {
            Outcome::Fail {
                error_class: resp.error_class.unwrap_or(ErrorClass::Unknown),
                raw_error: resp.raw_error.unwrap_or_default(),
            }
        };
        Verdict {
            impl_name: resp.impl_name,
            impl_version: resp.impl_version,
            outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_case() -> Case {
        Case {
            tx_hex: "0200".into(),
            input_index: 0,
            prevouts: vec![Prevout {
                script_pubkey_hex: "51".into(),
                amount_sats: 100_000,
            }],
            flags: vec![Flag::P2sh, Flag::Witness, Flag::Taproot],
            origin: Some("test".into()),
        }
    }

    #[test]
    fn flag_names_round_trip() {
        for f in Flag::ALL {
            assert_eq!(Flag::from_name(f.name()), Some(f));
            let json = serde_json::to_string(&f).unwrap();
            assert_eq!(json, format!("\"{}\"", f.name()));
            assert_eq!(serde_json::from_str::<Flag>(&json).unwrap(), f);
            assert_eq!(f.to_string(), f.name());
        }
        assert_eq!(Flag::from_name("CHECKLOCKTIMEVERIFY"), Some(Flag::Cltv));
        assert_eq!(Flag::from_name("CHECKSEQUENCEVERIFY"), Some(Flag::Csv));
        assert_eq!(
            serde_json::from_str::<Flag>("\"CHECKSEQUENCEVERIFY\"").unwrap(),
            Flag::Csv
        );
        assert_eq!(Flag::from_name("NOPE"), None);
    }

    #[test]
    fn consensus_split() {
        assert_eq!(Flag::ALL.iter().filter(|f| f.is_consensus()).count(), 7);
        assert!(Flag::Taproot.is_consensus());
        assert!(!Flag::LowS.is_consensus());
        assert!(all_consensus(&[Flag::P2sh, Flag::Csv]));
        assert!(!all_consensus(&[Flag::P2sh, Flag::CleanStack]));
        assert!(sample_case().is_consensus_only());
    }

    #[test]
    fn normalize_sorts_and_dedups() {
        let mut v = vec![Flag::Witness, Flag::P2sh, Flag::Witness];
        normalize_flags(&mut v);
        assert_eq!(v, vec![Flag::P2sh, Flag::Witness]);
    }

    #[test]
    fn case_round_trip_and_request() {
        let case = sample_case();
        let json = serde_json::to_string(&case).unwrap();
        assert_eq!(serde_json::from_str::<Case>(&json).unwrap(), case);

        let req = case.to_request(42);
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("origin"));
        assert!(!json.contains('\n'));
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), req);
    }

    #[test]
    fn request_matches_documented_wire_format() {
        let wire = r#"{"id": 42, "tx_hex": "0200", "input_index": 0,
            "prevouts": [{"script_pubkey_hex": "76a988ac", "amount_sats": 100000}],
            "flags": ["P2SH", "DERSIG", "NULLDUMMY", "CLTV", "CSV", "WITNESS", "TAPROOT"]}"#;
        let req: Request = serde_json::from_str(wire).unwrap();
        assert_eq!(req.flags, Flag::CONSENSUS.to_vec());
        assert_eq!(req.prevouts[0].amount_sats, 100_000);
    }

    #[test]
    fn response_round_trip() {
        let wire = r#"{"id": 42, "ok": false, "error_class": "SIG_NULLFAIL",
            "raw_error": "text", "impl": "btcd", "impl_version": "v0.24.x"}"#;
        let resp: Response = serde_json::from_str(wire).unwrap();
        assert_eq!(resp.error_class, Some(ErrorClass::SigNullfail));
        assert_eq!(resp.impl_name, "btcd");
        let back = serde_json::to_string(&resp).unwrap();
        assert_eq!(serde_json::from_str::<Response>(&back).unwrap(), resp);

        let ok: Response =
            serde_json::from_str(r#"{"id":1,"ok":true,"impl":"core","impl_version":"26.0"}"#)
                .unwrap();
        assert!(ok.ok && ok.error_class.is_none());
    }

    #[test]
    fn unknown_error_class_is_tolerated() {
        let c: ErrorClass = serde_json::from_str("\"SOMETHING_NEW\"").unwrap();
        assert_eq!(c, ErrorClass::Unknown);
        assert_eq!(ErrorClass::EvalFalse.name(), "EVAL_FALSE");
        assert_eq!(
            ErrorClass::WitnessMalleatedP2sh.to_string(),
            "WITNESS_MALLEATED_P2SH"
        );
    }

    #[test]
    fn verdict_from_response() {
        let resp = Response {
            id: 1,
            ok: false,
            error_class: None,
            raw_error: None,
            impl_name: "x".into(),
            impl_version: "1".into(),
        };
        let v = Verdict::from_response(resp);
        assert_eq!(v.outcome.accepted(), Some(false));
        assert!(matches!(
            v.outcome,
            Outcome::Fail {
                error_class: ErrorClass::Unknown,
                ..
            }
        ));
        assert_eq!(Outcome::Ok.accepted(), Some(true));
        assert_eq!(Outcome::Timeout.accepted(), None);
        assert_eq!(
            Outcome::Crash {
                detail: String::new()
            }
            .accepted(),
            None
        );

        let recovered = Response {
            id: 2,
            ok: false,
            error_class: Some(ErrorClass::Crash),
            raw_error: Some("panic: boom".into()),
            impl_name: "x".into(),
            impl_version: "1".into(),
        };
        assert_eq!(
            Verdict::from_response(recovered).outcome,
            Outcome::Crash {
                detail: "panic: boom".into()
            }
        );
        assert!(ErrorClass::Unsupported.is_abstention());
        assert!(ErrorClass::InvalidFlags.is_abstention());
        assert!(!ErrorClass::EvalFalse.is_abstention());

        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"outcome\":\"FAIL\""));
        assert_eq!(serde_json::from_str::<Verdict>(&json).unwrap(), v);
    }
}
