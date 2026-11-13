//! Signature-checking cases for legacy and segwit v0 scripts: CHECKSIG, CHECKMULTISIG, every
//! hash type, DER and public-key encoding edge cases, NULLDUMMY, OP_CODESEPARATOR and
//! FindAndDelete.

use diffuzz_types::script::{op, push_data, push_int};
use diffuzz_types::{Case, Flag};

use super::Generator;
use crate::keys::{DerQuirk, test_key};
use crate::rng::Rng;
use crate::spend::{
    Damage, EcdsaSpec, Item, SigVersion, TapParams, Wrapper, ecdsa_sig, hash160, random_flags,
    skeleton, to_case, wrap, wrap_p2wpkh,
};

/// Script shapes this generator produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Template {
    /// `<pk> CHECKSIG`
    P2pk,
    /// `<pk> CHECKSIGVERIFY 1`
    P2pkVerify,
    /// `DUP HASH160 <h> EQUALVERIFY CHECKSIG`
    P2pkh,
    /// `m <pk>... n CHECKMULTISIG`
    Multisig,
    /// `m <pk>... n CHECKMULTISIGVERIFY 1`
    MultisigVerify,
    /// `<pk> CHECKSIG NOT`: succeeds when the signature check *fails* softly.
    ChecksigNot,
    /// `<pk> CODESEPARATOR CHECKSIG`
    CodeSepAfterKey,
    /// `CODESEPARATOR <pk> CHECKSIG`
    CodeSepFirst,
    /// `<sig> <pk> CHECKSIG` with the signature inside the script (legacy FindAndDelete).
    SigInScript,
    /// Native P2WPKH.
    P2wpkh,
    /// P2WPKH nested in P2SH.
    P2shP2wpkh,
}

impl Template {
    /// Every template.
    pub const ALL: [Template; 11] = [
        Template::P2pk,
        Template::P2pkVerify,
        Template::P2pkh,
        Template::Multisig,
        Template::MultisigVerify,
        Template::ChecksigNot,
        Template::CodeSepAfterKey,
        Template::CodeSepFirst,
        Template::SigInScript,
        Template::P2wpkh,
        Template::P2shP2wpkh,
    ];

    /// Short name for origins and statistics.
    pub fn name(self) -> &'static str {
        match self {
            Template::P2pk => "p2pk",
            Template::P2pkVerify => "p2pk-verify",
            Template::P2pkh => "p2pkh",
            Template::Multisig => "multisig",
            Template::MultisigVerify => "multisig-verify",
            Template::ChecksigNot => "checksig-not",
            Template::CodeSepAfterKey => "codesep-after-key",
            Template::CodeSepFirst => "codesep-first",
            Template::SigInScript => "sig-in-script",
            Template::P2wpkh => "p2wpkh",
            Template::P2shP2wpkh => "p2sh-p2wpkh",
        }
    }
}

/// Public key serializations, valid and not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyForm {
    /// 33 bytes, `02`/`03`.
    Compressed,
    /// 65 bytes, `04`.
    Uncompressed,
    /// 65 bytes, `06`/`07` (consensus-valid).
    Hybrid,
    /// Compressed with an undefined prefix byte.
    BadPrefix,
    /// Compressed key missing its last byte.
    Short,
    /// Compressed key with an extra byte.
    Long,
    /// `02 || ff..ff`: x is not a field element.
    OffCurve,
    /// Hybrid key with the wrong parity prefix.
    HybridWrongParity,
    /// Zero bytes.
    Empty,
}

impl KeyForm {
    const ALL: [KeyForm; 9] = [
        KeyForm::Compressed,
        KeyForm::Uncompressed,
        KeyForm::Hybrid,
        KeyForm::BadPrefix,
        KeyForm::Short,
        KeyForm::Long,
        KeyForm::OffCurve,
        KeyForm::HybridWrongParity,
        KeyForm::Empty,
    ];

    /// Serialize test key `key` in this form.
    pub fn encode(self, key: u32) -> Vec<u8> {
        let k = test_key(key);
        match self {
            KeyForm::Compressed => k.compressed().to_vec(),
            KeyForm::Uncompressed => k.uncompressed().to_vec(),
            KeyForm::Hybrid => k.hybrid().to_vec(),
            KeyForm::BadPrefix => {
                let mut v = k.compressed().to_vec();
                v[0] = 0x05;
                v
            }
            KeyForm::Short => k.compressed()[..32].to_vec(),
            KeyForm::Long => {
                let mut v = k.compressed().to_vec();
                v.push(0);
                v
            }
            KeyForm::OffCurve => {
                let mut v = vec![0x02];
                v.extend_from_slice(&[0xff; 32]);
                v
            }
            KeyForm::HybridWrongParity => {
                let mut v = k.hybrid().to_vec();
                v[0] ^= 1;
                v
            }
            KeyForm::Empty => Vec::new(),
        }
    }
}

/// The free choices of a signature case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choices {
    /// Public key encoding.
    pub key_form: KeyForm,
    /// Hash-type byte.
    pub hash_type: u8,
    /// DER variant.
    pub quirk: DerQuirk,
    /// High-S form.
    pub high_s: bool,
    /// Damage applied to (one of) the signature(s).
    pub damage: Damage,
    /// Multisig: required signatures.
    pub m: usize,
    /// Multisig: public keys.
    pub n: usize,
    /// Multisig: the dummy element consumed by the off-by-one bug.
    pub dummy: Vec<u8>,
    /// Multisig: supply signatures in reverse key order.
    pub reverse_sigs: bool,
    /// Multisig: number of signatures actually supplied (normally `m`).
    pub sigs_supplied: usize,
}

impl Choices {
    /// Choices that make every template valid under all consensus flags.
    pub fn valid() -> Choices {
        Choices {
            key_form: KeyForm::Compressed,
            hash_type: 1,
            quirk: DerQuirk::Strict,
            high_s: false,
            damage: Damage::None,
            m: 2,
            n: 3,
            dummy: Vec::new(),
            reverse_sigs: false,
            sigs_supplied: 2,
        }
    }

    /// Random choices: each dimension is usually benign, so most cases differ from a valid
    /// spend in only one or two ways.
    pub fn random(rng: &mut Rng) -> Choices {
        let key_form = if rng.chance(55) {
            KeyForm::Compressed
        } else {
            *rng.pick(&KeyForm::ALL)
        };
        let hash_type = if rng.chance(45) {
            1
        } else {
            *rng.pick(&[
                2u8, 3, 0x81, 0x82, 0x83, 0x00, 0x04, 0x7f, 0x80, 0xff, 0x41, 0x1f, 0x21,
            ])
        };
        let quirk = if rng.chance(65) {
            DerQuirk::Strict
        } else {
            *rng.pick(&DerQuirk::ALL)
        };
        let damage = if rng.chance(60) {
            Damage::None
        } else {
            *rng.pick(&Damage::ECDSA)
        };
        let n = *rng.pick(&[1usize, 2, 3, 3, 3, 5, 15, 16, 17, 20, 21]);
        let m = match rng.below(10) {
            0 => 0,
            1 => n,
            2 => n + 1,
            _ => rng.range(1, n.min(3)),
        };
        let dummy = match rng.below(12) {
            0 => vec![0x01],
            1 => vec![0x00],
            2 => rng.bytes(3),
            _ => Vec::new(),
        };
        let sigs_supplied = match rng.below(12) {
            0 => m.saturating_sub(1),
            1 => m + 1,
            _ => m,
        };
        Choices {
            key_form,
            hash_type,
            quirk,
            high_s: rng.chance(15),
            damage,
            m,
            n,
            dummy,
            reverse_sigs: rng.chance(10),
            sigs_supplied,
        }
    }

    fn spec(&self, key: u32, code_from: usize) -> EcdsaSpec {
        EcdsaSpec {
            key,
            hash_type: self.hash_type,
            quirk: self.quirk,
            high_s: self.high_s,
            damage: self.damage,
            code_from,
        }
    }
}

/// Signature-checking cases.
#[derive(Debug, Clone, Default)]
pub struct SigGen;

impl SigGen {
    /// Build one case from explicit choices. `key_base` selects which test keys are used.
    pub fn build(
        &self,
        rng: &mut Rng,
        template: Template,
        wrapper: Wrapper,
        c: &Choices,
        flags: Vec<Flag>,
    ) -> Case {
        let mut sk = skeleton(rng);
        let key = 10 + rng.below(8) as u32;
        let pubkey = c.key_form.encode(key);
        let tap = TapParams::default();
        let mut script = Vec::new();
        let mut items: Vec<Item> = Vec::new();
        let mut wrapper_name = wrapper.name();

        match template {
            Template::P2pk | Template::P2pkVerify | Template::ChecksigNot => {
                push_data(&mut script, &pubkey);
                match template {
                    Template::P2pk => script.push(op::CHECKSIG),
                    Template::P2pkVerify => {
                        script.extend_from_slice(&[op::CHECKSIGVERIFY, op::OP_1])
                    }
                    _ => script.extend_from_slice(&[op::CHECKSIG, op::NOT]),
                }
                items.push(Item::Ecdsa(c.spec(key, 0)));
            }
            Template::P2pkh => {
                script.extend_from_slice(&[op::DUP, op::HASH160, 0x14]);
                script.extend_from_slice(&hash160(&pubkey));
                script.extend_from_slice(&[op::EQUALVERIFY, op::CHECKSIG]);
                items.push(Item::Ecdsa(c.spec(key, 0)));
                items.push(Item::Data(pubkey.clone()));
            }
            Template::CodeSepAfterKey => {
                push_data(&mut script, &pubkey);
                script.push(op::CODESEPARATOR);
                let from = script.len();
                script.push(op::CHECKSIG);
                items.push(Item::Ecdsa(c.spec(key, from)));
            }
            Template::CodeSepFirst => {
                script.push(op::CODESEPARATOR);
                push_data(&mut script, &pubkey);
                script.push(op::CHECKSIG);
                items.push(Item::Ecdsa(c.spec(key, 1)));
            }
            Template::Multisig | Template::MultisigVerify => {
                let keys: Vec<u32> = (0..c.n as u32).map(|i| 40 + i).collect();
                push_int(&mut script, c.m as i64);
                for (i, k) in keys.iter().enumerate() {
                    // Only the first key takes the odd encoding, so one thing varies at a time.
                    let form = if i == 0 {
                        c.key_form
                    } else {
                        KeyForm::Compressed
                    };
                    push_data(&mut script, &form.encode(*k));
                }
                push_int(&mut script, c.n as i64);
                if template == Template::Multisig {
                    script.push(op::CHECKMULTISIG);
                } else {
                    script.extend_from_slice(&[op::CHECKMULTISIGVERIFY, op::OP_1]);
                }
                items.push(Item::Data(c.dummy.clone()));
                let mut sigs: Vec<Item> = (0..c.sigs_supplied)
                    .map(|i| {
                        let k = keys.get(i).copied().unwrap_or(40);
                        // Damage only the last signature.
                        let mut spec = c.spec(k, 0);
                        if i + 1 != c.sigs_supplied {
                            spec.damage = Damage::None;
                        }
                        Item::Ecdsa(spec)
                    })
                    .collect();
                if c.reverse_sigs {
                    sigs.reverse();
                }
                items.extend(sigs);
            }
            Template::SigInScript => {
                // The signature commits to the script *without* itself; legacy FindAndDelete
                // removes it again before hashing. Under segwit there is no FindAndDelete, so
                // the same construction must fail there.
                let mut tail = Vec::new();
                push_data(&mut tail, &pubkey);
                tail.push(op::CHECKSIG);
                let amount = sk.prevouts[sk.index].1;
                let sig = ecdsa_sig(
                    &c.spec(key, 0),
                    wrapper.sig_version(),
                    &sk.tx,
                    sk.index,
                    &tail,
                    amount,
                );
                push_data(&mut script, &sig);
                script.extend_from_slice(&tail);
            }
            Template::P2wpkh | Template::P2shP2wpkh => {
                let nested = template == Template::P2shP2wpkh;
                wrap_p2wpkh(&mut sk, &pubkey, &c.spec(key, 0), nested);
                wrapper_name = if nested { "p2sh-p2wpkh" } else { "p2wpkh" };
                return to_case(
                    &sk,
                    flags,
                    format!("gen/sig/{wrapper_name}/{}", template.name()),
                );
            }
        }
        debug_assert!(wrapper.sig_version() != SigVersion::Tapscript);
        wrap(&mut sk, wrapper, &script, &items, &tap);
        to_case(
            &sk,
            flags,
            format!("gen/sig/{wrapper_name}/{}", template.name()),
        )
    }

    /// A case that must verify under every consensus flag.
    pub fn valid_case(&self, rng: &mut Rng, template: Template, wrapper: Wrapper) -> Case {
        self.build(
            rng,
            template,
            wrapper,
            &Choices::valid(),
            Flag::CONSENSUS.to_vec(),
        )
    }
}

impl Generator for SigGen {
    fn name(&self) -> &'static str {
        "sig"
    }

    fn generate(&self, rng: &mut Rng) -> Case {
        let template = *rng.pick(&Template::ALL);
        let wrapper = *rng.pick(&Wrapper::PRE_TAPROOT);
        let choices = if rng.chance(12) {
            Choices::valid()
        } else {
            Choices::random(rng)
        };
        let flags = random_flags(rng);
        self.build(rng, template, wrapper, &choices, flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::PublicKey;

    #[test]
    fn key_forms() {
        assert_eq!(KeyForm::Compressed.encode(1).len(), 33);
        assert_eq!(KeyForm::Uncompressed.encode(1).len(), 65);
        assert_eq!(KeyForm::Short.encode(1).len(), 32);
        assert_eq!(KeyForm::Long.encode(1).len(), 34);
        assert!(KeyForm::Empty.encode(1).is_empty());
        // What libsecp256k1 itself accepts, as a sanity check on the labels.
        for form in [KeyForm::Compressed, KeyForm::Uncompressed, KeyForm::Hybrid] {
            assert!(PublicKey::from_slice(&form.encode(2)).is_ok(), "{form:?}");
        }
        for form in [
            KeyForm::BadPrefix,
            KeyForm::Short,
            KeyForm::Long,
            KeyForm::OffCurve,
            KeyForm::HybridWrongParity,
            KeyForm::Empty,
        ] {
            assert!(PublicKey::from_slice(&form.encode(2)).is_err(), "{form:?}");
        }
    }

    #[test]
    fn deterministic_and_tagged() {
        let g = SigGen;
        for seed in 0..50 {
            let a = g.generate(&mut Rng::new(seed));
            let b = g.generate(&mut Rng::new(seed));
            assert_eq!(a, b);
            assert!(a.origin.as_deref().unwrap().starts_with("gen/sig/"));
            assert!(a.is_consensus_only());
        }
    }

    #[test]
    fn random_choices_cover_the_space() {
        let mut rng = Rng::new(1);
        let all: Vec<Choices> = (0..3000).map(|_| Choices::random(&mut rng)).collect();
        for form in KeyForm::ALL {
            assert!(
                all.iter().any(|c| c.key_form == form),
                "{form:?} never chosen"
            );
        }
        for q in DerQuirk::ALL {
            assert!(all.iter().any(|c| c.quirk == q), "{q:?} never chosen");
        }
        for d in Damage::ECDSA {
            assert!(all.iter().any(|c| c.damage == d), "{d:?} never chosen");
        }
        assert!(all.iter().any(|c| c.high_s));
        assert!(all.iter().any(|c| c.n == 21));
        assert!(all.iter().any(|c| c.m > c.n));
        assert!(all.iter().any(|c| c.m == 0));
        assert!(all.iter().any(|c| !c.dummy.is_empty()));
        assert!(all.iter().any(|c| c.sigs_supplied != c.m));
    }
}
