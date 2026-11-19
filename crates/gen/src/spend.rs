//! Building blocks shared by all generators: a transaction skeleton, output wrappers (bare,
//! P2SH, P2WSH, nested, tapscript, P2WPKH, taproot key path) and deferred signature items that
//! are signed once the wrapper and transaction are fixed.

use diffuzz_types::script::push_data;
use diffuzz_types::taproot;
use diffuzz_types::tx::{Tx, TxIn, TxOut};
use diffuzz_types::{Case, Flag, Prevout, hex};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::keys::{DerQuirk, der_encode, negate_s, test_key};
use crate::rng::Rng;
use crate::sighash::{self, TapscriptContext};

/// SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// RIPEMD160(SHA256(data)).
pub fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(data)).into()
}

/// `HASH160 <20 bytes> EQUAL`
pub fn p2sh_script(redeem: &[u8]) -> Vec<u8> {
    let mut s = vec![0xa9, 0x14];
    s.extend_from_slice(&hash160(redeem));
    s.push(0x87);
    s
}

/// `OP_0 <32-byte SHA256(witness script)>`
pub fn p2wsh_script(witness_script: &[u8]) -> Vec<u8> {
    let mut s = vec![0x00, 0x20];
    s.extend_from_slice(&sha256(witness_script));
    s
}

/// `OP_0 <20-byte HASH160(pubkey)>`
pub fn p2wpkh_script(pubkey: &[u8]) -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend_from_slice(&hash160(pubkey));
    s
}

/// `DUP HASH160 <20 bytes> EQUALVERIFY CHECKSIG`
pub fn p2pkh_script(pubkey: &[u8]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(&hash160(pubkey));
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

/// How an inner script is committed to by the spent output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Wrapper {
    /// The script is the scriptPubKey.
    Bare,
    /// Pay-to-script-hash.
    P2sh,
    /// Native segwit v0 script hash.
    P2wsh,
    /// P2WSH nested in P2SH.
    P2shP2wsh,
    /// Taproot script path (tapscript leaf).
    Tapscript,
}

/// Which signature-hash algorithm and script rules apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigVersion {
    /// Legacy scripts.
    Base,
    /// Segwit v0 (BIP143).
    WitnessV0,
    /// Tapscript (BIP342).
    Tapscript,
}

impl Wrapper {
    /// Every wrapper.
    pub const ALL: [Wrapper; 5] = [
        Wrapper::Bare,
        Wrapper::P2sh,
        Wrapper::P2wsh,
        Wrapper::P2shP2wsh,
        Wrapper::Tapscript,
    ];
    /// Wrappers executing with pre-taproot rules.
    pub const PRE_TAPROOT: [Wrapper; 4] = [
        Wrapper::Bare,
        Wrapper::P2sh,
        Wrapper::P2wsh,
        Wrapper::P2shP2wsh,
    ];

    /// Short name used in case origins and statistics.
    pub fn name(self) -> &'static str {
        match self {
            Wrapper::Bare => "bare",
            Wrapper::P2sh => "p2sh",
            Wrapper::P2wsh => "p2wsh",
            Wrapper::P2shP2wsh => "p2sh-p2wsh",
            Wrapper::Tapscript => "tapscript",
        }
    }

    /// The signature version the inner script executes under.
    pub fn sig_version(self) -> SigVersion {
        match self {
            Wrapper::Bare | Wrapper::P2sh => SigVersion::Base,
            Wrapper::P2wsh | Wrapper::P2shP2wsh => SigVersion::WitnessV0,
            Wrapper::Tapscript => SigVersion::Tapscript,
        }
    }
}

/// A transaction under construction, the input being tested, and all spent outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skeleton {
    /// The spending transaction (scriptSig and witness of `index` are filled in by a wrapper).
    pub tx: Tx,
    /// Input under test.
    pub index: usize,
    /// `(scriptPubKey, amount)` for every input.
    pub prevouts: Vec<(Vec<u8>, u64)>,
}

const SEQUENCES: [u32; 10] = [
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_fffe,
    0,
    1,
    0x0000_ffff,
    0x0040_0000,
    0x8000_0000,
    0x0001_0000,
];
const LOCK_TIMES: [u32; 8] = [
    0,
    0,
    0,
    1,
    499_999_999,
    500_000_000,
    0x7fff_ffff,
    0xffff_ffff,
];
const VERSIONS: [u32; 8] = [1, 2, 2, 2, 0, 3, 0x8000_0000, 0xffff_ffff];

/// A random transaction skeleton: 1 to 3 inputs, 0 to 3 outputs, boundary-heavy version,
/// lock time and sequence values. Inputs other than the one under test spend simple outputs.
pub fn skeleton(rng: &mut Rng) -> Skeleton {
    let n_in = 1 + rng.weighted(&[70, 20, 10]);
    let n_out = rng.weighted(&[5, 60, 25, 10]);
    let mut inputs = Vec::with_capacity(n_in);
    let mut prevouts = Vec::with_capacity(n_in);
    for _ in 0..n_in {
        let mut prev_txid = [0u8; 32];
        prev_txid.copy_from_slice(&rng.bytes(32));
        inputs.push(TxIn {
            prev_txid,
            prev_vout: rng.below(4) as u32,
            script_sig: Vec::new(),
            sequence: *rng.pick(&SEQUENCES),
            witness: Vec::new(),
        });
        let spk = match rng.below(3) {
            0 => vec![0x51],
            1 => p2pkh_script(&test_key(900).compressed()),
            _ => p2wpkh_script(&test_key(901).compressed()),
        };
        prevouts.push((spk, 1_000 + rng.below(1_000_000) as u64));
    }
    let outputs = (0..n_out)
        .map(|_| TxOut {
            value: rng.below(100_000) as u64,
            script_pubkey: match rng.below(3) {
                0 => Vec::new(),
                1 => vec![0x51],
                _ => p2pkh_script(&test_key(902).compressed()),
            },
        })
        .collect();
    Skeleton {
        tx: Tx {
            version: *rng.pick(&VERSIONS),
            inputs,
            outputs,
            lock_time: *rng.pick(&LOCK_TIMES),
        },
        index: rng.below(n_in),
        prevouts,
    }
}

/// How a correctly produced signature is then broken (or not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Damage {
    /// A valid signature.
    None,
    /// One bit of the signature body flipped.
    FlipBit,
    /// Signed with a different key.
    WrongKey,
    /// Signed over a different message.
    WrongMessage,
    /// The empty byte string.
    Empty,
    /// Last signature byte removed.
    Truncated,
    /// Signed for one hash type but labelled with another.
    SwapHashType,
    /// Schnorr only: explicit `0x00` hash-type byte appended (65 bytes, invalid by BIP341).
    ExplicitDefault,
}

impl Damage {
    /// Damages applicable to ECDSA signatures.
    pub const ECDSA: [Damage; 7] = [
        Damage::None,
        Damage::FlipBit,
        Damage::WrongKey,
        Damage::WrongMessage,
        Damage::Empty,
        Damage::Truncated,
        Damage::SwapHashType,
    ];
    /// Damages applicable to Schnorr signatures.
    pub const SCHNORR: [Damage; 8] = [
        Damage::None,
        Damage::FlipBit,
        Damage::WrongKey,
        Damage::WrongMessage,
        Damage::Empty,
        Damage::Truncated,
        Damage::SwapHashType,
        Damage::ExplicitDefault,
    ];
}

/// An ECDSA signature to be produced once the spend is fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdsaSpec {
    /// Test key index.
    pub key: u32,
    /// Hash-type byte (any value: consensus hashes whatever byte is present).
    pub hash_type: u8,
    /// DER encoding variant.
    pub quirk: DerQuirk,
    /// Use the high-S form.
    pub high_s: bool,
    /// Post-signing damage.
    pub damage: Damage,
    /// Byte offset into the inner script where the scriptCode starts (after the last executed
    /// `OP_CODESEPARATOR`; 0 if none).
    pub code_from: usize,
}

impl EcdsaSpec {
    /// A valid, canonical `SIGHASH_ALL` signature by `key`.
    pub fn valid(key: u32) -> EcdsaSpec {
        EcdsaSpec {
            key,
            hash_type: 1,
            quirk: DerQuirk::Strict,
            high_s: false,
            damage: Damage::None,
            code_from: 0,
        }
    }
}

/// A BIP340 signature to be produced once the spend is fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchnorrSpec {
    /// Test key index.
    pub key: u32,
    /// Hash type; 0 means the 64-byte default form.
    pub hash_type: u8,
    /// Post-signing damage.
    pub damage: Damage,
    /// Opcode position of the last executed `OP_CODESEPARATOR` (script path only).
    pub codesep_pos: u32,
}

impl SchnorrSpec {
    /// A valid default-hash-type signature by `key`.
    pub fn valid(key: u32) -> SchnorrSpec {
        SchnorrSpec {
            key,
            hash_type: 0,
            damage: Damage::None,
            codesep_pos: 0xffff_ffff,
        }
    }
}

/// One stack element supplied by the spender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// Literal bytes.
    Data(Vec<u8>),
    /// An ECDSA signature (legacy / segwit v0).
    Ecdsa(EcdsaSpec),
    /// A Schnorr signature (tapscript).
    Schnorr(SchnorrSpec),
}

fn other_hash_type(t: u8) -> u8 {
    if t & 0x03 == 1 {
        (t & 0x80) | 2
    } else {
        (t & 0x80) | 1
    }
}

fn damage_bytes(mut sig: Vec<u8>, damage: Damage) -> Vec<u8> {
    match damage {
        Damage::FlipBit => {
            let i = sig.len() / 2;
            if let Some(b) = sig.get_mut(i) {
                *b ^= 0x08;
            }
        }
        Damage::Truncated => {
            sig.pop();
        }
        Damage::Empty => sig.clear(),
        _ => {}
    }
    sig
}

/// Produce the ECDSA signature bytes (DER plus hash-type byte) for `spec`.
pub fn ecdsa_sig(
    spec: &EcdsaSpec,
    version: SigVersion,
    tx: &Tx,
    index: usize,
    script: &[u8],
    amount: u64,
) -> Vec<u8> {
    let code = script.get(spec.code_from..).unwrap_or(&[]);
    let signed_type = if spec.damage == Damage::SwapHashType {
        other_hash_type(spec.hash_type)
    } else {
        spec.hash_type
    };
    let mut digest = match version {
        SigVersion::Base => sighash::legacy(tx, index, code, u32::from(signed_type)),
        _ => sighash::bip143(tx, index, code, amount, u32::from(signed_type)),
    };
    if spec.damage == Damage::WrongMessage {
        digest[0] ^= 1;
    }
    let key = if spec.damage == Damage::WrongKey {
        spec.key + 500
    } else {
        spec.key
    };
    let (r, mut s) = test_key(key).sign_ecdsa(digest);
    if spec.high_s {
        s = negate_s(&s);
    }
    let der = damage_bytes(der_encode(&r, &s, spec.quirk), spec.damage);
    if spec.damage == Damage::Empty {
        return der;
    }
    let mut sig = der;
    sig.push(spec.hash_type);
    sig
}

/// Produce the Schnorr signature bytes for `spec`. `tweak` is `Some(merkle_root)` for a key-path
/// spend (sign with the tweaked key) and `None` for a script-path signature.
#[allow(clippy::too_many_arguments)]
pub fn schnorr_sig(
    spec: &SchnorrSpec,
    tx: &Tx,
    index: usize,
    prevouts: &[(Vec<u8>, u64)],
    annex: Option<&[u8]>,
    leaf_hash: Option<[u8; 32]>,
    tweak: Option<Option<[u8; 32]>>,
) -> Vec<u8> {
    let signed_type = if spec.damage == Damage::SwapHashType {
        other_hash_type(spec.hash_type.max(1))
    } else {
        spec.hash_type
    };
    let ctx = leaf_hash.map(|leaf_hash| TapscriptContext {
        leaf_hash,
        codesep_pos: spec.codesep_pos,
    });
    // Where BIP341 defines no digest (bad hash type, SINGLE without output) sign a fixed
    // message: the signature is invalid either way, but stays well-formed.
    let mut digest =
        sighash::bip341(tx, index, prevouts, signed_type, annex, ctx).unwrap_or([0x42; 32]);
    if spec.damage == Damage::WrongMessage {
        digest[0] ^= 1;
    }
    let key = test_key(if spec.damage == Damage::WrongKey {
        spec.key + 500
    } else {
        spec.key
    });
    let raw = match tweak {
        Some(root) => key
            .sign_schnorr_tweaked(digest, root.as_ref())
            .unwrap_or([0u8; 64]),
        None => key.sign_schnorr(digest),
    };
    let mut sig = damage_bytes(raw.to_vec(), spec.damage);
    if spec.damage == Damage::Empty {
        return sig;
    }
    if spec.hash_type != 0 || spec.damage == Damage::ExplicitDefault {
        sig.push(spec.hash_type);
    }
    sig
}

/// Internal key of a taproot output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Internal {
    /// The unspendable NUMS point.
    Nums,
    /// A test key.
    Key(u32),
}

impl Internal {
    /// The x-only public key.
    pub fn xonly(self) -> [u8; 32] {
        match self {
            Internal::Nums => taproot::NUMS_H,
            Internal::Key(k) => test_key(k).xonly(),
        }
    }
}

/// Deliberate corruption of a control block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CbTamper {
    /// Well-formed.
    None,
    /// Parity bit inverted.
    FlipParity,
    /// One byte removed (length no longer `33 + 32k`).
    DropByte,
    /// One byte appended.
    ExtraByte,
    /// A bit flipped in the internal key.
    FlipKeyBit,
    /// A bit flipped in the merkle path (only if the path is non-empty).
    FlipPathBit,
}

/// Script-path parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapParams {
    /// Internal key.
    pub internal: Internal,
    /// Merkle path from the leaf to the root.
    pub path: Vec<[u8; 32]>,
    /// Leaf version (0xc0 is tapscript; other even values are "unknown").
    pub leaf_version: u8,
    /// Optional annex (must start with 0x50 to be recognised as one).
    pub annex: Option<Vec<u8>>,
    /// Control block corruption.
    pub tamper: CbTamper,
}

impl Default for TapParams {
    fn default() -> Self {
        TapParams {
            internal: Internal::Nums,
            path: Vec::new(),
            leaf_version: taproot::LEAF_TAPSCRIPT,
            annex: None,
            tamper: CbTamper::None,
        }
    }
}

fn push_all(items: &[Vec<u8>]) -> Vec<u8> {
    let mut s = Vec::new();
    for i in items {
        push_data(&mut s, i);
    }
    s
}

/// Commit `inner` to the spent output with `wrapper`, sign the deferred `items`, and fill in the
/// scriptSig / witness of the input under test. `tap` is used by [`Wrapper::Tapscript`] only.
pub fn wrap(sk: &mut Skeleton, wrapper: Wrapper, inner: &[u8], items: &[Item], tap: &TapParams) {
    let idx = sk.index;
    let amount = sk.prevouts[idx].1;

    // Fix the scriptPubKey first: BIP341 signatures commit to it.
    let mut leaf_hash = None;
    let mut control = Vec::new();
    let spk = match wrapper {
        Wrapper::Bare => inner.to_vec(),
        Wrapper::P2sh => p2sh_script(inner),
        Wrapper::P2wsh => p2wsh_script(inner),
        Wrapper::P2shP2wsh => p2sh_script(&p2wsh_script(inner)),
        Wrapper::Tapscript => {
            let leaf = taproot::tapleaf_hash(tap.leaf_version, inner);
            leaf_hash = Some(leaf);
            let root = taproot::merkle_root(leaf, &tap.path);
            let internal = tap.internal.xonly();
            // NUMS and test keys are always valid points, so the fallback is unreachable.
            let (q, odd) =
                taproot::tweak_output_key(&internal, Some(&root)).unwrap_or(([0; 32], false));
            control = taproot::control_block(tap.leaf_version, odd, &internal, &tap.path);
            match tap.tamper {
                CbTamper::None => {}
                CbTamper::FlipParity => control[0] ^= 1,
                CbTamper::DropByte => {
                    control.pop();
                }
                CbTamper::ExtraByte => control.push(0),
                CbTamper::FlipKeyBit => control[5] ^= 0x10,
                CbTamper::FlipPathBit => {
                    if let Some(b) = control.get_mut(40) {
                        *b ^= 0x10;
                    }
                }
            }
            taproot::p2tr_script(&q)
        }
    };
    sk.prevouts[idx].0 = spk;

    let version = wrapper.sig_version();
    let annex = tap
        .annex
        .as_deref()
        .filter(|_| wrapper == Wrapper::Tapscript);
    let stack: Vec<Vec<u8>> = items
        .iter()
        .map(|item| match item {
            Item::Data(d) => d.clone(),
            Item::Ecdsa(spec) => ecdsa_sig(spec, version, &sk.tx, idx, inner, amount),
            Item::Schnorr(spec) => {
                schnorr_sig(spec, &sk.tx, idx, &sk.prevouts, annex, leaf_hash, None)
            }
        })
        .collect();

    let input = &mut sk.tx.inputs[idx];
    match wrapper {
        Wrapper::Bare => input.script_sig = push_all(&stack),
        Wrapper::P2sh => {
            let mut s = push_all(&stack);
            push_data(&mut s, inner);
            input.script_sig = s;
        }
        Wrapper::P2wsh | Wrapper::P2shP2wsh => {
            if wrapper == Wrapper::P2shP2wsh {
                input.script_sig = push_all(&[p2wsh_script(inner)]);
            }
            let mut w = stack;
            w.push(inner.to_vec());
            input.witness = w;
        }
        Wrapper::Tapscript => {
            let mut w = stack;
            w.push(inner.to_vec());
            w.push(control);
            if let Some(a) = &tap.annex {
                w.push(a.clone());
            }
            input.witness = w;
        }
    }
}

/// Fill in a P2WPKH (or P2SH-nested P2WPKH) spend of `pubkey` signed per `spec`.
pub fn wrap_p2wpkh(sk: &mut Skeleton, pubkey: &[u8], spec: &EcdsaSpec, nested: bool) {
    let idx = sk.index;
    let program = p2wpkh_script(pubkey);
    sk.prevouts[idx].0 = if nested {
        p2sh_script(&program)
    } else {
        program.clone()
    };
    let script_code = p2pkh_script(pubkey);
    let sig = ecdsa_sig(
        spec,
        SigVersion::WitnessV0,
        &sk.tx,
        idx,
        &script_code,
        sk.prevouts[idx].1,
    );
    let input = &mut sk.tx.inputs[idx];
    if nested {
        input.script_sig = push_all(&[program]);
    }
    input.witness = vec![sig, pubkey.to_vec()];
}

/// Fill in a taproot key-path spend of test key `spec.key` with optional script tree root and
/// annex.
pub fn wrap_keypath(
    sk: &mut Skeleton,
    spec: &SchnorrSpec,
    merkle_root: Option<[u8; 32]>,
    annex: Option<Vec<u8>>,
) {
    let idx = sk.index;
    let (q, _) = test_key(spec.key)
        .taproot_output(merkle_root.as_ref())
        .unwrap_or(([0; 32], false));
    sk.prevouts[idx].0 = taproot::p2tr_script(&q);
    let sig = schnorr_sig(
        spec,
        &sk.tx,
        idx,
        &sk.prevouts,
        annex.as_deref(),
        None,
        Some(merkle_root),
    );
    let mut w = vec![sig];
    if let Some(a) = annex {
        w.push(a);
    }
    sk.tx.inputs[idx].witness = w;
}

/// Random consensus flag set: usually everything, sometimes a random subset, always keeping
/// the dependency WITNESS => P2SH that Core requires.
pub fn random_flags(rng: &mut Rng) -> Vec<Flag> {
    let mut flags: Vec<Flag> = Flag::CONSENSUS.to_vec();
    if rng.chance(35) {
        flags.retain(|_| rng.chance(70));
    }
    if !flags.contains(&Flag::P2sh) {
        flags.retain(|f| *f != Flag::Witness);
    }
    flags
}

/// Make the input under test have no output at the same index, so that `SIGHASH_SINGLE` has
/// nothing to commit to: legacy signatures then sign the number one (the "SIGHASH_SINGLE bug"),
/// BIP143 hashes a zero `hashOutputs`, and BIP341 defines no digest at all. Call it before any
/// signature is computed. With several inputs the last one is tested and some outputs are kept;
/// with one input every output is removed.
///
/// Only acts when `single` is set, and then in 40% of calls; returns the origin suffix to
/// append (`"/single-no-output"` or `""`).
pub fn orphan_single(sk: &mut Skeleton, rng: &mut Rng, single: bool) -> &'static str {
    if !single || !rng.chance(40) {
        return "";
    }
    sk.index = sk.tx.inputs.len() - 1;
    let keep = rng.below(sk.index + 1);
    sk.tx.outputs.truncate(keep);
    "/single-no-output"
}

/// Whether a hash type selects `SIGHASH_SINGLE` the way legacy and BIP143 read it (low five
/// bits equal to 3).
pub fn is_single(hash_type: u8) -> bool {
    hash_type & 0x1f == sighash::SIGHASH_SINGLE
}

/// Turn a finished skeleton into a case.
pub fn to_case(sk: &Skeleton, flags: Vec<Flag>, origin: String) -> Case {
    Case {
        tx_hex: hex::encode(&sk.tx.serialize()),
        input_index: sk.index as u32,
        prevouts: sk
            .prevouts
            .iter()
            .map(|(spk, amount)| Prevout {
                script_pubkey_hex: hex::encode(spk),
                amount_sats: *amount,
            })
            .collect(),
        flags,
        origin: Some(origin),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_templates() {
        // HASH160 of the empty string.
        assert_eq!(
            hex::encode(&hash160(&[])),
            "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
        );
        assert_eq!(
            hex::encode(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(p2sh_script(&[0x51]).len(), 23);
        assert_eq!(p2wsh_script(&[0x51]).len(), 34);
        assert_eq!(p2wpkh_script(&[2; 33]).len(), 22);
        assert_eq!(p2pkh_script(&[2; 33]).len(), 25);
    }

    #[test]
    fn skeleton_is_deterministic_and_consistent() {
        let a = skeleton(&mut Rng::new(11));
        let b = skeleton(&mut Rng::new(11));
        assert_eq!(a, b);
        for seed in 0..200 {
            let s = skeleton(&mut Rng::new(seed));
            assert!(!s.tx.inputs.is_empty() && s.tx.inputs.len() <= 3);
            assert_eq!(s.prevouts.len(), s.tx.inputs.len());
            assert!(s.index < s.tx.inputs.len());
            assert!(s.tx.outputs.len() <= 3);
        }
    }

    #[test]
    fn orphan_single_leaves_no_matching_output() {
        for seed in 0..200 {
            let mut rng = Rng::new(seed);
            let mut s = skeleton(&mut rng);
            let before = s.clone();
            assert_eq!(orphan_single(&mut s, &mut rng, false), "");
            assert_eq!(s, before);
            if orphan_single(&mut s, &mut rng, true).is_empty() {
                continue;
            }
            assert!(s.index < s.tx.inputs.len());
            assert!(s.tx.outputs.len() <= s.index);
        }
        assert!(is_single(0x03) && is_single(0x83) && is_single(0x43) && is_single(0x23));
        assert!(!is_single(0x01) && !is_single(0x02) && !is_single(0x04));
    }

    #[test]
    fn wrappers_place_scripts_where_expected() {
        let inner = vec![0x51];
        let items = vec![Item::Data(vec![0xaa])];
        for w in Wrapper::ALL {
            let mut sk = skeleton(&mut Rng::new(3));
            wrap(&mut sk, w, &inner, &items, &TapParams::default());
            let input = &sk.tx.inputs[sk.index];
            let spk = &sk.prevouts[sk.index].0;
            match w {
                Wrapper::Bare => {
                    assert_eq!(spk, &inner);
                    assert_eq!(input.script_sig, vec![0x01, 0xaa]);
                    assert!(input.witness.is_empty());
                }
                Wrapper::P2sh => {
                    assert_eq!(spk, &p2sh_script(&inner));
                    assert_eq!(input.script_sig, vec![0x01, 0xaa, 0x01, 0x51]);
                }
                Wrapper::P2wsh => {
                    assert_eq!(spk, &p2wsh_script(&inner));
                    assert!(input.script_sig.is_empty());
                    assert_eq!(input.witness, vec![vec![0xaa], inner.clone()]);
                }
                Wrapper::P2shP2wsh => {
                    assert_eq!(spk.len(), 23);
                    assert_eq!(input.script_sig.len(), 35);
                    assert_eq!(input.witness.len(), 2);
                }
                Wrapper::Tapscript => {
                    assert_eq!(spk.len(), 34);
                    assert_eq!(input.witness.len(), 3);
                    assert_eq!(input.witness[2].len(), 33);
                }
            }
            assert!(!w.name().is_empty());
        }
    }

    #[test]
    fn control_block_tampering_and_annex() {
        let mut tap = TapParams {
            path: vec![[9u8; 32]],
            ..TapParams::default()
        };
        let mut lens = Vec::new();
        for t in [CbTamper::None, CbTamper::DropByte, CbTamper::ExtraByte] {
            tap.tamper = t;
            let mut sk = skeleton(&mut Rng::new(1));
            wrap(&mut sk, Wrapper::Tapscript, &[0x51], &[], &tap);
            lens.push(sk.tx.inputs[sk.index].witness[1].len());
        }
        assert_eq!(lens, vec![65, 64, 66]);

        tap.tamper = CbTamper::None;
        tap.annex = Some(vec![0x50, 0x01]);
        let mut sk = skeleton(&mut Rng::new(1));
        wrap(&mut sk, Wrapper::Tapscript, &[0x51], &[], &tap);
        assert_eq!(
            sk.tx.inputs[sk.index].witness.last(),
            Some(&vec![0x50, 0x01])
        );
    }

    #[test]
    fn signature_shapes() {
        let mut sk = skeleton(&mut Rng::new(2));
        let spec = EcdsaSpec::valid(1);
        let script = [0xac];
        let sig = ecdsa_sig(&spec, SigVersion::Base, &sk.tx, sk.index, &script, 0);
        assert_eq!(sig[0], 0x30);
        assert_eq!(*sig.last().unwrap(), 1);
        let empty = EcdsaSpec {
            damage: Damage::Empty,
            ..spec
        };
        assert!(ecdsa_sig(&empty, SigVersion::Base, &sk.tx, sk.index, &script, 0).is_empty());
        let v0 = ecdsa_sig(&spec, SigVersion::WitnessV0, &sk.tx, sk.index, &script, 5);
        assert_ne!(v0, sig, "different sighash algorithm, different signature");

        let s = SchnorrSpec::valid(1);
        wrap_keypath(&mut sk, &s, None, None);
        assert_eq!(sk.tx.inputs[sk.index].witness[0].len(), 64);
        let explicit = SchnorrSpec {
            hash_type: 0x83,
            ..s
        };
        wrap_keypath(&mut sk, &explicit, None, Some(vec![0x50]));
        let w = &sk.tx.inputs[sk.index].witness;
        assert_eq!((w[0].len(), w[0][64], w.len()), (65, 0x83, 2));
        let bad = SchnorrSpec {
            damage: Damage::ExplicitDefault,
            ..s
        };
        wrap_keypath(&mut sk, &bad, None, None);
        assert_eq!(sk.tx.inputs[sk.index].witness[0].len(), 65);
        assert_eq!(other_hash_type(1), 2);
        assert_eq!(other_hash_type(0x83), 0x81);
    }

    #[test]
    fn flags_keep_witness_dependency() {
        let mut r = Rng::new(9);
        let mut subset_seen = false;
        for _ in 0..500 {
            let f = random_flags(&mut r);
            assert!(f.iter().all(|x| x.is_consensus()));
            assert!(!f.contains(&Flag::Witness) || f.contains(&Flag::P2sh));
            subset_seen |= f.len() < 7;
        }
        assert!(subset_seen);
    }

    #[test]
    fn case_conversion() {
        let mut sk = skeleton(&mut Rng::new(4));
        wrap_p2wpkh(
            &mut sk,
            &test_key(1).compressed(),
            &EcdsaSpec::valid(1),
            true,
        );
        let case = to_case(&sk, vec![Flag::P2sh], "gen/test".into());
        assert_eq!(case.input_index as usize, sk.index);
        assert_eq!(case.prevouts.len(), sk.prevouts.len());
        assert_eq!(
            Tx::deserialize(&hex::decode(&case.tx_hex).unwrap()).unwrap(),
            sk.tx
        );
        assert_eq!(case.origin.as_deref(), Some("gen/test"));
        assert_eq!(sk.tx.inputs[sk.index].witness.len(), 2);
        assert_eq!(sk.tx.inputs[sk.index].script_sig.len(), 23);
    }
}
