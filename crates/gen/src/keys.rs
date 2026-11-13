//! Deterministic test keys and signature encoding.
//!
//! Every key is derived from a fixed public string and an index, so they are worthless as
//! secrets by construction: **never** fund an address made from them. Signing is deterministic
//! (RFC 6979 for ECDSA, zero auxiliary randomness for BIP340) so cases are reproducible.

use diffuzz_types::taproot::tagged_hash;
use secp256k1::{Keypair, Message, Parity, Scalar, SecretKey, ecdsa, schnorr};
use sha2::{Digest, Sha256};

/// The secp256k1 group order, big-endian.
pub const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// A deterministic test key.
#[derive(Debug, Clone)]
pub struct TestKey {
    /// Index the key was derived from.
    pub index: u32,
    keypair: Keypair,
}

/// Derive test key number `index`. Key `i` is `SHA256("diffuzz-btc test key" || i || ctr)`.
pub fn test_key(index: u32) -> TestKey {
    let mut ctr = 0u32;
    loop {
        let mut h = Sha256::new();
        h.update(b"diffuzz-btc test key");
        h.update(index.to_le_bytes());
        h.update(ctr.to_le_bytes());
        let bytes: [u8; 32] = h.finalize().into();
        // Rejection is cryptographically negligible (zero or >= group order).
        if let Ok(sk) = SecretKey::from_secret_bytes(bytes) {
            return TestKey {
                index,
                keypair: Keypair::from_secret_key(&sk),
            };
        }
        ctr += 1;
    }
}

impl TestKey {
    /// 33-byte compressed public key.
    pub fn compressed(&self) -> [u8; 33] {
        self.keypair.public_key().serialize()
    }

    /// 65-byte uncompressed public key (`04 || X || Y`).
    pub fn uncompressed(&self) -> [u8; 65] {
        self.keypair.public_key().serialize_uncompressed()
    }

    /// 65-byte hybrid public key (`06`/`07 || X || Y`): consensus-valid, non-standard.
    pub fn hybrid(&self) -> [u8; 65] {
        let mut k = self.uncompressed();
        k[0] = if k[64] & 1 == 0 { 0x06 } else { 0x07 };
        k
    }

    /// 32-byte x-only public key (BIP340).
    pub fn xonly(&self) -> [u8; 32] {
        self.keypair.x_only_public_key().0.to_byte_array()
    }

    /// ECDSA-sign a 32-byte digest. Returns `(r, s)` big-endian, with low `s`.
    pub fn sign_ecdsa(&self, digest: [u8; 32]) -> ([u8; 32], [u8; 32]) {
        let sig = ecdsa::sign(Message::from_digest(digest), &self.keypair.secret_key());
        let c = sig.serialize_compact();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&c[..32]);
        s.copy_from_slice(&c[32..]);
        (r, s)
    }

    /// BIP340-sign a 32-byte message with this key.
    pub fn sign_schnorr(&self, msg: [u8; 32]) -> [u8; 64] {
        schnorr::sign_no_aux_rand(&msg, &self.keypair).to_byte_array()
    }

    /// The taproot output key for this key as internal key, and whether it has odd Y.
    pub fn taproot_output(&self, merkle_root: Option<&[u8; 32]>) -> Option<([u8; 32], bool)> {
        let tweaked = self.tweaked(merkle_root)?;
        let (x, parity) = tweaked.x_only_public_key();
        Some((x.to_byte_array(), parity == Parity::Odd))
    }

    /// BIP340-sign with the taproot-tweaked key (key-path spend).
    pub fn sign_schnorr_tweaked(
        &self,
        msg: [u8; 32],
        merkle_root: Option<&[u8; 32]>,
    ) -> Option<[u8; 64]> {
        let tweaked = self.tweaked(merkle_root)?;
        Some(schnorr::sign_no_aux_rand(&msg, &tweaked).to_byte_array())
    }

    fn tweaked(&self, merkle_root: Option<&[u8; 32]>) -> Option<Keypair> {
        let mut data = self.xonly().to_vec();
        if let Some(root) = merkle_root {
            data.extend_from_slice(root);
        }
        let tweak = Scalar::from_be_bytes(tagged_hash("TapTweak", &data)).ok()?;
        self.keypair.add_xonly_tweak(&tweak).ok()
    }
}

/// `ORDER - s`: turns a low-S signature into the equivalent high-S one (and back).
pub fn negate_s(s: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(ORDER[i]) - i16::from(s[i]) - borrow;
        borrow = i16::from(d < 0);
        out[i] = (d + 256 * borrow) as u8;
    }
    out
}

/// Ways to encode a signature that Core's lax DER parser still accepts, but strict DER (BIP66)
/// rejects. With the DERSIG flag every one of these must fail; without it they are valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerQuirk {
    /// Strict, canonical DER.
    Strict,
    /// An unnecessary leading zero byte on R.
    ExtraPadR,
    /// An unnecessary leading zero byte on S.
    ExtraPadS,
    /// Sequence length in long form (`0x81 LL`).
    LongSeqLen,
    /// R's length in long form (`0x81 LL`).
    LongIntLen,
    /// Sequence length byte one too large.
    WrongSeqLen,
    /// One garbage byte after S.
    TrailingByte,
    /// No zero pad on R even when its top bit is set (a "negative" R under strict DER).
    NoPadR,
}

impl DerQuirk {
    /// Every quirk, strict first.
    pub const ALL: [DerQuirk; 8] = [
        DerQuirk::Strict,
        DerQuirk::ExtraPadR,
        DerQuirk::ExtraPadS,
        DerQuirk::LongSeqLen,
        DerQuirk::LongIntLen,
        DerQuirk::WrongSeqLen,
        DerQuirk::TrailingByte,
        DerQuirk::NoPadR,
    ];
}

fn der_int(v: &[u8; 32], extra_pad: bool, omit_pad: bool) -> Vec<u8> {
    let mut bytes: Vec<u8> = v.iter().copied().skip_while(|b| *b == 0).collect();
    if bytes.is_empty() {
        bytes.push(0);
    }
    if bytes[0] & 0x80 != 0 && !omit_pad {
        bytes.insert(0, 0);
    }
    if extra_pad {
        bytes.insert(0, 0);
    }
    bytes
}

/// DER-encode `(r, s)` (without the trailing sighash-type byte), applying `quirk`.
pub fn der_encode(r: &[u8; 32], s: &[u8; 32], quirk: DerQuirk) -> Vec<u8> {
    let r_bytes = der_int(r, quirk == DerQuirk::ExtraPadR, quirk == DerQuirk::NoPadR);
    let s_bytes = der_int(s, quirk == DerQuirk::ExtraPadS, false);
    let mut body = vec![0x02];
    if quirk == DerQuirk::LongIntLen {
        body.push(0x81);
    }
    body.push(r_bytes.len() as u8);
    body.extend_from_slice(&r_bytes);
    body.push(0x02);
    body.push(s_bytes.len() as u8);
    body.extend_from_slice(&s_bytes);

    let mut out = vec![0x30];
    let mut seq_len = body.len() as u8;
    if quirk == DerQuirk::WrongSeqLen {
        seq_len += 1;
    }
    if quirk == DerQuirk::LongSeqLen {
        out.push(0x81);
    }
    out.push(seq_len);
    out.extend_from_slice(&body);
    if quirk == DerQuirk::TrailingByte {
        out.push(0x00);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{PublicKey, XOnlyPublicKey};

    #[test]
    fn keys_are_deterministic_and_distinct() {
        assert_eq!(test_key(3).compressed(), test_key(3).compressed());
        assert_ne!(test_key(3).compressed(), test_key(4).compressed());
        let k = test_key(0);
        assert_eq!(k.index, 0);
        assert!(matches!(k.compressed()[0], 2 | 3));
        assert_eq!(k.uncompressed()[0], 4);
        assert_eq!(&k.uncompressed()[1..33], &k.compressed()[1..]);
        assert_eq!(&k.xonly(), &k.compressed()[1..]);
        let h = k.hybrid();
        assert_eq!(h[0], 6 + (k.compressed()[0] - 2));
        // libsecp256k1 parses hybrid keys.
        assert!(PublicKey::from_slice(&h).is_ok());
    }

    #[test]
    fn ecdsa_signs_and_all_lax_encodings_parse() {
        let k = test_key(1);
        let digest = [7u8; 32];
        let (r, s) = k.sign_ecdsa(digest);
        let pk = PublicKey::from_slice(&k.compressed()).unwrap();
        let msg = Message::from_digest(digest);

        let strict = der_encode(&r, &s, DerQuirk::Strict);
        let sig = ecdsa::Signature::from_der(&strict).unwrap();
        assert!(sig.verify(msg, &pk).is_ok());

        for q in DerQuirk::ALL {
            let enc = der_encode(&r, &s, q);
            let lax = ecdsa::Signature::from_der_lax(&enc)
                .unwrap_or_else(|e| panic!("{q:?} must parse laxly: {e}"));
            assert!(lax.verify(msg, &pk).is_ok(), "{q:?}");
            if q != DerQuirk::Strict && !(q == DerQuirk::NoPadR && r[0] & 0x80 == 0) {
                assert_ne!(enc, strict, "{q:?} must differ from strict encoding");
            }
        }
    }

    #[test]
    fn high_s_is_the_same_signature_modulo_normalization() {
        let k = test_key(2);
        let digest = [9u8; 32];
        let (r, s) = k.sign_ecdsa(digest);
        let high = negate_s(&s);
        assert_ne!(high, s);
        assert_eq!(negate_s(&high), s);
        assert!(high > s, "library signs low-S");
        let mut sig = ecdsa::Signature::from_der(&der_encode(&r, &high, DerQuirk::Strict)).unwrap();
        let pk = PublicKey::from_slice(&k.compressed()).unwrap();
        // libsecp256k1 only verifies normalized signatures; Core normalizes before verifying.
        assert!(sig.verify(Message::from_digest(digest), &pk).is_err());
        sig.normalize_s();
        assert!(sig.verify(Message::from_digest(digest), &pk).is_ok());
    }

    #[test]
    fn schnorr_plain_and_tweaked() {
        let k = test_key(5);
        let msg = [3u8; 32];
        let sig = schnorr::Signature::from_byte_array(k.sign_schnorr(msg));
        let pk = XOnlyPublicKey::from_byte_array(k.xonly()).unwrap();
        assert!(sig.verify(&msg, &pk).is_ok());

        let root = [0x11u8; 32];
        let (out, odd) = k.taproot_output(Some(&root)).unwrap();
        // Matches the context-free tweak used for control blocks.
        assert_eq!(
            diffuzz_types::taproot::tweak_output_key(&k.xonly(), Some(&root)),
            Some((out, odd))
        );
        let sig =
            schnorr::Signature::from_byte_array(k.sign_schnorr_tweaked(msg, Some(&root)).unwrap());
        let out_pk = XOnlyPublicKey::from_byte_array(out).unwrap();
        assert!(sig.verify(&msg, &out_pk).is_ok());
        assert!(sig.verify(&msg, &pk).is_err());
        assert_ne!(k.taproot_output(None).unwrap().0, out);
    }

    #[test]
    fn der_shapes() {
        let mut r = [0u8; 32];
        r[31] = 1;
        let mut s = [0u8; 32];
        s[0] = 0x80;
        // r = 1 -> 02 01 01 ; s has top bit -> 02 21 00 80 ...
        let d = der_encode(&r, &s, DerQuirk::Strict);
        assert_eq!(&d[..5], &[0x30, 0x26, 0x02, 0x01, 0x01]);
        assert_eq!(&d[5..8], &[0x02, 0x21, 0x00]);
        assert_eq!(
            der_encode(&r, &s, DerQuirk::LongSeqLen)[..3],
            [0x30, 0x81, 0x26]
        );
        assert_eq!(der_encode(&r, &s, DerQuirk::WrongSeqLen)[1], 0x27);
        assert_eq!(
            der_encode(&r, &s, DerQuirk::ExtraPadR)[2..6],
            [0x02, 0x02, 0x00, 0x01]
        );
        assert_eq!(
            der_encode(&r, &s, DerQuirk::LongIntLen)[2..5],
            [0x02, 0x81, 0x01]
        );
        assert_eq!(
            der_encode(&r, &s, DerQuirk::TrailingByte).len(),
            d.len() + 1
        );
        // NoPadR on a high-bit R drops the pad byte.
        assert_eq!(
            der_encode(&s, &r, DerQuirk::NoPadR)[2..5],
            [0x02, 0x20, 0x80]
        );
        assert_eq!(der_int(&[0u8; 32], false, false), vec![0]);
    }
}
