//! BIP340/341 building blocks: tagged hashes, leaf/branch hashes, output-key tweaking and
//! control blocks. Used to build taproot test vectors and generated cases.

use secp256k1::{Parity, Scalar, XOnlyPublicKey};
use sha2::{Digest, Sha256};

use crate::tx::write_compact_size;

/// The tapscript leaf version (BIP342).
pub const LEAF_TAPSCRIPT: u8 = 0xc0;

/// The "nothing up my sleeve" x-only point `H` from BIP341, used as an unspendable internal key
/// (`XOnlyPubKey::NUMS_H` in Bitcoin Core).
pub const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// BIP340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || data)`.
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let t = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(data);
    h.finalize().into()
}

/// `TapLeaf` hash of a script under a leaf version.
pub fn tapleaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    let mut data = vec![leaf_version];
    write_compact_size(&mut data, script.len() as u64);
    data.extend_from_slice(script);
    tagged_hash("TapLeaf", &data)
}

/// `TapBranch` hash of two child hashes (sorted lexicographically, as BIP341 requires).
pub fn tapbranch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(lo);
    data[32..].copy_from_slice(hi);
    tagged_hash("TapBranch", &data)
}

/// Merkle root reached from `leaf_hash` by folding in `path` (leaf to root).
pub fn merkle_root(leaf_hash: [u8; 32], path: &[[u8; 32]]) -> [u8; 32] {
    path.iter()
        .fold(leaf_hash, |acc, sibling| tapbranch_hash(&acc, sibling))
}

/// Compute the taproot output key `Q = P + H_TapTweak(P || root) * G`.
///
/// Returns the x-only output key and whether `Q` has odd Y, or `None` if `internal_key` is not
/// a valid x-only point or the tweak is out of range (cryptographically negligible).
pub fn tweak_output_key(
    internal_key: &[u8; 32],
    merkle_root: Option<&[u8; 32]>,
) -> Option<([u8; 32], bool)> {
    let p = XOnlyPublicKey::from_byte_array(*internal_key).ok()?;
    let mut data = internal_key.to_vec();
    if let Some(root) = merkle_root {
        data.extend_from_slice(root);
    }
    let tweak = Scalar::from_be_bytes(tagged_hash("TapTweak", &data)).ok()?;
    let (q, parity) = p.add_tweak(&tweak).ok()?;
    Some((q.to_byte_array(), parity == Parity::Odd))
}

/// Serialize a control block: `(leaf_version | parity) || internal_key || path`.
pub fn control_block(
    leaf_version: u8,
    output_key_odd: bool,
    internal_key: &[u8; 32],
    path: &[[u8; 32]],
) -> Vec<u8> {
    let mut cb = Vec::with_capacity(33 + 32 * path.len());
    cb.push((leaf_version & 0xfe) | u8::from(output_key_odd));
    cb.extend_from_slice(internal_key);
    for node in path {
        cb.extend_from_slice(node);
    }
    cb
}

/// The scriptPubKey `OP_1 <32-byte output key>`.
pub fn p2tr_script(output_key: &[u8; 32]) -> Vec<u8> {
    let mut s = vec![0x51, 0x20];
    s.extend_from_slice(output_key);
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    // BIP341 wallet-test-vectors.json, scriptPubKey[0]: key-path only.
    #[test]
    fn bip341_key_only_output() {
        let internal = h32("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
        let (q, _) = tweak_output_key(&internal, None).unwrap();
        assert_eq!(
            hex::encode(&q),
            "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
        );
        assert_eq!(
            hex::encode(&p2tr_script(&q)),
            "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
        );
    }

    // BIP341 wallet-test-vectors.json, scriptPubKey[1]: one script leaf.
    #[test]
    fn bip341_single_leaf() {
        let internal = h32("187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27");
        let script =
            hex::decode("20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac")
                .unwrap();
        let leaf = tapleaf_hash(LEAF_TAPSCRIPT, &script);
        assert_eq!(
            hex::encode(&leaf),
            "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21"
        );
        let root = merkle_root(leaf, &[]);
        let (q, odd) = tweak_output_key(&internal, Some(&root)).unwrap();
        assert_eq!(
            hex::encode(&q),
            "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3"
        );
        let cb = control_block(LEAF_TAPSCRIPT, odd, &internal, &[]);
        assert_eq!(
            hex::encode(&cb),
            "c1187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27"
        );
    }

    #[test]
    fn branch_is_order_independent() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(tapbranch_hash(&a, &b), tapbranch_hash(&b, &a));
        assert_ne!(tapbranch_hash(&a, &b), tapbranch_hash(&a, &a));
        assert_eq!(merkle_root(a, &[b]), tapbranch_hash(&a, &b));
    }

    #[test]
    fn nums_h_is_a_valid_point_and_bad_keys_are_rejected() {
        assert!(tweak_output_key(&NUMS_H, Some(&[7u8; 32])).is_some());
        // x = 0 is not on the curve... nor is all-ones (>= field size).
        assert!(tweak_output_key(&[0xff; 32], None).is_none());
    }

    #[test]
    fn tagged_hash_known_value() {
        // SHA256(SHA256("TapLeaf")||SHA256("TapLeaf")) prefix check via an empty-script leaf.
        let leaf = tapleaf_hash(0xc0, &[]);
        assert_eq!(leaf, tagged_hash("TapLeaf", &[0xc0, 0x00]));
        assert_ne!(leaf, tapleaf_hash(0xc2, &[]));
    }
}
