//! A deliberately small transaction model with our own (de)serializer.
//!
//! The fuzzer needs byte-level control over transactions (for building vectors, mutating and
//! minimizing), independent of any implementation under test. This is *not* a validating parser:
//! it accepts anything structurally decodable.

use sha2::{Digest, Sha256};

/// A transaction input.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TxIn {
    /// Previous transaction id in internal (little-endian, as serialized) byte order.
    pub prev_txid: [u8; 32],
    /// Previous output index.
    pub prev_vout: u32,
    /// scriptSig bytes.
    pub script_sig: Vec<u8>,
    /// nSequence.
    pub sequence: u32,
    /// Witness stack (empty for non-witness inputs).
    pub witness: Vec<Vec<u8>>,
}

/// A transaction output.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TxOut {
    /// Value in satoshis.
    pub value: u64,
    /// scriptPubKey bytes.
    pub script_pubkey: Vec<u8>,
}

/// A transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Tx {
    /// nVersion (raw 32 bits).
    pub version: u32,
    /// Inputs.
    pub inputs: Vec<TxIn>,
    /// Outputs.
    pub outputs: Vec<TxOut>,
    /// nLockTime.
    pub lock_time: u32,
}

/// Why a byte string could not be decoded as a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxDecodeError {
    /// Ran out of bytes.
    UnexpectedEof,
    /// Bytes left over after the lock time.
    TrailingBytes,
    /// Extended format with an unknown flag byte, or a witness flag with no witness data.
    BadWitnessFlag,
    /// A declared count or length is larger than the remaining data could hold.
    Oversized,
}

impl std::fmt::Display for TxDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            TxDecodeError::UnexpectedEof => "unexpected end of data",
            TxDecodeError::TrailingBytes => "trailing bytes after transaction",
            TxDecodeError::BadWitnessFlag => "bad segwit marker/flag",
            TxDecodeError::Oversized => "declared size exceeds data",
        };
        f.write_str(s)
    }
}

impl std::error::Error for TxDecodeError {}

/// Append a Bitcoin CompactSize integer.
pub fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// Double SHA-256.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TxDecodeError> {
        let end = self.pos.checked_add(n).ok_or(TxDecodeError::Oversized)?;
        let s = self
            .data
            .get(self.pos..end)
            .ok_or(TxDecodeError::UnexpectedEof)?;
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, TxDecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, TxDecodeError> {
        let mut b = [0u8; 4];
        b.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(b))
    }

    fn u64(&mut self) -> Result<u64, TxDecodeError> {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(b))
    }

    /// CompactSize, without enforcing canonical encoding (this parser is lenient on purpose).
    fn compact(&mut self) -> Result<u64, TxDecodeError> {
        Ok(match self.u8()? {
            0xfd => {
                let mut b = [0u8; 2];
                b.copy_from_slice(self.take(2)?);
                u64::from(u16::from_le_bytes(b))
            }
            0xfe => u64::from(self.u32()?),
            0xff => self.u64()?,
            n => u64::from(n),
        })
    }

    /// A count of items that each need at least `min_item` bytes.
    fn count(&mut self, min_item: usize) -> Result<usize, TxDecodeError> {
        let n = self.compact()?;
        let remaining = (self.data.len() - self.pos) as u64;
        if n.saturating_mul(min_item as u64) > remaining {
            return Err(TxDecodeError::Oversized);
        }
        Ok(n as usize)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, TxDecodeError> {
        let n = self.count(1)?;
        Ok(self.take(n)?.to_vec())
    }
}

impl Tx {
    /// True if any input carries witness data.
    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(|i| !i.witness.is_empty())
    }

    fn write(&self, with_witness: bool) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        if with_witness {
            out.extend_from_slice(&[0x00, 0x01]);
        }
        write_compact_size(&mut out, self.inputs.len() as u64);
        for i in &self.inputs {
            out.extend_from_slice(&i.prev_txid);
            out.extend_from_slice(&i.prev_vout.to_le_bytes());
            write_compact_size(&mut out, i.script_sig.len() as u64);
            out.extend_from_slice(&i.script_sig);
            out.extend_from_slice(&i.sequence.to_le_bytes());
        }
        write_compact_size(&mut out, self.outputs.len() as u64);
        for o in &self.outputs {
            out.extend_from_slice(&o.value.to_le_bytes());
            write_compact_size(&mut out, o.script_pubkey.len() as u64);
            out.extend_from_slice(&o.script_pubkey);
        }
        if with_witness {
            for i in &self.inputs {
                write_compact_size(&mut out, i.witness.len() as u64);
                for item in &i.witness {
                    write_compact_size(&mut out, item.len() as u64);
                    out.extend_from_slice(item);
                }
            }
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// Network serialization: BIP144 extended format if any input has a witness, legacy otherwise.
    pub fn serialize(&self) -> Vec<u8> {
        self.write(self.has_witness())
    }

    /// Legacy serialization without witness data (the txid preimage).
    pub fn serialize_no_witness(&self) -> Vec<u8> {
        self.write(false)
    }

    /// Transaction id in internal byte order (reverse it for display).
    pub fn txid(&self) -> [u8; 32] {
        sha256d(&self.serialize_no_witness())
    }

    /// Witness transaction id in internal byte order.
    pub fn wtxid(&self) -> [u8; 32] {
        sha256d(&self.serialize())
    }

    /// Decode a transaction in legacy or BIP144 extended format.
    pub fn deserialize(data: &[u8]) -> Result<Tx, TxDecodeError> {
        let mut r = Reader { data, pos: 0 };
        let version = r.u32()?;
        let mut n_in = r.count(41)?;
        let mut flag = 0u8;
        if n_in == 0 {
            // Either the segwit marker or a (useless) transaction with no inputs.
            flag = r.u8()?;
            if flag != 0 {
                n_in = r.count(41)?;
            }
        }
        let mut inputs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            let mut prev_txid = [0u8; 32];
            prev_txid.copy_from_slice(r.take(32)?);
            let prev_vout = r.u32()?;
            let script_sig = r.bytes()?;
            let sequence = r.u32()?;
            inputs.push(TxIn {
                prev_txid,
                prev_vout,
                script_sig,
                sequence,
                witness: Vec::new(),
            });
        }
        let mut outputs = Vec::new();
        if !(n_in == 0 && flag == 0) {
            let n_out = r.count(9)?;
            outputs.reserve(n_out);
            for _ in 0..n_out {
                let value = r.u64()?;
                let script_pubkey = r.bytes()?;
                outputs.push(TxOut {
                    value,
                    script_pubkey,
                });
            }
        }
        if flag & 1 != 0 {
            flag ^= 1;
            for input in &mut inputs {
                let n = r.count(1)?;
                let mut stack = Vec::with_capacity(n);
                for _ in 0..n {
                    stack.push(r.bytes()?);
                }
                input.witness = stack;
            }
            if inputs.iter().all(|i| i.witness.is_empty()) {
                return Err(TxDecodeError::BadWitnessFlag);
            }
        }
        if flag != 0 {
            return Err(TxDecodeError::BadWitnessFlag);
        }
        let lock_time = r.u32()?;
        if r.pos != data.len() {
            return Err(TxDecodeError::TrailingBytes);
        }
        Ok(Tx {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    // BIP143 native P2WPKH example transaction (signed).
    const SEGWIT_TX: &str = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";

    #[test]
    fn segwit_round_trip_and_ids() {
        let raw = hex::decode(SEGWIT_TX).unwrap();
        let tx = Tx::deserialize(&raw).unwrap();
        assert_eq!(tx.version, 1);
        assert_eq!(tx.inputs.len(), 2);
        assert_eq!(tx.outputs.len(), 2);
        assert!(tx.inputs[0].witness.is_empty());
        assert_eq!(tx.inputs[1].witness.len(), 2);
        assert_eq!(tx.lock_time, 0x11);
        assert_eq!(tx.serialize(), raw);
        assert_ne!(tx.txid(), tx.wtxid());
        // The legacy form parses back to the same tx minus witnesses.
        let legacy = Tx::deserialize(&tx.serialize_no_witness()).unwrap();
        assert_eq!(legacy.txid(), tx.txid());
        assert!(!legacy.has_witness());
    }

    #[test]
    fn known_txid() {
        // Genesis block coinbase.
        let raw = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000").unwrap();
        let tx = Tx::deserialize(&raw).unwrap();
        let mut id = tx.txid();
        id.reverse();
        assert_eq!(
            hex::encode(&id),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
        assert_eq!(tx.serialize(), raw);
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(Tx::deserialize(&[]), Err(TxDecodeError::UnexpectedEof));
        let raw = hex::decode(SEGWIT_TX).unwrap();
        assert!(Tx::deserialize(&raw[..raw.len() - 1]).is_err());
        let mut extra = raw.clone();
        extra.push(0);
        assert_eq!(Tx::deserialize(&extra), Err(TxDecodeError::TrailingBytes));
        // Huge declared input count must not allocate.
        let huge = hex::decode("01000000ffffffffffffffffff").unwrap();
        assert_eq!(Tx::deserialize(&huge), Err(TxDecodeError::Oversized));
    }

    #[test]
    fn compact_size_boundaries() {
        let mut v = Vec::new();
        write_compact_size(&mut v, 0xfc);
        write_compact_size(&mut v, 0xfd);
        write_compact_size(&mut v, 0x1_0000);
        write_compact_size(&mut v, 0x1_0000_0000);
        assert_eq!(hex::encode(&v), "fcfdfd00fe00000100ff0000000001000000");
    }
}
