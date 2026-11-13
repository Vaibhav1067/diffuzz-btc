//! A small, self-contained deterministic PRNG.
//!
//! Reproducibility is a hard requirement: the same seed must give the same cases on every
//! platform and after every dependency update. Owning the algorithm (xoshiro256** seeded with
//! SplitMix64) guarantees that; an external RNG crate could change its output between versions.
//! This is not a cryptographic generator and is never used for key material that matters.

/// Deterministic random source for case generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rng {
    s: [u64; 4],
}

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

impl Rng {
    /// Create a generator from a 64-bit seed.
    pub fn new(seed: u64) -> Rng {
        let mut st = seed;
        Rng {
            s: [
                splitmix(&mut st),
                splitmix(&mut st),
                splitmix(&mut st),
                splitmix(&mut st),
            ],
        }
    }

    /// Derive an independent generator for a numbered sub-stream (e.g. one per case), so a
    /// single case can be regenerated without replaying everything before it.
    pub fn fork(&self, stream: u64) -> Rng {
        let mut st =
            self.s[0] ^ stream.wrapping_mul(0xd6e8_feb8_6659_fd93) ^ self.s[2].rotate_left(17);
        Rng {
            s: [
                splitmix(&mut st),
                splitmix(&mut st),
                splitmix(&mut st),
                splitmix(&mut st),
            ],
        }
    }

    /// Next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Uniform value in `0..n`. Returns 0 when `n` is 0.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        // Multiply-shift; the bias is negligible for the small ranges used here.
        ((u128::from(self.next_u64()) * n as u128) >> 64) as usize
    }

    /// Uniform value in `lo..=hi`.
    pub fn range(&mut self, lo: usize, hi: usize) -> usize {
        if hi <= lo {
            lo
        } else {
            lo + self.below(hi - lo + 1)
        }
    }

    /// True with probability `percent`/100.
    pub fn chance(&mut self, percent: u32) -> bool {
        self.below(100) < percent as usize
    }

    /// A random byte.
    pub fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }

    /// `n` random bytes.
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            let chunk = self.next_u64().to_le_bytes();
            let take = (n - v.len()).min(8);
            v.extend_from_slice(&chunk[..take]);
        }
        v
    }

    /// A uniformly chosen element. Panics on an empty slice (a programming error).
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    /// Index chosen with probability proportional to `weights`. Returns 0 if all are zero.
    pub fn weighted(&mut self, weights: &[u32]) -> usize {
        let total: u64 = weights.iter().map(|w| u64::from(*w)).sum();
        if total == 0 {
            return 0;
        }
        let mut roll = ((u128::from(self.next_u64()) * u128::from(total)) >> 64) as u64;
        for (i, w) in weights.iter().enumerate() {
            if roll < u64::from(*w) {
                return i;
            }
            roll -= u64::from(*w);
        }
        weights.len() - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_seed_sensitive() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        let mut c = Rng::new(43);
        let xs: Vec<u64> = (0..8).map(|_| a.next_u64()).collect();
        let ys: Vec<u64> = (0..8).map(|_| b.next_u64()).collect();
        let zs: Vec<u64> = (0..8).map(|_| c.next_u64()).collect();
        assert_eq!(xs, ys);
        assert_ne!(xs, zs);
    }

    #[test]
    fn output_is_pinned() {
        // Guards against accidental changes to the algorithm: generated corpora would no
        // longer be reproducible from their seeds.
        let mut r = Rng::new(0);
        assert_eq!(r.next_u64(), 0x99ec_5f36_cb75_f2b4);
        assert_eq!(r.next_u64(), 0xbf6e_1f78_4956_452a);
    }

    #[test]
    fn ranges() {
        let mut r = Rng::new(7);
        for _ in 0..2000 {
            assert!(r.below(10) < 10);
            let v = r.range(3, 5);
            assert!((3..=5).contains(&v));
        }
        assert_eq!(r.below(0), 0);
        assert_eq!(r.range(9, 9), 9);
        assert_eq!(r.range(9, 2), 9);
        assert_eq!(r.bytes(13).len(), 13);
        assert!(!r.chance(0));
        assert!(r.chance(100));
        assert!([1, 2, 3].contains(r.pick(&[1, 2, 3])));
    }

    #[test]
    fn weighted_respects_zero_weights() {
        let mut r = Rng::new(1);
        let mut hits = [0u32; 3];
        for _ in 0..3000 {
            hits[r.weighted(&[1, 0, 3])] += 1;
        }
        assert_eq!(hits[1], 0);
        assert!(hits[2] > hits[0] * 2, "{hits:?}");
        assert_eq!(r.weighted(&[0, 0]), 0);
        assert_eq!(r.weighted(&[]), 0);
    }

    #[test]
    fn fork_is_independent_and_stable() {
        let base = Rng::new(5);
        let mut a = base.fork(1);
        let mut b = base.fork(2);
        let mut a2 = base.fork(1);
        assert_eq!(a.next_u64(), a2.next_u64());
        assert_ne!(a.next_u64(), b.next_u64());
    }
}
