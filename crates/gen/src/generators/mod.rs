//! The generators and the weighted mix that combines them.

use diffuzz_types::Case;
use serde::Deserialize;

use crate::rng::Rng;

pub mod mutate;
pub mod script;
pub mod sig;
pub mod taproot;
pub mod wrapper;

/// A source of cases. Implementations are pure functions of the random stream: the same `rng`
/// state always yields the same case.
pub trait Generator {
    /// Short name, used as the second component of a case's `origin` (`gen/<name>/...`).
    fn name(&self) -> &'static str;

    /// Produce one case.
    fn generate(&self, rng: &mut Rng) -> Case;
}

/// Relative weights of the generators in a [`Mix`]. Loaded from `weights.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Weights {
    /// Script grammar and limit cases.
    pub script: u32,
    /// Legacy and segwit v0 signature cases.
    pub sig: u32,
    /// Output-type edge cases.
    pub wrapper: u32,
    /// Taproot and tapscript cases.
    pub taproot: u32,
    /// Mutations of seed cases.
    pub mutate: u32,
}

impl Default for Weights {
    fn default() -> Self {
        Weights {
            script: 30,
            sig: 25,
            wrapper: 10,
            taproot: 25,
            mutate: 10,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WeightsFile {
    weights: Weights,
}

impl Weights {
    /// Parse a `weights.toml` document: a `[weights]` table with any subset of the fields.
    pub fn from_toml(text: &str) -> Result<Weights, String> {
        let file: WeightsFile = toml::from_str(text).map_err(|e| e.to_string())?;
        if file.weights.as_array().iter().all(|w| *w == 0) {
            return Err("all generator weights are zero".to_string());
        }
        Ok(file.weights)
    }

    fn as_array(&self) -> [u32; 5] {
        [
            self.script,
            self.sig,
            self.wrapper,
            self.taproot,
            self.mutate,
        ]
    }
}

/// The weighted combination of all generators.
#[derive(Debug, Clone, Default)]
pub struct Mix {
    weights: Weights,
    script: script::ScriptGen,
    sig: sig::SigGen,
    wrapper: wrapper::WrapperGen,
    taproot: taproot::TaprootGen,
    mutate: mutate::MutateGen,
}

impl Mix {
    /// Build a mix. `seeds` feed the mutator (pass an empty vector to mutate fresh cases).
    pub fn new(weights: Weights, seeds: Vec<Case>) -> Mix {
        Mix {
            weights,
            mutate: mutate::MutateGen::new(seeds),
            ..Mix::default()
        }
    }

    /// The mutator, for mutating specific cases in a feedback loop.
    pub fn mutator(&self) -> &mutate::MutateGen {
        &self.mutate
    }

    /// Generate case number `n` of the stream identified by `seed`. Each case uses its own
    /// forked random stream, so any case can be regenerated from `(seed, n)` alone.
    pub fn case(&self, seed: u64, n: u64) -> Case {
        let mut rng = Rng::new(seed).fork(n);
        self.generate(&mut rng)
    }
}

impl Generator for Mix {
    fn name(&self) -> &'static str {
        "mix"
    }

    fn generate(&self, rng: &mut Rng) -> Case {
        match rng.weighted(&self.weights.as_array()) {
            0 => self.script.generate(rng),
            1 => self.sig.generate(rng),
            2 => self.wrapper.generate(rng),
            3 => self.taproot.generate(rng),
            _ => self.mutate.generate(rng),
        }
    }
}

/// The category of a generated case: the first two components of its origin (`gen/script`),
/// or `"other"` for cases that did not come from a generator.
pub fn category(case: &Case) -> &str {
    let origin = case.origin.as_deref().unwrap_or("");
    match origin.match_indices('/').nth(1) {
        Some((i, _)) if origin.starts_with("gen/") => &origin[..i],
        _ if origin.starts_with("gen/") => origin,
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn weights_parse_and_default() {
        assert_eq!(
            Weights::from_toml("[weights]\n").unwrap(),
            Weights::default()
        );
        let w = Weights::from_toml("[weights]\nscript = 1\nsig = 0\nmutate = 7\n").unwrap();
        assert_eq!((w.script, w.sig, w.mutate), (1, 0, 7));
        assert_eq!(w.taproot, Weights::default().taproot);
        assert!(Weights::from_toml("[weights]\nbogus = 1\n").is_err());
        assert!(Weights::from_toml("").is_err());
        let zero = "[weights]\nscript=0\nsig=0\nwrapper=0\ntaproot=0\nmutate=0\n";
        assert!(Weights::from_toml(zero).unwrap_err().contains("zero"));
    }

    #[test]
    fn repository_weights_file_is_valid() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../weights.toml"))
                .unwrap();
        Weights::from_toml(&text).unwrap();
    }

    #[test]
    fn mix_is_deterministic_and_addressable() {
        let mix = Mix::new(Weights::default(), Vec::new());
        let a: Vec<Case> = (0..40).map(|n| mix.case(7, n)).collect();
        let b: Vec<Case> = (0..40).map(|n| mix.case(7, n)).collect();
        assert_eq!(a, b);
        // Case n does not depend on the cases before it.
        assert_eq!(mix.case(7, 25), a[25]);
        assert_ne!(mix.case(8, 25), a[25]);
        assert_eq!(mix.name(), "mix");
    }

    #[test]
    fn mix_follows_weights_and_reaches_every_generator() {
        let mix = Mix::new(Weights::default(), Vec::new());
        let mut counts: BTreeMap<String, u32> = BTreeMap::new();
        for n in 0..2000 {
            *counts
                .entry(category(&mix.case(1, n)).to_string())
                .or_insert(0) += 1;
        }
        for cat in [
            "gen/script",
            "gen/sig",
            "gen/wrapper",
            "gen/taproot",
            "gen/mutate",
        ] {
            assert!(
                counts.get(cat).copied().unwrap_or(0) > 100,
                "{cat}: {counts:?}"
            );
        }
        assert!(counts["gen/script"] > counts["gen/wrapper"]);

        let only_sig = Weights {
            script: 0,
            sig: 1,
            wrapper: 0,
            taproot: 0,
            mutate: 0,
        };
        let mix = Mix::new(only_sig, Vec::new());
        assert!((0..100).all(|n| category(&mix.case(1, n)) == "gen/sig"));
    }

    #[test]
    fn category_parsing() {
        let c = |o: Option<&str>| Case {
            tx_hex: String::new(),
            input_index: 0,
            prevouts: vec![],
            flags: vec![],
            origin: o.map(str::to_string),
        };
        assert_eq!(category(&c(Some("gen/sig/p2sh/multisig"))), "gen/sig");
        assert_eq!(category(&c(Some("gen/taproot/keypath"))), "gen/taproot");
        assert_eq!(category(&c(Some("gen/x"))), "gen/x");
        assert_eq!(category(&c(Some("script_tests.json#5"))), "other");
        assert_eq!(category(&c(None)), "other");
    }
}
