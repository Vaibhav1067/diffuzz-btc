//! Mutators: take an existing case (a corpus vector or a kept fuzz case) and perturb it.
//!
//! Mutations work on the decoded transaction where possible so that results stay structurally
//! valid, and scripts are edited at opcode granularity. After a script that is committed to by
//! hash (P2SH redeem script, P2WSH witness script) is changed, the commitment is usually
//! recomputed, otherwise nearly every mutant would die at the hash check.

use diffuzz_types::script::{Instruction, instructions, op, push_data, push_int};
use diffuzz_types::tx::Tx;
use diffuzz_types::{Case, Flag, hex};

use super::Generator;
use crate::rng::Rng;
use crate::spend::{p2sh_script, sha256};

/// Integers worth trying wherever a number appears.
const BOUNDARY: [i64; 16] = [
    0,
    1,
    -1,
    16,
    17,
    127,
    128,
    255,
    256,
    520,
    521,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
    499_999_999,
    500_000_000,
];
const BOUNDARY_U32: [u32; 10] = [
    0,
    1,
    2,
    0xffff,
    0x0040_0000,
    499_999_999,
    500_000_000,
    0x7fff_ffff,
    0xffff_fffe,
    0xffff_ffff,
];

/// The mutation operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    /// Flip one bit of a script or witness item.
    BitFlip,
    /// Insert a random byte.
    InsertByte,
    /// Delete one byte.
    DeleteByte,
    /// Replace one opcode with another, keeping pushes intact.
    SubstituteOpcode,
    /// Insert a run of instructions taken from another case's script.
    Splice,
    /// Replace a pushed number, or a numeric transaction field, with a boundary value.
    BoundaryInt,
    /// Duplicate, drop or empty a witness item.
    WitnessShape,
    /// Add or remove a consensus flag.
    ToggleFlag,
    /// Delete one whole instruction.
    DeleteInstruction,
}

impl Mutation {
    /// Every operator.
    pub const ALL: [Mutation; 9] = [
        Mutation::BitFlip,
        Mutation::InsertByte,
        Mutation::DeleteByte,
        Mutation::SubstituteOpcode,
        Mutation::Splice,
        Mutation::BoundaryInt,
        Mutation::WitnessShape,
        Mutation::ToggleFlag,
        Mutation::DeleteInstruction,
    ];
}

fn encode_instruction(out: &mut Vec<u8>, script: &[u8], ins: &[Instruction<'_>], i: usize) {
    let end = ins.get(i + 1).map(|n| n.offset).unwrap_or(script.len());
    out.extend_from_slice(&script[ins[i].offset..end]);
}

/// Byte-level mutation of any blob.
fn mutate_bytes(rng: &mut Rng, data: &mut Vec<u8>, m: Mutation) {
    match m {
        Mutation::InsertByte => {
            let at = rng.below(data.len() + 1);
            data.insert(at, rng.byte());
        }
        Mutation::DeleteByte if !data.is_empty() => {
            let at = rng.below(data.len());
            data.remove(at);
        }
        _ if !data.is_empty() => {
            let at = rng.below(data.len());
            data[at] ^= 1 << rng.below(8);
        }
        _ => data.push(rng.byte()),
    }
}

/// Instruction-level mutation of a script. `donor` supplies material for splicing.
fn mutate_script(rng: &mut Rng, script: &mut Vec<u8>, m: Mutation, donor: &[u8]) {
    let original = script.clone();
    let (ins, complete) = instructions(&original);
    if !complete || ins.is_empty() {
        mutate_bytes(rng, script, Mutation::BitFlip);
        return;
    }
    match m {
        Mutation::SubstituteOpcode => {
            let candidates: Vec<usize> =
                (0..ins.len()).filter(|i| ins[*i].data.is_none()).collect();
            if candidates.is_empty() {
                return mutate_bytes(rng, script, Mutation::BitFlip);
            }
            let target = *rng.pick(&candidates);
            // Mostly a defined non-push opcode, sometimes an undefined one; never a push
            // opcode, which would swallow the following bytes.
            let old = ins[target].opcode;
            let mut new = if rng.chance(85) {
                0x4f + rng.below(0xba - 0x4f + 1) as u8
            } else {
                0xbb + rng.below(0x100 - 0xbb) as u8
            };
            if new == old {
                new = if old == op::NOP { op::DUP } else { op::NOP };
            }
            script[ins[target].offset] = new;
        }
        Mutation::DeleteInstruction => {
            let target = rng.below(ins.len());
            let mut out = Vec::with_capacity(original.len());
            for i in (0..ins.len()).filter(|i| *i != target) {
                encode_instruction(&mut out, &original, &ins, i);
            }
            *script = out;
        }
        Mutation::Splice => {
            let (donor_ins, _) = instructions(donor);
            let mut piece = Vec::new();
            if donor_ins.is_empty() {
                piece.push(*rng.pick(&[op::DUP, op::DROP, op::OP_1, op::NOP, op::CHECKSIG]));
            } else {
                let start = rng.below(donor_ins.len());
                let len = rng.range(1, 4).min(donor_ins.len() - start);
                for i in start..start + len {
                    encode_instruction(&mut piece, donor, &donor_ins, i);
                }
            }
            let at = rng.below(ins.len() + 1);
            let offset = ins.get(at).map(|i| i.offset).unwrap_or(original.len());
            script.splice(offset..offset, piece);
        }
        Mutation::BoundaryInt => {
            // Replace one push (or small-number opcode) with a boundary number.
            let candidates: Vec<usize> = (0..ins.len())
                .filter(|i| ins[*i].data.is_some() || matches!(ins[*i].opcode, 0x4f | 0x51..=0x60))
                .collect();
            let mut replacement = Vec::new();
            if rng.chance(15) {
                push_data(
                    &mut replacement,
                    &vec![0x5a; *rng.pick(&[75usize, 76, 255, 256, 520, 521])],
                );
            } else {
                push_int(&mut replacement, *rng.pick(&BOUNDARY));
            }
            if candidates.is_empty() {
                script.splice(0..0, replacement);
                return;
            }
            let target = *rng.pick(&candidates);
            let end = ins
                .get(target + 1)
                .map(|n| n.offset)
                .unwrap_or(original.len());
            script.splice(ins[target].offset..end, replacement);
        }
        other => mutate_bytes(rng, script, other),
    }
}

/// Which part of a case a mutation is aimed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    ScriptSig,
    ScriptPubKey,
    /// The last witness item that is a script (P2WSH witness script or tapscript leaf).
    WitnessScript,
    /// Any witness item, as raw bytes.
    WitnessItem,
    /// The P2SH redeem script (last push of the scriptSig).
    RedeemScript,
    TxField,
}

fn is_p2sh(spk: &[u8]) -> bool {
    spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87
}

fn is_p2wsh(spk: &[u8]) -> bool {
    spk.len() == 34 && spk[0] == 0x00 && spk[1] == 0x20
}

/// The data of the last push in a push-only scriptSig, with the byte range of that instruction.
fn last_push(script_sig: &[u8]) -> Option<(Vec<u8>, std::ops::Range<usize>)> {
    let (ins, complete) = instructions(script_sig);
    if !complete {
        return None;
    }
    let last = ins.last()?;
    Some((last.data?.to_vec(), last.offset..script_sig.len()))
}

/// Apply one mutation to `case`. `donor` is another case whose scripts feed splicing. Returns
/// the mutated case, or the input unchanged if it cannot be decoded.
pub fn mutate(rng: &mut Rng, case: &Case, donor: &Case, m: Mutation) -> Case {
    let mut out = case.clone();
    if m == Mutation::ToggleFlag {
        let f = *rng.pick(&Flag::CONSENSUS);
        if out.flags.contains(&f) {
            out.flags.retain(|x| *x != f);
        } else {
            out.flags.push(f);
        }
        // Keep the dependency Core's consensus library insists on.
        if out.flags.contains(&Flag::Witness) && !out.flags.contains(&Flag::P2sh) {
            out.flags.push(Flag::P2sh);
        }
        diffuzz_types::normalize_flags(&mut out.flags);
        return out;
    }

    let Some(raw) = hex::decode(&case.tx_hex) else {
        return out;
    };
    let Ok(mut tx) = Tx::deserialize(&raw) else {
        return out;
    };
    let idx = case.input_index as usize;
    if idx >= tx.inputs.len() || idx >= out.prevouts.len() {
        return out;
    }
    let Some(mut spk) = hex::decode(&out.prevouts[idx].script_pubkey_hex) else {
        return out;
    };
    let donor_script = donor
        .prevouts
        .get(donor.input_index as usize)
        .and_then(|p| hex::decode(&p.script_pubkey_hex))
        .unwrap_or_default();

    let has_witness = !tx.inputs[idx].witness.is_empty();
    let mut targets = vec![Target::ScriptSig, Target::ScriptPubKey, Target::TxField];
    if has_witness {
        targets.extend([
            Target::WitnessScript,
            Target::WitnessScript,
            Target::WitnessItem,
        ]);
    }
    if is_p2sh(&spk) && last_push(&tx.inputs[idx].script_sig).is_some() {
        targets.extend([Target::RedeemScript, Target::RedeemScript]);
    }
    let target = if m == Mutation::WitnessShape {
        Target::WitnessItem
    } else if m == Mutation::BoundaryInt && rng.chance(35) {
        Target::TxField
    } else {
        *rng.pick(&targets)
    };
    // Usually keep hash commitments consistent so the mutated script is actually executed.
    let recommit = rng.chance(75);

    match target {
        Target::ScriptSig => mutate_script(rng, &mut tx.inputs[idx].script_sig, m, &donor_script),
        Target::ScriptPubKey => mutate_script(rng, &mut spk, m, &donor_script),
        Target::RedeemScript => {
            if let Some((mut redeem, range)) = last_push(&tx.inputs[idx].script_sig) {
                mutate_script(rng, &mut redeem, m, &donor_script);
                let mut push = Vec::new();
                push_data(&mut push, &redeem);
                tx.inputs[idx].script_sig.splice(range, push);
                if recommit {
                    spk = p2sh_script(&redeem);
                }
            }
        }
        Target::WitnessScript => {
            let w = &mut tx.inputs[idx].witness;
            // P2WSH: the script is the last item. Taproot script path: second to last (before
            // the control block); mutating it without re-deriving the output key breaks the
            // commitment, which is itself a path worth exercising.
            let pos = if is_p2wsh(&spk) || w.len() < 2 {
                w.len() - 1
            } else {
                w.len() - 2
            };
            mutate_script(rng, &mut w[pos], m, &donor_script);
            if recommit && is_p2wsh(&spk) {
                spk.truncate(2);
                spk.extend_from_slice(&sha256(&w[pos]));
            }
        }
        Target::WitnessItem => {
            let w = &mut tx.inputs[idx].witness;
            if m == Mutation::WitnessShape || w.is_empty() {
                match rng.below(4) {
                    0 if !w.is_empty() => {
                        let at = rng.below(w.len());
                        w.remove(at);
                    }
                    1 if !w.is_empty() => {
                        let at = rng.below(w.len());
                        let item = w[at].clone();
                        w.insert(at, item);
                    }
                    2 if !w.is_empty() => {
                        let at = rng.below(w.len());
                        w[at].clear();
                    }
                    _ => {
                        let at = rng.below(w.len() + 1);
                        let n = *rng.pick(&[0usize, 1, 32, 64]);
                        w.insert(at, rng.bytes(n));
                    }
                }
            } else {
                let at = rng.below(w.len());
                let kind = *rng.pick(&[
                    Mutation::BitFlip,
                    Mutation::InsertByte,
                    Mutation::DeleteByte,
                ]);
                mutate_bytes(rng, &mut w[at], kind);
            }
        }
        Target::TxField => match rng.below(5) {
            0 => tx.version = *rng.pick(&BOUNDARY_U32),
            1 => tx.lock_time = *rng.pick(&BOUNDARY_U32),
            2 => tx.inputs[idx].sequence = *rng.pick(&BOUNDARY_U32),
            3 => {
                out.prevouts[idx].amount_sats =
                    *rng.pick(&[0u64, 1, 546, 2_100_000_000_000_000, i64::MAX as u64]);
            }
            _ => {
                if let Some(o) = tx.outputs.first_mut() {
                    o.value = *rng.pick(&[0u64, 1, 2_100_000_000_000_000, u64::MAX]);
                } else {
                    tx.outputs.push(Default::default());
                }
            }
        },
    }

    out.prevouts[idx].script_pubkey_hex = hex::encode(&spk);
    out.tx_hex = hex::encode(&tx.serialize());
    out
}

/// Mutates cases drawn from a fixed seed pool.
#[derive(Debug, Clone, Default)]
pub struct MutateGen {
    seeds: Vec<Case>,
}

impl MutateGen {
    /// Create a mutator over `seeds` (corpus vectors, kept fuzz cases...).
    pub fn new(seeds: Vec<Case>) -> MutateGen {
        MutateGen { seeds }
    }

    /// Number of seed cases.
    pub fn seed_count(&self) -> usize {
        self.seeds.len()
    }

    /// Mutate a specific case 1 to 3 times, drawing splice material from the pool.
    pub fn mutate_case(&self, rng: &mut Rng, case: &Case) -> Case {
        let mut out = case.clone();
        for _ in 0..1 + rng.weighted(&[60, 30, 10]) {
            let donor = if self.seeds.is_empty() {
                case
            } else {
                rng.pick(&self.seeds)
            };
            let m = *rng.pick(&Mutation::ALL);
            out = mutate(rng, &out, donor, m);
        }
        // Half of all mutants get fresh signatures from the test keys, so mutations of signed
        // data can still reach success paths (see `resign`).
        let mut tag = "";
        if rng.chance(50) {
            let resigned = crate::resign::resign(&out);
            if resigned != out {
                out = resigned;
                tag = "resigned/";
            }
        }
        let parent = case.origin.as_deref().unwrap_or("unknown");
        // Keep origins bounded when mutants are mutated again.
        let parent = parent.strip_prefix("gen/mutate/").unwrap_or(parent);
        let parent = parent.strip_prefix("resigned/").unwrap_or(parent);
        out.origin = Some(format!("gen/mutate/{tag}{parent}"));
        out
    }
}

impl Generator for MutateGen {
    fn name(&self) -> &'static str {
        "mutate"
    }

    fn generate(&self, rng: &mut Rng) -> Case {
        if self.seeds.is_empty() {
            // No pool: mutate a fresh signature case instead of producing nothing.
            let base = super::sig::SigGen.generate(rng);
            return self.mutate_case(rng, &base);
        }
        let seed = rng.pick(&self.seeds).clone();
        self.mutate_case(rng, &seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generators::sig::{SigGen, Template};
    use crate::spend::Wrapper;

    fn pool() -> Vec<Case> {
        let g = SigGen;
        let mut v = Vec::new();
        for (i, w) in Wrapper::PRE_TAPROOT.iter().enumerate() {
            v.push(g.valid_case(&mut Rng::new(i as u64), Template::P2pkh, *w));
            v.push(g.valid_case(&mut Rng::new(100 + i as u64), Template::Multisig, *w));
        }
        v
    }

    #[test]
    fn script_mutations_preserve_parseability_where_promised() {
        let script = hex::decode("76a914000102030405060708090a0b0c0d0e0f1011121388ac").unwrap();
        let donor = [op::OP_1, op::DUP, op::EQUAL];
        for seed in 0..300 {
            let mut rng = Rng::new(seed);
            for m in [
                Mutation::SubstituteOpcode,
                Mutation::DeleteInstruction,
                Mutation::Splice,
                Mutation::BoundaryInt,
            ] {
                let mut s = script.clone();
                mutate_script(&mut rng, &mut s, m, &donor);
                assert_ne!(s, script, "{m:?} must change the script (seed {seed})");
                assert!(
                    instructions(&s).1,
                    "{m:?} must keep the script parseable (seed {seed})"
                );
            }
        }
    }

    #[test]
    fn byte_mutations_handle_empty_input() {
        for m in [
            Mutation::BitFlip,
            Mutation::InsertByte,
            Mutation::DeleteByte,
        ] {
            let mut v = Vec::new();
            mutate_bytes(&mut Rng::new(1), &mut v, m);
            assert_eq!(v.len(), 1, "{m:?}");
        }
        let mut s = Vec::new();
        mutate_script(&mut Rng::new(1), &mut s, Mutation::Splice, &[]);
        assert!(!s.is_empty());
    }

    #[test]
    fn mutants_are_decodable_and_differ() {
        let seeds = pool();
        let g = MutateGen::new(seeds.clone());
        assert_eq!(g.seed_count(), 8);
        let mut changed = 0;
        let mut resigned = 0;
        for seed in 0..400 {
            let c = g.generate(&mut Rng::new(seed));
            assert_eq!(c, g.generate(&mut Rng::new(seed)), "deterministic");
            let origin = c.origin.as_deref().unwrap();
            let rest = origin.strip_prefix("gen/mutate/").unwrap();
            if let Some(r) = rest.strip_prefix("resigned/") {
                resigned += 1;
                assert!(r.starts_with("gen/sig/"), "{origin}");
            } else {
                assert!(rest.starts_with("gen/sig/"), "{origin}");
            }
            let tx = Tx::deserialize(&hex::decode(&c.tx_hex).unwrap()).unwrap();
            assert_eq!(tx.inputs.len(), c.prevouts.len());
            assert!(c.is_consensus_only());
            assert!(!c.flags.contains(&Flag::Witness) || c.flags.contains(&Flag::P2sh));
            let same_as_a_seed = seeds
                .iter()
                .any(|s| s.tx_hex == c.tx_hex && s.prevouts == c.prevouts && s.flags == c.flags);
            changed += usize::from(!same_as_a_seed);
        }
        assert!(
            changed > 380,
            "only {changed}/400 mutants differ from their seeds"
        );
        assert!(resigned > 50, "only {resigned}/400 mutants were re-signed");
    }

    #[test]
    fn recommit_keeps_hash_commitments_consistent_most_of_the_time() {
        let g = SigGen;
        let base = g.valid_case(&mut Rng::new(5), Template::P2pk, Wrapper::P2wsh);
        let mut consistent = 0;
        let mut total = 0;
        for seed in 0..300 {
            let mut rng = Rng::new(seed);
            let m = mutate(&mut rng, &base, &base, Mutation::SubstituteOpcode);
            let tx = Tx::deserialize(&hex::decode(&m.tx_hex).unwrap()).unwrap();
            let base_tx = Tx::deserialize(&hex::decode(&base.tx_hex).unwrap()).unwrap();
            let i = m.input_index as usize;
            if tx.inputs[i].witness.last() == base_tx.inputs[i].witness.last() {
                continue; // the witness script was not the target this time
            }
            total += 1;
            let spk = hex::decode(&m.prevouts[i].script_pubkey_hex).unwrap();
            let ws = tx.inputs[i].witness.last().unwrap();
            consistent += usize::from(spk[2..] == sha256(ws));
        }
        assert!(total > 30, "witness script rarely targeted: {total}");
        assert!(
            consistent * 10 > total * 6 && consistent < total,
            "{consistent}/{total}"
        );
    }

    #[test]
    fn empty_pool_still_generates() {
        let g = MutateGen::default();
        let c = g.generate(&mut Rng::new(1));
        assert!(c.origin.as_deref().unwrap().starts_with("gen/mutate/"));
    }
}
