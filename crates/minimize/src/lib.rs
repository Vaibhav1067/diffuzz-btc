//! Delta-debugging minimizer for diverging cases.
//!
//! [`minimize`] repeatedly tries simplifications and keeps each one only if the caller's
//! predicate says the case is still interesting (normally: "the implementations still disagree
//! in the same way"). The predicate is re-evaluated for every candidate, the order of attempts
//! is fixed, and no randomness is used, so the result is deterministic.
//!
//! Scripts that are committed to by hash (P2SH redeem scripts, P2WSH witness scripts, tapscript
//! leaves) are edited together with their commitment, otherwise every edit would only change
//! the failure to "hash mismatch".

#![forbid(unsafe_code)]

use diffuzz_types::script::{instructions, push_data};
use diffuzz_types::taproot;
use diffuzz_types::tx::{Tx, sha256d};
use diffuzz_types::{Case, Flag, Prevout, hex};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// What the minimizer did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    /// Candidates evaluated with the predicate.
    pub attempts: u64,
    /// Candidates accepted.
    pub accepted: u64,
    /// Full passes over all reductions.
    pub rounds: u32,
    /// Serialized transaction size before, in bytes.
    pub bytes_before: usize,
    /// Serialized transaction size after, in bytes.
    pub bytes_after: usize,
}

/// A decoded, editable case.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Work {
    tx: Tx,
    index: usize,
    prevouts: Vec<(Vec<u8>, u64)>,
    flags: Vec<Flag>,
    origin: Option<String>,
}

impl Work {
    fn decode(case: &Case) -> Option<Work> {
        let tx = Tx::deserialize(&hex::decode(&case.tx_hex)?).ok()?;
        let index = case.input_index as usize;
        if index >= tx.inputs.len() || tx.inputs.len() != case.prevouts.len() {
            return None;
        }
        let mut prevouts = Vec::with_capacity(case.prevouts.len());
        for p in &case.prevouts {
            prevouts.push((hex::decode(&p.script_pubkey_hex)?, p.amount_sats));
        }
        Some(Work {
            tx,
            index,
            prevouts,
            flags: case.flags.clone(),
            origin: case.origin.clone(),
        })
    }

    fn encode(&self) -> Case {
        Case {
            tx_hex: hex::encode(&self.tx.serialize()),
            input_index: self.index as u32,
            prevouts: self
                .prevouts
                .iter()
                .map(|(s, a)| Prevout {
                    script_pubkey_hex: hex::encode(s),
                    amount_sats: *a,
                })
                .collect(),
            flags: self.flags.clone(),
            origin: self.origin.clone(),
        }
    }

    fn size(&self) -> usize {
        self.tx.serialize().len() + self.prevouts.iter().map(|p| p.0.len()).sum::<usize>()
    }
}

fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(data)).into()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn is_p2sh(s: &[u8]) -> bool {
    s.len() == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87
}

fn is_p2wsh(s: &[u8]) -> bool {
    s.len() == 34 && s[0] == 0x00 && s[1] == 0x20
}

fn is_p2tr(s: &[u8]) -> bool {
    s.len() == 34 && s[0] == 0x51 && s[1] == 0x20
}

fn p2sh(redeem: &[u8]) -> Vec<u8> {
    let mut s = vec![0xa9, 0x14];
    s.extend_from_slice(&hash160(redeem));
    s.push(0x87);
    s
}

fn p2wsh(script: &[u8]) -> Vec<u8> {
    let mut s = vec![0x00, 0x20];
    s.extend_from_slice(&sha256(script));
    s
}

/// The last push of a fully parseable script and the byte offset where it starts.
fn last_push(script: &[u8]) -> Option<(Vec<u8>, usize)> {
    let (ins, complete) = instructions(script);
    if !complete {
        return None;
    }
    let last = ins.last()?;
    Some((last.data?.to_vec(), last.offset))
}

/// A script inside a case that can be edited, with its commitment kept consistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    /// The scriptSig (for P2SH: everything before the redeem-script push).
    ScriptSig,
    /// A scriptPubKey that is not itself a commitment to another script.
    ScriptPubKey,
    /// P2SH redeem script.
    Redeem,
    /// P2WSH witness script (native or nested).
    WitnessScript,
    /// Tapscript leaf.
    TapLeaf,
}

const SLOTS: [Slot; 5] = [
    Slot::WitnessScript,
    Slot::TapLeaf,
    Slot::Redeem,
    Slot::ScriptPubKey,
    Slot::ScriptSig,
];

/// Position of the tapscript leaf in the witness, if this looks like a script-path spend.
fn tap_leaf_pos(witness: &[Vec<u8>]) -> Option<usize> {
    let mut n = witness.len();
    if n >= 2 && witness[n - 1].first() == Some(&0x50) {
        n -= 1;
    }
    (n >= 2).then(|| n - 2)
}

impl Work {
    /// The witness program in force: the scriptPubKey itself, or the P2SH redeem script.
    fn nested_program(&self) -> Option<Vec<u8>> {
        let spk = &self.prevouts[self.index].0;
        if !is_p2sh(spk) {
            return None;
        }
        last_push(&self.tx.inputs[self.index].script_sig)
            .map(|(r, _)| r)
            .filter(|r| is_p2wsh(r))
    }

    fn get(&self, slot: Slot) -> Option<Vec<u8>> {
        let input = &self.tx.inputs[self.index];
        let spk = &self.prevouts[self.index].0;
        match slot {
            Slot::ScriptSig => {
                if is_p2sh(spk) {
                    let (_, at) = last_push(&input.script_sig)?;
                    Some(input.script_sig[..at].to_vec())
                } else {
                    Some(input.script_sig.clone())
                }
            }
            Slot::ScriptPubKey => {
                (!is_p2sh(spk) && !is_p2wsh(spk) && !is_p2tr(spk)).then(|| spk.clone())
            }
            Slot::Redeem => {
                if !is_p2sh(spk) || self.nested_program().is_some() {
                    return None;
                }
                last_push(&input.script_sig).map(|(r, _)| r)
            }
            Slot::WitnessScript => (is_p2wsh(spk) || self.nested_program().is_some())
                .then(|| input.witness.last().cloned())
                .flatten(),
            Slot::TapLeaf => {
                if !is_p2tr(spk) {
                    return None;
                }
                tap_leaf_pos(&input.witness).map(|p| input.witness[p].clone())
            }
        }
    }

    fn set(&mut self, slot: Slot, script: Vec<u8>) -> bool {
        let idx = self.index;
        match slot {
            Slot::ScriptSig => {
                if is_p2sh(&self.prevouts[idx].0) {
                    let Some((_, at)) = last_push(&self.tx.inputs[idx].script_sig) else {
                        return false;
                    };
                    let tail = self.tx.inputs[idx].script_sig[at..].to_vec();
                    let mut s = script;
                    s.extend_from_slice(&tail);
                    self.tx.inputs[idx].script_sig = s;
                } else {
                    self.tx.inputs[idx].script_sig = script;
                }
            }
            Slot::ScriptPubKey => self.prevouts[idx].0 = script,
            Slot::Redeem => {
                let Some((_, at)) = last_push(&self.tx.inputs[idx].script_sig) else {
                    return false;
                };
                self.tx.inputs[idx].script_sig.truncate(at);
                push_data(&mut self.tx.inputs[idx].script_sig, &script);
                self.prevouts[idx].0 = p2sh(&script);
            }
            Slot::WitnessScript => {
                let nested = self.nested_program().is_some();
                let program = p2wsh(&script);
                let Some(last) = self.tx.inputs[idx].witness.last_mut() else {
                    return false;
                };
                *last = script;
                if nested {
                    let Some((_, at)) = last_push(&self.tx.inputs[idx].script_sig) else {
                        return false;
                    };
                    self.tx.inputs[idx].script_sig.truncate(at);
                    push_data(&mut self.tx.inputs[idx].script_sig, &program);
                    self.prevouts[idx].0 = p2sh(&program);
                } else {
                    self.prevouts[idx].0 = program;
                }
            }
            Slot::TapLeaf => {
                let w = &mut self.tx.inputs[idx].witness;
                let Some(pos) = tap_leaf_pos(w) else {
                    return false;
                };
                let control = w[pos + 1].clone();
                // Only a well-formed control block can be re-committed.
                if control.len() < 33 || !(control.len() - 33).is_multiple_of(32) {
                    return false;
                }
                let mut internal = [0u8; 32];
                internal.copy_from_slice(&control[1..33]);
                let path: Vec<[u8; 32]> = control[33..].as_chunks::<32>().0.to_vec();
                let leaf = taproot::tapleaf_hash(control[0] & 0xfe, &script);
                let root = taproot::merkle_root(leaf, &path);
                let Some((q, odd)) = taproot::tweak_output_key(&internal, Some(&root)) else {
                    return false;
                };
                w[pos] = script;
                w[pos + 1][0] = (control[0] & 0xfe) | u8::from(odd);
                self.prevouts[idx].0 = taproot::p2tr_script(&q);
            }
        }
        true
    }
}

struct Ctx<'a> {
    still_interesting: &'a mut dyn FnMut(&Case) -> bool,
    stats: Stats,
    budget: u64,
}

impl Ctx<'_> {
    /// Try a candidate; on success replace `work` with it.
    fn try_replace(&mut self, work: &mut Work, candidate: Work) -> bool {
        if candidate == *work || self.stats.attempts >= self.budget {
            return false;
        }
        self.stats.attempts += 1;
        if (self.still_interesting)(&candidate.encode()) {
            *work = candidate;
            self.stats.accepted += 1;
            true
        } else {
            false
        }
    }
}

/// Try to replace a hash-committed script by the same script used directly as the
/// scriptPubKey, with the remaining stack items pushed by the scriptSig. This removes the
/// wrapper whenever the divergence does not depend on it.
fn unwrap_to_bare(ctx: &mut Ctx<'_>, work: &mut Work) {
    let idx = work.index;
    let mut c = work.clone();
    if let Some(inner) = work.get(Slot::WitnessScript) {
        let witness = &work.tx.inputs[idx].witness;
        let mut script_sig = Vec::new();
        for item in &witness[..witness.len() - 1] {
            push_data(&mut script_sig, item);
        }
        c.tx.inputs[idx].witness.clear();
        c.tx.inputs[idx].script_sig = script_sig;
        c.prevouts[idx].0 = inner;
    } else if let Some(inner) = work.get(Slot::Redeem) {
        let Some(prefix) = work.get(Slot::ScriptSig) else {
            return;
        };
        c.tx.inputs[idx].script_sig = prefix;
        c.prevouts[idx].0 = inner;
    } else {
        return;
    }
    ctx.try_replace(work, c);
}

fn drop_other_inputs(ctx: &mut Ctx<'_>, work: &mut Work) {
    let mut i = 0;
    while i < work.tx.inputs.len() {
        if i == work.index {
            i += 1;
            continue;
        }
        let mut c = work.clone();
        c.tx.inputs.remove(i);
        c.prevouts.remove(i);
        if i < c.index {
            c.index -= 1;
        }
        if !ctx.try_replace(work, c) {
            i += 1;
        }
    }
}

fn drop_outputs(ctx: &mut Ctx<'_>, work: &mut Work) {
    let mut i = work.tx.outputs.len();
    while i > 0 {
        i -= 1;
        let mut c = work.clone();
        c.tx.outputs.remove(i);
        ctx.try_replace(work, c);
    }
}

fn drop_witness_items(ctx: &mut Ctx<'_>, work: &mut Work) {
    let mut i = work.tx.inputs[work.index].witness.len();
    while i > 0 {
        i -= 1;
        if i >= work.tx.inputs[work.index].witness.len() {
            continue;
        }
        let mut c = work.clone();
        c.tx.inputs[c.index].witness.remove(i);
        ctx.try_replace(work, c);
    }
}

/// Re-encode a list of instruction byte ranges.
fn join(script: &[u8], ranges: &[(usize, usize)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (a, b) in ranges {
        out.extend_from_slice(&script[*a..*b]);
    }
    out
}

fn instruction_ranges(script: &[u8]) -> Vec<(usize, usize)> {
    let (ins, complete) = instructions(script);
    let mut ranges: Vec<(usize, usize)> = Vec::with_capacity(ins.len() + 1);
    for (i, ins_i) in ins.iter().enumerate() {
        let end = ins.get(i + 1).map(|n| n.offset).unwrap_or(script.len());
        ranges.push((ins_i.offset, end));
    }
    if !complete {
        // Keep an unparsable tail as one removable unit; `ranges` already ends at script.len()
        // for the last parsed instruction, so split it off.
        if let Some(last) = ranges.last_mut() {
            let parsed_end = ins
                .last()
                .map(|i| i.offset + 1 + i.data.map(|d| d.len()).unwrap_or(0))
                .unwrap_or(0)
                .min(script.len());
            if parsed_end > last.0 && parsed_end < script.len() {
                let tail = (parsed_end, script.len());
                last.1 = parsed_end;
                ranges.push(tail);
            }
        } else if !script.is_empty() {
            ranges.push((0, script.len()));
        }
    }
    ranges
}

/// Classic ddmin over the instructions of one script slot.
fn reduce_script(ctx: &mut Ctx<'_>, work: &mut Work, slot: Slot) {
    let Some(mut script) = work.get(slot) else {
        return;
    };
    let mut chunk = instruction_ranges(&script).len().max(1);
    while chunk >= 1 {
        let ranges = instruction_ranges(&script);
        let mut start = 0;
        let mut progressed = false;
        while start < ranges.len() {
            let end = (start + chunk).min(ranges.len());
            let kept: Vec<(usize, usize)> = ranges[..start]
                .iter()
                .chain(&ranges[end..])
                .copied()
                .collect();
            let candidate_script = join(&script, &kept);
            let mut c = work.clone();
            if c.set(slot, candidate_script.clone()) && ctx.try_replace(work, c) {
                script = candidate_script;
                progressed = true;
                break; // ranges changed; restart this chunk size
            }
            start += chunk;
        }
        if !progressed {
            if chunk == 1 {
                break;
            }
            chunk /= 2;
        }
    }
}

/// Shorten pushed data inside one script slot.
fn shrink_pushes(ctx: &mut Ctx<'_>, work: &mut Work, slot: Slot) {
    let mut i = 0;
    loop {
        let Some(script) = work.get(slot) else { return };
        let (ins, complete) = instructions(&script);
        if !complete || i >= ins.len() {
            return;
        }
        let Some(data) = ins[i].data else {
            i += 1;
            continue;
        };
        let end = ins.get(i + 1).map(|n| n.offset).unwrap_or(script.len());
        let mut done = false;
        for replacement in [Vec::new(), vec![0x01], data[..data.len() / 2].to_vec()] {
            if replacement.len() >= data.len() {
                continue;
            }
            let mut s = script[..ins[i].offset].to_vec();
            push_data(&mut s, &replacement);
            s.extend_from_slice(&script[end..]);
            let mut c = work.clone();
            if c.set(slot, s) && ctx.try_replace(work, c) {
                done = true;
                break;
            }
        }
        if !done {
            i += 1;
        }
    }
}

fn shrink_witness_items(ctx: &mut Ctx<'_>, work: &mut Work) {
    for i in 0..work.tx.inputs[work.index].witness.len() {
        loop {
            let item = work.tx.inputs[work.index].witness[i].clone();
            if item.is_empty() {
                break;
            }
            let mut shrunk = false;
            for replacement in [Vec::new(), item[..item.len() / 2].to_vec()] {
                let mut c = work.clone();
                c.tx.inputs[c.index].witness[i] = replacement;
                if ctx.try_replace(work, c) {
                    shrunk = true;
                    break;
                }
            }
            if !shrunk {
                break;
            }
        }
    }
}

/// One field simplification.
type Edit = Box<dyn Fn(&mut Work)>;

fn simplify_fields(ctx: &mut Ctx<'_>, work: &mut Work) {
    let idx = work.index;
    let edits: Vec<Edit> = vec![
        Box::new(|w| w.tx.lock_time = 0),
        Box::new(|w| w.tx.version = 2),
        Box::new(|w| w.tx.version = 1),
        Box::new(move |w| w.tx.inputs[idx].sequence = 0xffff_ffff),
        Box::new(move |w| w.tx.inputs[idx].prev_txid = [0; 32]),
        Box::new(move |w| w.tx.inputs[idx].prev_vout = 0),
        Box::new(move |w| w.prevouts[idx].1 = 0),
        Box::new(|w| w.tx.outputs.iter_mut().for_each(|o| o.value = 0)),
        Box::new(|w| {
            w.tx.outputs
                .iter_mut()
                .for_each(|o| o.script_pubkey.clear())
        }),
        Box::new(move |w| {
            for (i, input) in w.tx.inputs.iter_mut().enumerate() {
                if i != idx {
                    input.script_sig.clear();
                    input.witness.clear();
                    input.sequence = 0xffff_ffff;
                    // Keep outpoints distinct so adapters that key by outpoint still work.
                    input.prev_txid = sha256d(&[i as u8]);
                    input.prev_vout = 0;
                }
            }
            for (i, p) in w.prevouts.iter_mut().enumerate() {
                if i != idx {
                    *p = (vec![0x51], 0);
                }
            }
        }),
    ];
    for edit in &edits {
        let mut c = work.clone();
        edit(&mut c);
        ctx.try_replace(work, c);
    }
}

fn drop_flags(ctx: &mut Ctx<'_>, work: &mut Work) {
    for f in Flag::ALL.iter().rev() {
        if !work.flags.contains(f) {
            continue;
        }
        let mut c = work.clone();
        c.flags.retain(|x| x != f);
        // Core's library requires P2SH whenever WITNESS is set.
        if c.flags.contains(&Flag::Witness) && !c.flags.contains(&Flag::P2sh) {
            continue;
        }
        ctx.try_replace(work, c);
    }
}

/// Shrink `case` while `still_interesting` keeps returning `true` for the result.
///
/// The predicate must return `true` for `case` itself; if it does not (a flaky divergence),
/// the case is returned unchanged with zero accepted steps. `max_attempts` bounds the number
/// of predicate evaluations.
pub fn minimize(
    case: &Case,
    still_interesting: &mut dyn FnMut(&Case) -> bool,
    max_attempts: u64,
) -> (Case, Stats) {
    let Some(mut work) = Work::decode(case) else {
        return (case.clone(), Stats::default());
    };
    let mut ctx = Ctx {
        still_interesting,
        stats: Stats {
            bytes_before: work.size(),
            ..Stats::default()
        },
        budget: max_attempts,
    };
    // Re-verify the starting point: never "minimize" something that does not reproduce.
    ctx.stats.attempts += 1;
    if !(ctx.still_interesting)(&work.encode()) {
        ctx.stats.bytes_after = ctx.stats.bytes_before;
        return (case.clone(), ctx.stats);
    }

    loop {
        let before = work.clone();
        ctx.stats.rounds += 1;
        drop_other_inputs(&mut ctx, &mut work);
        unwrap_to_bare(&mut ctx, &mut work);
        drop_outputs(&mut ctx, &mut work);
        drop_flags(&mut ctx, &mut work);
        drop_witness_items(&mut ctx, &mut work);
        for slot in SLOTS {
            reduce_script(&mut ctx, &mut work, slot);
        }
        for slot in SLOTS {
            shrink_pushes(&mut ctx, &mut work, slot);
        }
        shrink_witness_items(&mut ctx, &mut work);
        simplify_fields(&mut ctx, &mut work);
        if work == before || ctx.stats.attempts >= ctx.budget || ctx.stats.rounds >= 20 {
            break;
        }
    }
    ctx.stats.bytes_after = work.size();
    (work.encode(), ctx.stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffuzz_types::tx::{TxIn, TxOut};

    fn case(spk: Vec<u8>, script_sig: Vec<u8>, witness: Vec<Vec<u8>>) -> Case {
        let mk = |n: u8| TxIn {
            prev_txid: [n; 32],
            prev_vout: 3,
            script_sig: vec![0x51, 0x51],
            sequence: 7,
            witness: Vec::new(),
        };
        let mut me = mk(2);
        me.script_sig = script_sig;
        me.witness = witness;
        let tx = Tx {
            version: 0xffff_ffff,
            inputs: vec![mk(1), me, mk(3)],
            outputs: vec![
                TxOut {
                    value: 5,
                    script_pubkey: vec![0x51; 10],
                },
                TxOut {
                    value: 6,
                    script_pubkey: vec![0x52; 10],
                },
            ],
            lock_time: 99,
        };
        Case {
            tx_hex: hex::encode(&tx.serialize()),
            input_index: 1,
            prevouts: vec![
                Prevout {
                    script_pubkey_hex: "5151".into(),
                    amount_sats: 9,
                },
                Prevout {
                    script_pubkey_hex: hex::encode(&spk),
                    amount_sats: 1234,
                },
                Prevout {
                    script_pubkey_hex: "52".into(),
                    amount_sats: 8,
                },
            ],
            flags: Flag::CONSENSUS.to_vec(),
            origin: Some("t".into()),
        }
    }

    /// "Interesting" = the script in `slot` still contains opcode 0xac (CHECKSIG).
    fn contains_checksig(slot: Slot) -> impl FnMut(&Case) -> bool {
        move |c: &Case| {
            Work::decode(c).and_then(|w| w.get(slot)).is_some_and(|s| {
                instructions(&s)
                    .0
                    .iter()
                    .any(|i| i.data.is_none() && i.opcode == 0xac)
            })
        }
    }

    #[test]
    fn bare_script_is_reduced_to_the_essential_opcode() {
        // <20 bytes> DUP HASH160 CHECKSIG NOP NOP 1
        let mut spk = vec![20];
        spk.extend([0xab; 20]);
        spk.extend([0x76, 0xa9, 0xac, 0x61, 0x61, 0x51]);
        let c = case(spk, vec![0x02, 0xaa, 0xbb, 0x51], vec![]);
        let (min, stats) = minimize(&c, &mut contains_checksig(Slot::ScriptPubKey), 10_000);
        let w = Work::decode(&min).unwrap();
        assert_eq!(w.prevouts[w.index].0, vec![0xac]);
        assert_eq!(w.tx.inputs.len(), 1, "unrelated inputs dropped");
        assert_eq!(w.index, 0);
        assert!(w.tx.outputs.is_empty());
        assert!(w.tx.inputs[0].script_sig.is_empty());
        assert!(w.flags.is_empty());
        assert_eq!(
            (w.tx.version, w.tx.lock_time, w.tx.inputs[0].sequence),
            (1, 0, 0xffff_ffff)
        );
        assert_eq!(w.prevouts[0].1, 0);
        assert!(stats.bytes_after < stats.bytes_before / 3, "{stats:?}");
        assert!(stats.accepted > 5 && stats.attempts >= stats.accepted);
        assert_eq!(min.origin.as_deref(), Some("t"));
    }

    #[test]
    fn committed_scripts_stay_committed() {
        let script = vec![0x61, 0x76, 0xac, 0x61, 0x51];
        // P2WSH
        let c = case(p2wsh(&script), vec![], vec![vec![1, 2, 3], script.clone()]);
        let (min, _) = minimize(&c, &mut contains_checksig(Slot::WitnessScript), 10_000);
        let w = Work::decode(&min).unwrap();
        assert_eq!(w.tx.inputs[0].witness, vec![vec![0xac]]);
        assert_eq!(w.prevouts[0].0, p2wsh(&[0xac]));

        // P2SH
        let mut sig = vec![0x51];
        push_data(&mut sig, &script);
        let c = case(p2sh(&script), sig, vec![]);
        let (min, _) = minimize(&c, &mut contains_checksig(Slot::Redeem), 10_000);
        let w = Work::decode(&min).unwrap();
        assert_eq!(w.tx.inputs[0].script_sig, vec![0x01, 0xac]);
        assert_eq!(w.prevouts[0].0, p2sh(&[0xac]));

        // P2SH-P2WSH
        let program = p2wsh(&script);
        let mut sig = Vec::new();
        push_data(&mut sig, &program);
        let c = case(p2sh(&program), sig, vec![script.clone()]);
        let (min, _) = minimize(&c, &mut contains_checksig(Slot::WitnessScript), 10_000);
        let w = Work::decode(&min).unwrap();
        assert_eq!(w.tx.inputs[0].witness, vec![vec![0xac]]);
        let inner = p2wsh(&[0xac]);
        assert_eq!(w.prevouts[0].0, p2sh(&inner));
        assert_eq!(last_push(&w.tx.inputs[0].script_sig).unwrap().0, inner);
    }

    #[test]
    fn wrappers_are_removed_when_the_divergence_does_not_need_them() {
        // Interesting whenever *any* executed script contains CHECKSIG.
        let mut anywhere = |c: &Case| {
            Work::decode(c).is_some_and(|w| {
                SLOTS
                    .iter()
                    .filter_map(|s| w.get(*s))
                    .any(|s| s.contains(&0xac))
            })
        };
        let script = vec![0x61, 0xac, 0x51];
        let c = case(p2wsh(&script), vec![], vec![vec![7], script.clone()]);
        let (min, _) = minimize(&c, &mut anywhere, 10_000);
        let w = Work::decode(&min).unwrap();
        assert_eq!(w.prevouts[0].0, vec![0xac], "unwrapped to a bare script");
        assert!(w.tx.inputs[0].witness.is_empty());

        let mut sig = vec![0x51];
        push_data(&mut sig, &script);
        let c = case(p2sh(&script), sig, vec![]);
        let (min, _) = minimize(&c, &mut anywhere, 10_000);
        assert_eq!(Work::decode(&min).unwrap().prevouts[0].0, vec![0xac]);
    }

    #[test]
    fn tapscript_leaf_is_recommitted() {
        let script = vec![0x61, 0xac, 0x61, 0x51];
        let internal = taproot::NUMS_H;
        let path = [[7u8; 32]];
        let leaf = taproot::tapleaf_hash(0xc0, &script);
        let (q, odd) =
            taproot::tweak_output_key(&internal, Some(&taproot::merkle_root(leaf, &path))).unwrap();
        let cb = taproot::control_block(0xc0, odd, &internal, &path);
        let c = case(taproot::p2tr_script(&q), vec![], vec![vec![9], script, cb]);
        // Like a real verifier, also insist on an intact control block.
        let mut leaf_has_checksig = contains_checksig(Slot::TapLeaf);
        let mut pred = |c: &Case| {
            leaf_has_checksig(c)
                && Work::decode(c).is_some_and(|w| {
                    w.tx.inputs[w.index]
                        .witness
                        .last()
                        .is_some_and(|cb| cb.len() == 65)
                })
        };
        let (min, _) = minimize(&c, &mut pred, 10_000);
        let w = Work::decode(&min).unwrap();
        let wit = &w.tx.inputs[w.index].witness;
        assert_eq!(wit.len(), 2, "{w:?}");
        assert_eq!(wit[0], vec![0xac]);
        // The output key matches the reduced leaf.
        let leaf = taproot::tapleaf_hash(0xc0, &[0xac]);
        let (q2, odd2) =
            taproot::tweak_output_key(&internal, Some(&taproot::merkle_root(leaf, &path))).unwrap();
        assert_eq!(w.prevouts[0].0, taproot::p2tr_script(&q2));
        assert_eq!(wit[1][0] & 1, u8::from(odd2));
    }

    #[test]
    fn non_reproducing_or_undecodable_cases_are_returned_unchanged() {
        let c = case(vec![0x51], vec![], vec![]);
        let (min, stats) = minimize(&c, &mut |_| false, 100);
        assert_eq!(min, c);
        assert_eq!((stats.attempts, stats.accepted), (1, 0));
        let mut bad = c.clone();
        bad.tx_hex = "zz".into();
        assert_eq!(minimize(&bad, &mut |_| true, 100).0, bad);
    }

    #[test]
    fn deterministic_and_budgeted() {
        let mut spk = vec![0x61; 40];
        spk.push(0xac);
        let c = case(spk, vec![0x51; 30], vec![]);
        let a = minimize(&c, &mut contains_checksig(Slot::ScriptPubKey), 10_000);
        let b = minimize(&c, &mut contains_checksig(Slot::ScriptPubKey), 10_000);
        assert_eq!(a, b);
        let (_, limited) = minimize(&c, &mut contains_checksig(Slot::ScriptPubKey), 5);
        assert!(limited.attempts <= 5);
    }

    #[test]
    fn flags_keep_the_witness_dependency_and_needed_flags() {
        let c = case(vec![0x51], vec![], vec![]);
        // Interesting only while WITNESS is set.
        let (min, _) = minimize(&c, &mut |c| c.flags.contains(&Flag::Witness), 10_000);
        assert_eq!(min.flags, vec![Flag::P2sh, Flag::Witness]);
    }

    #[test]
    fn unparsable_scripts_do_not_break_reduction() {
        let c = case(vec![0xac, 0x61, 0x05, 0x01], vec![], vec![]);
        let mut pred =
            |c: &Case| Work::decode(c).is_some_and(|w| w.prevouts[w.index].0.contains(&0xac));
        let (min, _) = minimize(&c, &mut pred, 10_000);
        let w = Work::decode(&min).unwrap();
        assert_eq!(w.prevouts[0].0, vec![0xac]);
    }
}
