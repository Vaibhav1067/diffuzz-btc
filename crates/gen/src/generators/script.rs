//! Script grammar generator: random opcode sequences that keep a model of the stack so scripts
//! get past their first few opcodes, plus targeted cases for every interpreter limit.

use diffuzz_types::script::{op, push_data, push_int};
use diffuzz_types::{Case, Flag};

use super::Generator;
use crate::rng::Rng;
use crate::spend::{Item, Skeleton, TapParams, Wrapper, random_flags, skeleton, to_case, wrap};

/// What the model believes a stack element is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A script number that fits in 4 bytes (usable by arithmetic).
    Num,
    /// Arbitrary bytes (hash output, large push).
    Bytes,
}

/// Numbers pushed by the grammar, weighted toward small values and encoding boundaries.
const NUMBERS: [i64; 20] = [
    0,
    1,
    1,
    2,
    3,
    -1,
    -2,
    16,
    17,
    127,
    128,
    -128,
    255,
    256,
    32767,
    32768,
    0x7fff_ffff,
    -0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
];

const UNARY: [u8; 6] = [
    op::ADD1,
    op::SUB1,
    op::NEGATE,
    op::ABS,
    op::NOT,
    op::NOTEQUAL0,
];
const BINARY: [u8; 12] = [
    op::ADD,
    op::SUB,
    op::BOOLAND,
    op::BOOLOR,
    op::NUMEQUAL,
    op::NUMNOTEQUAL,
    op::LESSTHAN,
    op::GREATERTHAN,
    op::LESSTHANOREQUAL,
    op::GREATERTHANOREQUAL,
    op::MIN,
    op::MAX,
];
const HASHES: [u8; 5] = [
    op::RIPEMD160,
    op::SHA1,
    op::SHA256,
    op::HASH160,
    op::HASH256,
];
const NOPS: [u8; 9] = [
    op::NOP,
    op::NOP1,
    op::NOP4,
    0xb4,
    0xb5,
    0xb6,
    0xb7,
    0xb8,
    op::NOP10,
];
/// Disabled opcodes: fail even inside an unexecuted branch (pre-tapscript).
pub const DISABLED: [u8; 15] = [
    0x7e, 0x7f, 0x80, 0x81, 0x83, 0x84, 0x85, 0x86, 0x8d, 0x8e, 0x95, 0x96, 0x97, 0x98, 0x99,
];
/// Opcodes that are invalid when executed (and for VERIF/VERNOTIF, even when not).
const BAD: [u8; 9] = [
    op::RESERVED,
    op::VER,
    op::VERIF,
    op::VERNOTIF,
    0x89,
    0x8a,
    0xba,
    0xbb,
    0xff,
];

struct Builder<'r> {
    rng: &'r mut Rng,
    script: Vec<u8>,
    stack: Vec<Kind>,
    alt: usize,
    tapscript: bool,
    /// Opcodes used in the script, for the origin tag.
    spicy: bool,
}

impl Builder<'_> {
    fn emit(&mut self, opcode: u8) {
        self.script.push(opcode);
    }

    fn push_num(&mut self) {
        if self.rng.chance(6) {
            // Unusual encodings: negative zero, non-minimal, one-byte zero, five bytes.
            let raw: &[u8] = match self.rng.below(4) {
                0 => &[0x80],
                1 => &[0x01, 0x00],
                2 => &[0x00],
                _ => &[0x01, 0x00, 0x00, 0x00, 0x00],
            };
            push_data(&mut self.script, raw);
            self.stack.push(if raw.len() > 4 {
                Kind::Bytes
            } else {
                Kind::Num
            });
            return;
        }
        let n = *self.rng.pick(&NUMBERS);
        push_int(&mut self.script, n);
        self.stack.push(if n.unsigned_abs() > 0x7fff_ffff {
            Kind::Bytes
        } else {
            Kind::Num
        });
    }

    fn push_small(&mut self, n: i64) {
        push_int(&mut self.script, n);
        self.stack.push(Kind::Num);
    }

    fn push_bytes(&mut self) {
        let len = *self
            .rng
            .pick(&[1usize, 2, 5, 20, 32, 33, 75, 76, 80, 255, 256, 520]);
        let data = self.rng.bytes(len);
        if self.rng.chance(10) && len <= 255 {
            // Non-minimal push opcode: consensus-valid.
            self.script.push(op::PUSHDATA1);
            self.script.push(len as u8);
            self.script.extend_from_slice(&data);
        } else {
            push_data(&mut self.script, &data);
        }
        self.stack.push(Kind::Bytes);
    }

    /// Make sure at least `n` elements are on the model stack.
    fn need(&mut self, n: usize) {
        while self.stack.len() < n {
            self.push_num();
        }
    }

    /// Make sure the top `n` elements are small numbers (usually).
    fn need_nums(&mut self, n: usize) {
        self.need(n);
        let len = self.stack.len();
        let ok = self.stack[len - n..].iter().all(|k| *k == Kind::Num);
        if !ok && self.rng.chance(90) {
            for _ in 0..n {
                let v = *self.rng.pick(&[0i64, 1, 2, 3, 5, 100, -1]);
                self.push_small(v);
            }
        }
    }

    fn pop(&mut self, n: usize) {
        let keep = self.stack.len().saturating_sub(n);
        self.stack.truncate(keep);
    }

    fn stack_op(&mut self) {
        // (opcode, required depth, elements removed, elements added)
        const OPS: [(u8, usize, usize, usize); 15] = [
            (op::DUP, 1, 0, 1),
            (op::DROP, 1, 1, 0),
            (op::DROP2, 2, 2, 0),
            (op::DUP2, 2, 0, 2),
            (op::DUP3, 3, 0, 3),
            (op::OVER2, 4, 0, 2),
            (op::ROT2, 6, 0, 0),
            (op::SWAP2, 4, 0, 0),
            (op::IFDUP, 1, 0, 0),
            (op::NIP, 2, 1, 0),
            (op::OVER, 2, 0, 1),
            (op::ROT, 3, 0, 0),
            (op::SWAP, 2, 0, 0),
            (op::TUCK, 2, 0, 1),
            (op::DEPTH, 0, 0, 1),
        ];
        let (opcode, depth, removed, added) = *self.rng.pick(&OPS);
        // Mostly satisfy the requirement; sometimes underflow on purpose.
        if self.rng.chance(92) {
            self.need(depth);
        }
        self.emit(opcode);
        self.pop(removed);
        for _ in 0..added {
            // Duplicated elements have unknown kind in general; DEPTH pushes a number.
            self.stack.push(if opcode == op::DEPTH {
                Kind::Num
            } else {
                Kind::Bytes
            });
        }
    }

    fn pick_roll(&mut self) {
        self.need(2);
        let max = self.stack.len().saturating_sub(1);
        let n = if self.rng.chance(90) {
            self.rng.below(max + 1)
        } else {
            max + 1 + self.rng.below(3)
        };
        self.push_small(n as i64);
        let opcode = if self.rng.chance(50) {
            op::PICK
        } else {
            op::ROLL
        };
        self.emit(opcode);
        self.pop(1);
        if opcode == op::PICK {
            self.stack.push(Kind::Bytes);
        }
    }

    fn rebalance(&mut self, depth: usize, alt: usize) {
        while self.stack.len() > depth {
            self.emit(op::DROP);
            self.pop(1);
        }
        while self.stack.len() < depth {
            self.push_small(1);
        }
        while self.alt > alt {
            self.emit(op::FROMALTSTACK);
            self.emit(op::DROP);
            self.alt -= 1;
        }
        while self.alt < alt {
            self.push_small(1);
            self.emit(op::TOALTSTACK);
            self.pop(1);
            self.alt += 1;
        }
    }

    fn if_block(&mut self, nest: u32) {
        // Condition: mostly a minimal true/false (tapscript and MINIMALIF demand it).
        match self.rng.below(12) {
            0..=4 => self.push_small(1),
            5..=9 => self.push_small(0),
            10 => self.push_small(2),
            _ => {
                push_data(&mut self.script, &[0x01, 0x00]);
                self.stack.push(Kind::Bytes);
            }
        }
        let opener = if self.rng.chance(75) {
            op::IF
        } else {
            op::NOTIF
        };
        self.emit(opener);
        self.pop(1);
        let base = self.stack.clone();
        let alt = self.alt;

        let steps = self.rng.range(0, 4);
        self.block(nest + 1, steps);
        self.rebalance(base.len(), alt);
        let mut elses = self.rng.weighted(&[45, 50, 5]);
        while elses > 0 {
            self.emit(op::ELSE);
            self.stack = base.clone();
            let steps = self.rng.range(0, 3);
            self.block(nest + 1, steps);
            self.rebalance(base.len(), alt);
            elses -= 1;
        }
        if self.rng.chance(96) {
            self.emit(op::ENDIF);
        } else {
            self.spicy = true;
        }
    }

    fn step(&mut self, nest: u32) {
        let choice = self.rng.weighted(&[
            22,                           // 0 push number
            6,                            // 1 push bytes
            8,                            // 2 unary numeric
            10,                           // 3 binary numeric
            16,                           // 4 stack manipulation
            5,                            // 5 EQUAL
            4,                            // 6 verify family
            5,                            // 7 hash
            3,                            // 8 NOPs
            if nest < 4 { 7 } else { 0 }, // 9 IF block
            3,                            // 10 alt stack
            2,                            // 11 WITHIN
            2,                            // 12 PICK / ROLL
            1,                            // 13 SIZE
            2,                            // 14 locktime opcodes
            3,                            // 15 disabled / invalid / odd opcodes
        ]);
        match choice {
            0 => self.push_num(),
            1 => self.push_bytes(),
            2 => {
                self.need_nums(1);
                let o = *self.rng.pick(&UNARY);
                self.emit(o);
            }
            3 => {
                self.need_nums(2);
                let o = *self.rng.pick(&BINARY);
                self.emit(o);
                self.pop(2);
                self.stack.push(Kind::Num);
            }
            4 => self.stack_op(),
            5 => {
                self.need(2);
                self.emit(op::EQUAL);
                self.pop(2);
                self.stack.push(Kind::Num);
            }
            6 => match self.rng.below(3) {
                0 => {
                    self.push_small(1);
                    self.emit(op::VERIFY);
                    self.pop(1);
                }
                1 => {
                    self.need(1);
                    if self.rng.chance(85) {
                        self.emit(op::DUP);
                        self.stack.push(Kind::Bytes);
                    } else {
                        self.need(2);
                    }
                    self.emit(op::EQUALVERIFY);
                    self.pop(2);
                }
                _ => {
                    let a = *self.rng.pick(&[0i64, 1, 7, 300]);
                    let b = if self.rng.chance(85) { a } else { a + 1 };
                    self.push_small(a);
                    self.push_small(b);
                    self.emit(op::NUMEQUALVERIFY);
                    self.pop(2);
                }
            },
            7 => {
                self.need(1);
                let o = *self.rng.pick(&HASHES);
                self.emit(o);
                self.pop(1);
                self.stack.push(Kind::Bytes);
            }
            8 => {
                let o = *self.rng.pick(&NOPS);
                self.emit(o);
            }
            9 => self.if_block(nest),
            10 => {
                if self.alt > 0 && self.rng.chance(60) {
                    self.emit(op::FROMALTSTACK);
                    self.alt -= 1;
                    self.stack.push(Kind::Bytes);
                } else if self.rng.chance(90) {
                    self.need(1);
                    self.emit(op::TOALTSTACK);
                    self.pop(1);
                    self.alt += 1;
                } else {
                    // FROMALTSTACK on an empty alt stack.
                    self.emit(op::FROMALTSTACK);
                    self.spicy = true;
                }
            }
            11 => {
                self.need_nums(3);
                self.emit(op::WITHIN);
                self.pop(3);
                self.stack.push(Kind::Num);
            }
            12 => self.pick_roll(),
            13 => {
                self.need(1);
                self.emit(op::SIZE);
                self.stack.push(Kind::Num);
            }
            14 => {
                let n = *self
                    .rng
                    .pick(&[0i64, 1, 2, 499_999_999, 500_000_000, -1, 0x40_0000]);
                push_int(&mut self.script, n);
                let lock_op = if self.rng.chance(50) {
                    op::CLTV
                } else {
                    op::CSV
                };
                self.emit(lock_op);
                self.emit(op::DROP);
            }
            _ => {
                self.spicy = true;
                let o = match self.rng.below(5) {
                    0 | 1 => *self.rng.pick(&DISABLED),
                    2 => *self.rng.pick(&BAD),
                    3 => op::RETURN,
                    _ => op::CODESEPARATOR,
                };
                // In tapscript most of these are OP_SUCCESS and would end every case trivially.
                if self.tapscript && self.rng.chance(80) {
                    self.emit(op::NOP);
                } else {
                    self.emit(o);
                }
            }
        }
    }

    fn block(&mut self, nest: u32, steps: usize) {
        for _ in 0..steps {
            self.step(nest);
        }
    }

    /// Leave exactly one true element (what witness scripts need to succeed).
    fn finish_clean(&mut self) {
        while self.stack.len() >= 2 {
            self.emit(op::DROP2);
            self.pop(2);
        }
        if self.stack.len() == 1 {
            self.emit(op::DROP);
            self.pop(1);
        }
        self.push_small(1);
    }
}

/// A random script and the stack items its spender supplies.
fn random_script(rng: &mut Rng, tapscript: bool) -> (Vec<u8>, Vec<Item>, bool) {
    let mut items = Vec::new();
    let mut stack = Vec::new();
    for _ in 0..rng.weighted(&[40, 30, 20, 10]) {
        if rng.chance(70) {
            let n = *rng.pick(&[0i64, 1, 2, 5, -1, 1000]);
            items.push(Item::Data(diffuzz_types::script::scriptnum_encode(n)));
            stack.push(Kind::Num);
        } else {
            let len = *rng.pick(&[1usize, 20, 32, 80]);
            items.push(Item::Data(rng.bytes(len)));
            stack.push(Kind::Bytes);
        }
    }
    let steps = rng.range(1, 24);
    let mut b = Builder {
        rng,
        script: Vec::new(),
        stack,
        alt: 0,
        tapscript,
        spicy: false,
    };
    b.block(0, steps);
    match b.rng.below(10) {
        0..=6 => b.finish_clean(),
        7 => b.push_small(1),
        8 => b.push_small(0),
        _ => {}
    }
    (b.script, items, b.spicy)
}

fn filler(target: usize) -> Vec<u8> {
    // `<push> DROP` units summing to exactly `target` bytes, then callers append the tail.
    let mut s = Vec::with_capacity(target);
    while s.len() < target {
        let left = target - s.len();
        // A unit is 3 + n + 1 bytes for n in 256..=520 (PUSHDATA2), or 1 + n + 1 for n <= 75.
        if left >= 524 + 2 || left == 524 {
            s.push(op::PUSHDATA2);
            s.extend_from_slice(&520u16.to_le_bytes());
            s.extend(std::iter::repeat_n(0x42, 520));
            s.push(op::DROP);
        } else if left >= 260 {
            let n = (left - 4).min(520).min(left - 4 - 2).max(256);
            s.push(op::PUSHDATA2);
            s.extend_from_slice(&(n as u16).to_le_bytes());
            s.extend(std::iter::repeat_n(0x42, n));
            s.push(op::DROP);
        } else if left >= 2 {
            let n = (left - 2).min(75);
            s.push(n as u8);
            s.extend(std::iter::repeat_n(0x42, n));
            s.push(op::DROP);
        } else {
            s.push(op::NOP);
        }
    }
    s
}

/// The named limit cases. Each returns `(script, items)`; some also adjust the transaction.
const LIMITS: [&str; 16] = [
    "ops-201",
    "ops-202",
    "size-10000",
    "size-10001",
    "stack-1000",
    "stack-1001",
    "push-520",
    "push-521",
    "num-4byte-ok",
    "num-5byte-input",
    "num-overflow-chain",
    "negative-zero",
    "nonminimal-number",
    "if-deep",
    "unexecuted",
    "locktime",
];

fn limit_case(rng: &mut Rng, name: &str, sk: &mut Skeleton) -> (Vec<u8>, Vec<Item>) {
    let mut s = Vec::new();
    match name {
        "ops-201" | "ops-202" => {
            let n = if name == "ops-201" { 201 } else { 202 };
            s.extend(std::iter::repeat_n(op::NOP, n));
            s.push(op::OP_1);
        }
        "size-10000" | "size-10001" => {
            let total = if name == "size-10000" { 10_000 } else { 10_001 };
            s = filler(total - 1);
            s.push(op::OP_1);
        }
        "stack-1000" | "stack-1001" => {
            let n = if name == "stack-1000" { 1000 } else { 1001 };
            s.extend(std::iter::repeat_n(op::OP_1, n));
        }
        "push-520" | "push-521" => {
            let n = if name == "push-520" { 520 } else { 521 };
            push_data(&mut s, &vec![0x33; n]);
            s.push(op::DROP);
            s.push(op::OP_1);
        }
        "num-4byte-ok" => {
            // 2^31-1 + 1 is fine as a *result*; it only fails if used as an operand again.
            push_int(&mut s, 0x7fff_ffff);
            s.extend_from_slice(&[op::ADD1, op::DROP, op::OP_1]);
        }
        "num-5byte-input" => {
            push_int(&mut s, 0x8000_0000);
            s.extend_from_slice(&[op::ADD1, op::DROP, op::OP_1]);
        }
        "num-overflow-chain" => {
            push_int(&mut s, 0x7fff_ffff);
            s.extend_from_slice(&[op::ADD1, op::ADD1, op::DROP, op::OP_1]);
        }
        "negative-zero" => {
            // 0x80 is negative zero: false as a boolean, zero as a number.
            push_data(&mut s, &[0x80]);
            s.push(*rng.pick(&[op::NOT, op::NOTEQUAL0, op::ADD1, op::VERIFY, op::IF]));
            if s.last() == Some(&op::IF) {
                s.extend_from_slice(&[op::OP_0, op::ELSE, op::OP_1, op::ENDIF]);
            }
        }
        "nonminimal-number" => {
            push_data(
                &mut s,
                rng.pick(&[vec![0x01, 0x00], vec![0x00], vec![0x05, 0x00, 0x00]]),
            );
            s.push(op::ADD1);
        }
        "if-deep" => {
            let depth = *rng.pick(&[1usize, 50, 100, 101, 150]);
            for _ in 0..depth {
                s.push(op::OP_1);
                s.push(op::IF);
            }
            s.extend(std::iter::repeat_n(op::ENDIF, depth));
            s.push(op::OP_1);
        }
        "unexecuted" => {
            // What still fails inside a branch that is never executed?
            s.push(op::OP_0);
            s.push(op::IF);
            match rng.below(6) {
                0 => s.push(*rng.pick(&DISABLED)),
                1 => s.push(*rng.pick(&[op::VERIF, op::VERNOTIF])),
                2 => s.push(*rng.pick(&[op::RESERVED, op::VER, 0x89, 0x8a, op::RETURN])),
                3 => s.push(*rng.pick(&[0xba, 0xbb, 0xd0, 0xfe, 0xff])),
                4 => push_data(&mut s, &vec![0x44; *rng.pick(&[520usize, 521])]),
                _ => s.extend_from_slice(&[op::OP_1, op::CHECKSIG]),
            }
            s.push(op::ENDIF);
            s.push(op::OP_1);
        }
        _ => {
            // Locktime: compare a script operand against the transaction's field.
            let cltv = rng.chance(50);
            let field = *rng.pick(&[
                0u32,
                1,
                100,
                499_999_999,
                500_000_000,
                500_000_001,
                0x40_0005,
            ]);
            let delta = *rng.pick(&[-1i64, 0, 0, 1]);
            let operand = match rng.below(8) {
                0 => -1,
                1 => 0x8000_0000 | i64::from(field), // CSV disable flag / CLTV 5-byte value
                2 => 500_000_000,
                3 => 0x40_0000 | i64::from(field & 0xffff),
                _ => i64::from(field) + delta,
            };
            let idx = sk.index;
            if cltv {
                sk.tx.lock_time = field;
                sk.tx.inputs[idx].sequence = *rng.pick(&[0u32, 0xffff_fffe, 0xffff_ffff]);
            } else {
                sk.tx.inputs[idx].sequence = field | if rng.chance(15) { 0x8000_0000 } else { 0 };
                sk.tx.version = *rng.pick(&[1u32, 2, 2, 2, 3, 0xffff_ffff]);
            }
            push_int(&mut s, operand);
            s.push(if cltv { op::CLTV } else { op::CSV });
            s.extend_from_slice(&[op::DROP, op::OP_1]);
        }
    }
    (s, Vec::new())
}

/// Random and limit-probing scripts, wrapped in every output type.
#[derive(Debug, Clone, Default)]
pub struct ScriptGen;

impl ScriptGen {
    /// Build the named limit case (see [`ScriptGen::limit_names`]) under `wrapper`.
    pub fn limit(&self, rng: &mut Rng, name: &str, wrapper: Wrapper, flags: Vec<Flag>) -> Case {
        let mut sk = skeleton(rng);
        let (script, items) = limit_case(rng, name, &mut sk);
        wrap(&mut sk, wrapper, &script, &items, &TapParams::default());
        to_case(
            &sk,
            flags,
            format!("gen/script/{}/limit:{name}", wrapper.name()),
        )
    }

    /// Names of the limit cases.
    pub fn limit_names() -> &'static [&'static str] {
        &LIMITS
    }
}

impl Generator for ScriptGen {
    fn name(&self) -> &'static str {
        "script"
    }

    fn generate(&self, rng: &mut Rng) -> Case {
        let wrapper = *rng.pick(&Wrapper::ALL);
        let flags = random_flags(rng);
        if rng.chance(22) {
            let name = *rng.pick(&LIMITS);
            return self.limit(rng, name, wrapper, flags);
        }
        let mut sk = skeleton(rng);
        let (script, items, spicy) = random_script(rng, wrapper == Wrapper::Tapscript);
        wrap(&mut sk, wrapper, &script, &items, &TapParams::default());
        let tag = if spicy { "grammar-odd" } else { "grammar" };
        to_case(&sk, flags, format!("gen/script/{}/{tag}", wrapper.name()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffuzz_types::script::instructions;

    #[test]
    fn filler_hits_exact_sizes() {
        for target in [
            0usize, 1, 2, 3, 77, 78, 259, 260, 261, 523, 524, 525, 526, 9_999, 10_000,
        ] {
            let f = filler(target);
            assert_eq!(f.len(), target, "target {target}");
            assert!(instructions(&f).1, "filler for {target} must parse");
        }
    }

    #[test]
    fn deterministic() {
        let g = ScriptGen;
        let a: Vec<Case> = (0..20).map(|i| g.generate(&mut Rng::new(i))).collect();
        let b: Vec<Case> = (0..20).map(|i| g.generate(&mut Rng::new(i))).collect();
        assert_eq!(a, b);
    }

    #[test]
    fn random_scripts_parse_and_stay_small() {
        let mut odd = 0;
        for seed in 0..500 {
            let mut rng = Rng::new(seed);
            let (script, items, spicy) = random_script(&mut rng, seed % 2 == 0);
            assert!(
                instructions(&script).1,
                "seed {seed}: generated script must parse"
            );
            assert!(script.len() < 10_000);
            assert!(items.len() <= 3);
            odd += usize::from(spicy);
        }
        assert!(odd > 10 && odd < 400, "odd-opcode rate out of range: {odd}");
    }

    #[test]
    fn limit_cases_have_the_advertised_shape() {
        let g = ScriptGen;
        let script_of = |name: &str| {
            let mut sk = skeleton(&mut Rng::new(1));
            limit_case(&mut Rng::new(1), name, &mut sk).0
        };
        assert_eq!(script_of("ops-201").len(), 202);
        assert_eq!(script_of("ops-202").len(), 203);
        assert_eq!(script_of("size-10000").len(), 10_000);
        assert_eq!(script_of("size-10001").len(), 10_001);
        assert_eq!(script_of("stack-1001").len(), 1001);
        assert_eq!(script_of("push-521").len(), 3 + 521 + 2);
        for name in ScriptGen::limit_names() {
            let case = g.limit(&mut Rng::new(5), name, Wrapper::Bare, vec![]);
            assert!(case.origin.as_deref().unwrap().ends_with(name));
        }
    }
}
