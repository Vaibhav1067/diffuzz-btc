//! Ground truth for the generators: cases built to be valid must be accepted by Bitcoin Core,
//! and cases built to cross a limit must be rejected. This proves the generators reach the
//! success paths of signature checking (rather than only producing early failures) and that
//! the independent sighash implementations in this crate are correct.
//!
//! Core is called in-process through the adapter's library, so these tests need no subprocess.

#![allow(clippy::unwrap_used)]

use diffuzz_gen::generators::script::ScriptGen;
use diffuzz_gen::generators::sig::{Choices, KeyForm, SigGen, Template};
use diffuzz_gen::generators::taproot::{self, TaprootGen};
use diffuzz_gen::generators::wrapper::WrapperGen;
use diffuzz_gen::keys::DerQuirk;
use diffuzz_gen::rng::Rng;
use diffuzz_gen::spend::{Damage, Wrapper};
use diffuzz_types::{Case, Flag};

fn core(case: &Case) -> Result<(), String> {
    diffuzz_adapter_core::verify(&case.to_request(1))
        .map_err(|(class, raw)| format!("{class}: {raw}"))
}

fn all() -> Vec<Flag> {
    Flag::CONSENSUS.to_vec()
}

fn without(flag: Flag) -> Vec<Flag> {
    Flag::CONSENSUS
        .iter()
        .copied()
        .filter(|f| *f != flag)
        .collect()
}

#[test]
fn valid_signature_cases_verify_in_core() {
    let g = SigGen;
    let mut checked = 0;
    for template in Template::ALL {
        for wrapper in Wrapper::PRE_TAPROOT {
            for seed in 0..12 {
                let case = g.valid_case(&mut Rng::new(seed), template, wrapper);
                let result = core(&case);
                let expect_ok = match template {
                    // A signature embedded in the script it signs only works with legacy
                    // FindAndDelete; segwit v0 has no such step.
                    Template::SigInScript => matches!(wrapper, Wrapper::Bare | Wrapper::P2sh),
                    // `<pk> CHECKSIG NOT` is the inverse: a valid signature makes it false.
                    Template::ChecksigNot => false,
                    _ => true,
                };
                assert_eq!(
                    result.is_ok(),
                    expect_ok,
                    "{} under {} (seed {seed}): {result:?}",
                    template.name(),
                    wrapper.name()
                );
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 11 * 4 * 12);
}

#[test]
fn every_hash_type_byte_signs_validly_without_strictenc() {
    // Consensus accepts any hash-type byte and hashes with it; only policy restricts them.
    let g = SigGen;
    for hash_type in [
        0x00u8, 0x02, 0x03, 0x04, 0x1f, 0x21, 0x41, 0x7f, 0x80, 0x81, 0x82, 0x83, 0xff,
    ] {
        for (template, wrapper) in [
            (Template::P2pk, Wrapper::Bare),
            (Template::P2pkh, Wrapper::P2sh),
            (Template::P2pk, Wrapper::P2wsh),
            (Template::Multisig, Wrapper::P2shP2wsh),
            (Template::P2wpkh, Wrapper::Bare),
        ] {
            for seed in 0..6 {
                let choices = Choices {
                    hash_type,
                    ..Choices::valid()
                };
                let case = g.build(&mut Rng::new(seed), template, wrapper, &choices, all());
                assert!(
                    core(&case).is_ok(),
                    "hash type {hash_type:#04x}, {} under {} (seed {seed}): {:?}",
                    template.name(),
                    wrapper.name(),
                    core(&case)
                );
            }
        }
    }
}

#[test]
fn der_quirks_are_valid_only_without_dersig() {
    let g = SigGen;
    for quirk in DerQuirk::ALL {
        for seed in 0..10 {
            let choices = Choices {
                quirk,
                ..Choices::valid()
            };
            let with = g.build(
                &mut Rng::new(seed),
                Template::P2pk,
                Wrapper::Bare,
                &choices,
                all(),
            );
            let wo = g.build(
                &mut Rng::new(seed),
                Template::P2pk,
                Wrapper::Bare,
                &choices,
                without(Flag::Dersig),
            );
            assert!(
                core(&wo).is_ok(),
                "{quirk:?} must be valid without DERSIG (seed {seed})"
            );
            // NoPadR only differs from strict DER when R's top bit is set, so it may be valid.
            if quirk == DerQuirk::Strict {
                assert!(core(&with).is_ok());
            } else if quirk != DerQuirk::NoPadR {
                assert!(
                    core(&with).is_err(),
                    "{quirk:?} must fail with DERSIG (seed {seed})"
                );
            }
        }
    }
}

#[test]
fn high_s_and_odd_keys_are_consensus_valid() {
    let g = SigGen;
    for seed in 0..10 {
        let high = Choices {
            high_s: true,
            ..Choices::valid()
        };
        let c = g.build(
            &mut Rng::new(seed),
            Template::P2pk,
            Wrapper::P2sh,
            &high,
            all(),
        );
        assert!(
            core(&c).is_ok(),
            "high-S is policy, not consensus (seed {seed})"
        );

        for form in [KeyForm::Uncompressed, KeyForm::Hybrid] {
            let ch = Choices {
                key_form: form,
                ..Choices::valid()
            };
            for wrapper in Wrapper::PRE_TAPROOT {
                let c = g.build(&mut Rng::new(seed), Template::P2pk, wrapper, &ch, all());
                assert!(
                    core(&c).is_ok(),
                    "{form:?} under {} (seed {seed})",
                    wrapper.name()
                );
            }
        }
        for form in [
            KeyForm::BadPrefix,
            KeyForm::Short,
            KeyForm::OffCurve,
            KeyForm::Empty,
        ] {
            let ch = Choices {
                key_form: form,
                ..Choices::valid()
            };
            let c = g.build(
                &mut Rng::new(seed),
                Template::P2pk,
                Wrapper::Bare,
                &ch,
                all(),
            );
            assert!(core(&c).is_err(), "{form:?} must not verify (seed {seed})");
        }
    }
}

#[test]
fn damaged_signatures_fail_and_checksig_not_inverts() {
    let g = SigGen;
    for seed in 0..10 {
        for damage in [
            Damage::FlipBit,
            Damage::WrongKey,
            Damage::WrongMessage,
            Damage::SwapHashType,
        ] {
            let ch = Choices {
                damage,
                ..Choices::valid()
            };
            for template in [
                Template::P2pk,
                Template::P2pkh,
                Template::Multisig,
                Template::P2wpkh,
            ] {
                let c = g.build(&mut Rng::new(seed), template, Wrapper::P2wsh, &ch, all());
                assert!(
                    core(&c).is_err(),
                    "{damage:?} {} (seed {seed})",
                    template.name()
                );
            }
        }
        // `<pk> CHECKSIG NOT` succeeds with an empty signature (NULLFAIL is policy).
        let ch = Choices {
            damage: Damage::Empty,
            ..Choices::valid()
        };
        let c = g.build(
            &mut Rng::new(seed),
            Template::ChecksigNot,
            Wrapper::Bare,
            &ch,
            all(),
        );
        assert!(
            core(&c).is_ok(),
            "empty sig + NOT must succeed (seed {seed})"
        );
        // ...and fails with a valid one.
        let c = g.valid_case(&mut Rng::new(seed), Template::ChecksigNot, Wrapper::Bare);
        assert!(core(&c).is_err());
    }
}

#[test]
fn multisig_rules() {
    let g = SigGen;
    for seed in 0..8 {
        let build = |ch: &Choices, flags: Vec<Flag>| {
            g.build(
                &mut Rng::new(seed),
                Template::Multisig,
                Wrapper::P2sh,
                ch,
                flags,
            )
        };
        let v = Choices::valid();
        // Non-empty dummy: NULLDUMMY decides.
        let dummy = Choices {
            dummy: vec![1],
            ..v.clone()
        };
        assert!(core(&build(&dummy, all())).is_err());
        assert!(core(&build(&dummy, without(Flag::Nulldummy))).is_ok());
        // Signatures must follow key order.
        assert!(
            core(&build(
                &Choices {
                    reverse_sigs: true,
                    ..v.clone()
                },
                all()
            ))
            .is_err()
        );
        // 0-of-n needs no signatures; 20 keys is the maximum.
        let zero = Choices {
            m: 0,
            sigs_supplied: 0,
            ..v.clone()
        };
        assert!(core(&build(&zero, all())).is_ok());
        // Twenty keys do not fit a 520-byte P2SH redeem script, so use P2WSH for the count.
        let wsh = |ch: &Choices| {
            g.build(
                &mut Rng::new(seed),
                Template::Multisig,
                Wrapper::P2wsh,
                ch,
                all(),
            )
        };
        let twenty = Choices { n: 20, ..v.clone() };
        assert!(core(&wsh(&twenty)).is_ok(), "{:?}", core(&wsh(&twenty)));
        assert!(
            core(&build(&twenty, all())).is_err(),
            "680-byte redeem script exceeds 520"
        );
        let twenty_one = Choices { n: 21, ..v.clone() };
        assert!(core(&wsh(&twenty_one)).is_err());
        let too_many = Choices {
            m: 4,
            sigs_supplied: 3,
            ..v.clone()
        };
        assert!(core(&build(&too_many, all())).is_err());
    }
}

#[test]
fn valid_taproot_cases_verify_in_core() {
    let g = TaprootGen;
    for name in taproot::TEMPLATES {
        for seed in 0..25 {
            let case = g.valid_case(&mut Rng::new(seed), name);
            let result = core(&case);
            assert!(result.is_ok(), "taproot/{name} (seed {seed}): {result:?}");
        }
    }
}

#[test]
fn taproot_is_ignored_without_the_flag() {
    // Without TAPROOT a v1 program is an unknown witness version: anyone can spend.
    let g = TaprootGen;
    for name in ["keypath", "checksig", "control-block"] {
        for seed in 0..20 {
            let case = g.build(&mut Rng::new(seed), name, false, without(Flag::Taproot));
            assert!(
                core(&case).is_ok(),
                "taproot/{name} without TAPROOT (seed {seed})"
            );
        }
    }
}

#[test]
fn interpreter_limits_sit_exactly_where_expected() {
    let g = ScriptGen;
    let run = |name: &str, wrapper: Wrapper| core(&g.limit(&mut Rng::new(3), name, wrapper, all()));
    let pairs = [
        ("ops-201", "ops-202"),
        ("size-10000", "size-10001"),
        ("stack-1000", "stack-1001"),
        ("push-520", "push-521"),
        ("num-4byte-ok", "num-5byte-input"),
    ];
    for (ok, bad) in pairs {
        assert!(
            run(ok, Wrapper::Bare).is_ok(),
            "{ok} must pass: {:?}",
            run(ok, Wrapper::Bare)
        );
        assert!(run(bad, Wrapper::Bare).is_err(), "{bad} must fail");
    }
    assert!(run("num-overflow-chain", Wrapper::Bare).is_err());
    // Tapscript has no opcode-count limit.
    assert!(run("ops-202", Wrapper::Tapscript).is_ok());
    assert!(run("ops-202", Wrapper::P2wsh).is_err());
    assert!(run("ops-201", Wrapper::P2wsh).is_ok());
    // The 10,000 byte script limit also binds witness scripts, but not tapscripts.
    assert!(run("size-10000", Wrapper::P2wsh).is_ok());
    assert!(run("size-10001", Wrapper::P2wsh).is_err());
    assert!(run("size-10001", Wrapper::Tapscript).is_ok());
}

#[test]
fn wrapper_templates_behave() {
    let g = WrapperGen;
    let run = |name: &str, seed: u64| core(&g.build(&mut Rng::new(seed), name, all()));
    for seed in 0..10 {
        for ok in ["p2wsh-ok", "p2sh-ok"] {
            assert!(
                run(ok, seed).is_ok(),
                "{ok} seed {seed}: {:?}",
                run(ok, seed)
            );
        }
        for bad in [
            "p2wsh-mismatch",
            "p2wsh-empty-witness",
            "p2wpkh-bad-witness-count",
            "witness-malleated",
            "p2sh-witness-malleated",
            "witness-unexpected",
            "p2sh-mismatch",
            "p2sh-not-push-only",
        ] {
            assert!(run(bad, seed).is_err(), "{bad} seed {seed} must fail");
        }
    }
}

#[test]
fn mixed_stream_reaches_both_verdicts_in_every_category() {
    use diffuzz_gen::generators::{Mix, Weights, category};
    use std::collections::BTreeMap;

    let mix = Mix::new(Weights::default(), Vec::new());
    let mut seen: BTreeMap<String, (u32, u32)> = BTreeMap::new();
    for n in 0..4000 {
        let case = mix.case(2026, n);
        let entry = seen.entry(category(&case).to_string()).or_insert((0, 0));
        match diffuzz_adapter_core::verify(&case.to_request(n)) {
            Ok(()) => entry.0 += 1,
            Err((class, _)) if class.is_abstention() => panic!("generated case made Core abstain"),
            Err(_) => entry.1 += 1,
        }
    }
    for cat in [
        "gen/script",
        "gen/sig",
        "gen/wrapper",
        "gen/taproot",
        "gen/mutate",
    ] {
        let (ok, fail) = seen.get(cat).copied().unwrap_or((0, 0));
        let total = ok + fail;
        assert!(total > 200, "{cat}: only {total} cases");
        // Neither verdict may dominate completely: we want both success and failure paths.
        assert!(ok * 100 >= total * 8, "{cat}: only {ok}/{total} accepted");
        assert!(
            fail * 100 >= total * 8,
            "{cat}: only {fail}/{total} rejected"
        );
    }
}
