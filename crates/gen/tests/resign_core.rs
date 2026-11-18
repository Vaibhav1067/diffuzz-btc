//! Re-signing proof: take spends that Core accepts, invalidate every signature by changing the
//! lock time, re-sign, and require Core to accept again.

#![allow(clippy::unwrap_used)] // test helpers

use diffuzz_gen::generators::sig::{SigGen, Template};
use diffuzz_gen::generators::taproot::TaprootGen;
use diffuzz_gen::resign::resign;
use diffuzz_gen::rng::Rng;
use diffuzz_gen::spend::Wrapper;
use diffuzz_types::tx::Tx;
use diffuzz_types::{Case, hex};

fn core_ok(case: &Case) -> bool {
    diffuzz_adapter_core::verify(&case.to_request(1)).is_ok()
}

fn bump_locktime(case: &Case) -> Case {
    let mut tx = Tx::deserialize(&hex::decode(&case.tx_hex).unwrap()).unwrap();
    tx.lock_time = tx.lock_time.wrapping_add(1);
    let mut out = case.clone();
    out.tx_hex = hex::encode(&tx.serialize());
    out
}

#[test]
fn resigned_pre_taproot_spends_verify_in_core() {
    let mut restored = 0;
    let mut broken = 0;
    for template in Template::ALL {
        // Embedded-signature and inverted templates are not plain "valid signature" spends, and
        // scripts with OP_CODESEPARATOR are deliberately not re-signed.
        if matches!(
            template,
            Template::SigInScript
                | Template::ChecksigNot
                | Template::CodeSepFirst
                | Template::CodeSepAfterKey
        ) {
            continue;
        }
        for wrapper in Wrapper::PRE_TAPROOT {
            for seed in 0..8 {
                let case = SigGen.valid_case(&mut Rng::new(seed), template, wrapper);
                assert!(
                    core_ok(&case),
                    "{} {} {seed}",
                    template.name(),
                    wrapper.name()
                );
                let mutated = bump_locktime(&case);
                if core_ok(&mutated) {
                    continue; // nothing signed (e.g. zero signatures required)
                }
                broken += 1;
                let fixed = resign(&mutated);
                if core_ok(&fixed) {
                    restored += 1;
                }
            }
        }
    }
    assert!(
        broken > 100,
        "only {broken} spends were broken by the mutation"
    );
    assert_eq!(
        restored, broken,
        "re-signing restored {restored} of {broken}"
    );
}

#[test]
fn resigned_tapscript_spends_verify_in_core() {
    let mut restored = 0;
    let mut broken = 0;
    for name in ["checksig", "checksigadd", "annex"] {
        for seed in 0..12 {
            let case = TaprootGen.valid_case(&mut Rng::new(seed), name);
            assert!(core_ok(&case), "{name} {seed}");
            let mutated = bump_locktime(&case);
            if core_ok(&mutated) {
                continue;
            }
            broken += 1;
            let fixed = resign(&mutated);
            if core_ok(&fixed) {
                restored += 1;
            }
        }
    }
    assert!(broken >= 20, "only {broken} tapscript spends broken");
    assert_eq!(
        restored, broken,
        "tapscript re-signing restored {restored} of {broken}"
    );
}
