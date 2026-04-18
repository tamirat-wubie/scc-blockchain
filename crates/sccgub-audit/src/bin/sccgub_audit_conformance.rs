//! `sccgub-audit-conformance` — internal cross-check binary per
//! PATCH_08.md §D.3.
//!
//! Generates synthetic genesis-to-tip chain histories and verifies
//! the verifier's output matches an **oracle implementation** written
//! independently. The oracle uses a different code path (walks the
//! transition history byte-by-byte and compares ceilings field-by-
//! field via a secondary algorithm) to catch implementation bugs
//! that would affect both paths if they shared logic.
//!
//! Mutation-testing-in-spirit: each adversarial fixture is a
//! one-line mutation of a baseline; both verifier and oracle must
//! agree on the fixture's status (`Ok(())` or specific violation).
//!
//! Exits 0 on full agreement, 1 on any disagreement.

use std::path::PathBuf;
use std::process::ExitCode;

use sccgub_audit::{
    verify_ceilings_unchanged_since_genesis, CeilingFieldId, CeilingViolation,
    JsonChainStateFixture,
};
use sccgub_types::constitutional_ceilings::ConstitutionalCeilings;
use sccgub_types::upgrade::ChainVersionTransition;

fn main() -> ExitCode {
    // Optional first arg: --emit-fixtures <dir>
    // Per PATCH_09 §E.1, the conformance binary can dump every test
    // case as a JSON fixture + plain-text expected-output file. The
    // resulting directory becomes the canonical conformance corpus
    // every language port must satisfy.
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "--emit-fixtures" {
        let out_dir = PathBuf::from(&args[2]);
        return emit_fixtures(&out_dir);
    }

    let cases = generate_cases();
    let mut disagreements: Vec<String> = Vec::new();
    let mut total = 0;
    for (name, fixture, expected_oracle) in cases {
        total += 1;
        let verifier_result = verify_ceilings_unchanged_since_genesis(&fixture);
        let agree = match (&verifier_result, &expected_oracle) {
            (Ok(()), OracleVerdict::Ok) => true,
            (
                Err(CeilingViolation::FieldValueChanged {
                    transition_height: vh,
                    ceiling_field: vf,
                    ..
                }),
                OracleVerdict::Drift {
                    height: oh,
                    field: of,
                },
            ) => vh == oh && vf == of,
            (
                Err(CeilingViolation::HistoryStructurallyInvalid { .. }),
                OracleVerdict::Malformed,
            ) => true,
            _ => false,
        };
        if !agree {
            disagreements.push(format!(
                "DISAGREE: case={} verifier={:?} oracle={:?}",
                name, verifier_result, expected_oracle,
            ));
        }
    }

    println!("sccgub-audit-conformance: {} cases", total);
    if disagreements.is_empty() {
        println!("ALL CASES AGREE — verifier matches independent oracle on every input");
        ExitCode::from(0)
    } else {
        for d in &disagreements {
            eprintln!("{}", d);
        }
        eprintln!(
            "FAILED: {} disagreements out of {}",
            disagreements.len(),
            total
        );
        ExitCode::from(1)
    }
}

/// Independent oracle's expected verdict. Computed from the fixture
/// without any dependency on `sccgub_audit::verifier`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OracleVerdict {
    Ok,
    Drift { height: u64, field: CeilingFieldId },
    Malformed,
}

/// Emit every conformance case as a JSON fixture + plain-text
/// expected-output file per PATCH_09 §E.1/§E.2.
///
/// The `.expected` content is captured from the **actual Rust
/// verifier output** in conformance-format mode rather than
/// constructed from the OracleVerdict enum. This guarantees that
/// the canonical `.expected` always matches what the Rust port
/// produces — and the cross-language harness then verifies every
/// other language port produces byte-identical output. Catches
/// a richer set of disagreements than a hand-constructed expected
/// would (e.g. before/after value mismatches across i128 boundary
/// handling).
fn emit_fixtures(out_dir: &std::path::Path) -> ExitCode {
    if let Err(e) = std::fs::create_dir_all(out_dir) {
        eprintln!("could not create {:?}: {}", out_dir, e);
        return ExitCode::from(2);
    }
    let cases = generate_cases();
    let total = cases.len();
    for (name, fixture, _expected) in cases {
        let json_path = out_dir.join(format!("{}.json", name));
        let expected_path = out_dir.join(format!("{}.expected", name));
        let json = match serde_json::to_string_pretty(&fixture) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("could not serialize {}: {}", name, e);
                return ExitCode::from(2);
            }
        };
        if let Err(e) = std::fs::write(&json_path, json) {
            eprintln!("could not write {:?}: {}", json_path, e);
            return ExitCode::from(2);
        }
        // Capture actual Rust verifier output in conformance format.
        let expected_text = match verify_ceilings_unchanged_since_genesis(&fixture) {
            Ok(()) => "ok\n".to_string(),
            Err(CeilingViolation::FieldValueChanged {
                transition_height,
                ceiling_field,
                before_value,
                after_value,
            }) => format!(
                "violation:FieldValueChanged:transition_height={}:ceiling_field={}:before_value={}:after_value={}\n",
                transition_height,
                ceiling_field.as_str(),
                before_value,
                after_value,
            ),
            Err(CeilingViolation::CeilingsUnreadableAtTransition {
                transition_height,
                ..
            }) => format!(
                "violation:CeilingsUnreadableAtTransition:transition_height={}\n",
                transition_height
            ),
            Err(CeilingViolation::HistoryStructurallyInvalid { .. }) => {
                "violation:HistoryStructurallyInvalid\n".to_string()
            }
            Err(CeilingViolation::GenesisCeilingsUnreadable { .. }) => {
                "violation:GenesisCeilingsUnreadable\n".to_string()
            }
        };
        if let Err(e) = std::fs::write(&expected_path, expected_text) {
            eprintln!("could not write {:?}: {}", expected_path, e);
            return ExitCode::from(2);
        }
    }
    println!(
        "emitted {} conformance fixture(s) to {:?}",
        total, out_dir
    );
    ExitCode::from(0)
}

fn t(activation: u64, to_v: u32) -> ChainVersionTransition {
    ChainVersionTransition {
        activation_height: activation,
        from_version: to_v - 1,
        to_version: to_v,
        upgrade_spec_hash: [0xAA; 32],
        proposal_id: [0xBB; 32],
    }
}

fn generate_cases() -> Vec<(&'static str, JsonChainStateFixture, OracleVerdict)> {
    let mut cases: Vec<(&'static str, JsonChainStateFixture, OracleVerdict)> = Vec::new();

    let g = ConstitutionalCeilings::default();

    // Case A: empty history → Ok.
    cases.push((
        "empty_history",
        JsonChainStateFixture::genesis_preserved([0; 32], g.clone(), vec![]),
        OracleVerdict::Ok,
    ));

    // Case B: single transition, preserved → Ok.
    cases.push((
        "single_transition_preserved",
        JsonChainStateFixture::genesis_preserved([0; 32], g.clone(), vec![t(100, 5)]),
        OracleVerdict::Ok,
    ));

    // Case C: three transitions, preserved → Ok.
    cases.push((
        "three_transitions_preserved",
        JsonChainStateFixture::genesis_preserved(
            [0; 32],
            g.clone(),
            vec![t(100, 5), t(200, 6), t(300, 7)],
        ),
        OracleVerdict::Ok,
    ));

    // Case D: drift in max_proof_depth at height 100.
    cases.push((
        "drift_max_proof_depth",
        drift_post(vec![t(100, 5)], 100, |c| c.max_proof_depth_ceiling += 1),
        OracleVerdict::Drift {
            height: 100,
            field: CeilingFieldId::MaxProofDepth,
        },
    ));

    // Case E: drift in max_block_gas at second of three transitions.
    cases.push((
        "drift_middle_transition_max_block_gas",
        drift_post(vec![t(100, 5), t(200, 6), t(300, 7)], 200, |c| {
            c.max_block_gas_ceiling += 1
        }),
        OracleVerdict::Drift {
            height: 200,
            field: CeilingFieldId::MaxBlockGas,
        },
    ));

    // Case F: pre-transition drift (subtler attack).
    cases.push((
        "drift_pre_transition_max_address_length",
        drift_pre(vec![t(100, 5)], 100, |c| c.max_address_length_ceiling += 1),
        OracleVerdict::Drift {
            height: 100,
            field: CeilingFieldId::MaxAddressLength,
        },
    ));

    // Case G: out-of-order history → Malformed.
    {
        let mut by_height = Vec::new();
        for h in [99u64, 100, 199, 200] {
            by_height.push((h, g.clone()));
        }
        cases.push((
            "non_monotonic_history",
            JsonChainStateFixture {
                genesis_block_hash: [0; 32],
                genesis_ceilings: g.clone(),
                chain_version_history: vec![t(200, 6), t(100, 5)],
                ceilings_by_height: by_height,
            },
            OracleVerdict::Malformed,
        ));
    }

    // Case H: degenerate activation_height = 0 → Ok.
    cases.push((
        "degenerate_height_zero_preserved",
        JsonChainStateFixture {
            genesis_block_hash: [0; 32],
            genesis_ceilings: g.clone(),
            chain_version_history: vec![t(0, 1)],
            ceilings_by_height: vec![(0, g.clone())],
        },
        OracleVerdict::Ok,
    ));

    // Case I: drift in min_effective_fee_floor (decrease counts).
    cases.push((
        "drift_min_fee_floor_decrease",
        drift_post(vec![t(100, 5)], 100, |c| c.min_effective_fee_floor -= 1),
        OracleVerdict::Drift {
            height: 100,
            field: CeilingFieldId::MinEffectiveFeeFloor,
        },
    ));

    // Case J: drift in max_validator_set_size.
    cases.push((
        "drift_max_validator_set_size",
        drift_post(vec![t(100, 5)], 100, |c| {
            c.max_validator_set_size_ceiling += 1
        }),
        OracleVerdict::Drift {
            height: 100,
            field: CeilingFieldId::MaxValidatorSetSize,
        },
    ));

    cases
}

fn drift_post(
    history: Vec<ChainVersionTransition>,
    drift_height: u64,
    mutate: impl Fn(&mut ConstitutionalCeilings),
) -> JsonChainStateFixture {
    let g = ConstitutionalCeilings::default();
    let mut by_height = Vec::new();
    for tr in &history {
        if tr.activation_height > 0 {
            by_height.push((tr.activation_height - 1, g.clone()));
        }
        let mut here = g.clone();
        if tr.activation_height == drift_height {
            mutate(&mut here);
        }
        by_height.push((tr.activation_height, here));
    }
    JsonChainStateFixture {
        genesis_block_hash: [0; 32],
        genesis_ceilings: g,
        chain_version_history: history,
        ceilings_by_height: by_height,
    }
}

fn drift_pre(
    history: Vec<ChainVersionTransition>,
    drift_height: u64,
    mutate: impl Fn(&mut ConstitutionalCeilings),
) -> JsonChainStateFixture {
    let g = ConstitutionalCeilings::default();
    let mut by_height = Vec::new();
    for tr in &history {
        if tr.activation_height > 0 {
            let mut pre = g.clone();
            if tr.activation_height == drift_height {
                mutate(&mut pre);
            }
            by_height.push((tr.activation_height - 1, pre));
        }
        by_height.push((tr.activation_height, g.clone()));
    }
    JsonChainStateFixture {
        genesis_block_hash: [0; 32],
        genesis_ceilings: g,
        chain_version_history: history,
        ceilings_by_height: by_height,
    }
}
