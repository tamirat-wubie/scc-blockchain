//! `sccgub-audit` CLI — standalone moat verifier per PATCH_08.md §C.4.
//!
//! Subcommands:
//!
//! - `verify-ceilings --chain-state <path>` — load a JSON-formatted
//!   `ChainStateFixture` and run the verifier. Exit codes per
//!   PATCH_08 §C.4: 0 = `Ok(())`, 1 = `CeilingViolation`, 2 =
//!   malformed input or I/O error.
//!
//! Binary-snapshot reading (Patch-09) is deferred. Today's CLI uses
//! the JSON fixture format (`JsonChainStateFixture`) so the binary
//! can be exercised by external reviewers and pilot-adopter dry-runs
//! without requiring snapshot-format expertise.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use sccgub_audit::{
    verify_ceilings_unchanged_since_genesis, CeilingViolation, JsonChainStateFixture,
};

#[derive(Parser, Debug)]
#[command(
    name = "sccgub-audit",
    version,
    about = "External moat-verifier for SCCGUB",
    long_about = "Per PATCH_08.md and POSITIONING.md §11. Independently \
                  compilable and runnable by any third party with read \
                  access to the chain log; does not depend on \
                  sccgub-state, sccgub-execution, or any other \
                  consensus-layer crate."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Verify that no ConstitutionalCeilings field has been raised
    /// (or otherwise changed) since genesis.
    VerifyCeilings {
        /// Path to a JSON-encoded `JsonChainStateFixture`. Binary
        /// snapshot mode is deferred to Patch-09 §D.
        #[arg(long)]
        chain_state: PathBuf,
        /// Emit machine-readable JSON output (suitable for CI
        /// integration by pilot-adopter institutions).
        #[arg(long)]
        json: bool,
        /// Emit conformance-format output per PATCH_09 §E.2 (plain
        /// text, line-oriented, easy to diff across language ports).
        #[arg(long)]
        conformance: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::VerifyCeilings {
            chain_state,
            json,
            conformance,
        } => verify_ceilings_command(chain_state, json, conformance),
    }
}

fn verify_ceilings_command(
    chain_state_path: PathBuf,
    json_output: bool,
    conformance: bool,
) -> ExitCode {
    let bytes = match std::fs::read(&chain_state_path) {
        Ok(b) => b,
        Err(e) => {
            emit_input_error(
                json_output,
                conformance,
                &format!("could not read {:?}: {}", chain_state_path, e),
            );
            return ExitCode::from(2);
        }
    };
    let fixture: JsonChainStateFixture = match serde_json::from_slice(&bytes) {
        Ok(f) => f,
        Err(e) => {
            emit_input_error(
                json_output,
                conformance,
                &format!("could not parse JSON fixture: {}", e),
            );
            return ExitCode::from(2);
        }
    };
    match verify_ceilings_unchanged_since_genesis(&fixture) {
        Ok(()) => {
            emit_ok(json_output, conformance);
            ExitCode::from(0)
        }
        Err(violation) => {
            emit_violation(json_output, conformance, &violation);
            ExitCode::from(1)
        }
    }
}

fn emit_ok(json_output: bool, conformance: bool) {
    if conformance {
        // Per PATCH_09 §E.2 expected-output format.
        println!("ok");
    } else if json_output {
        let payload = serde_json::json!({
            "result": "ok",
            "message": "ceilings unchanged since genesis",
        });
        println!("{}", serde_json::to_string(&payload).unwrap());
    } else {
        println!("OK: ceilings unchanged since genesis. Moat HELD.");
    }
}

fn emit_violation(json_output: bool, conformance: bool, violation: &CeilingViolation) {
    if conformance {
        // Per PATCH_09 §E.2 expected-output format.
        match violation {
            CeilingViolation::FieldValueChanged {
                transition_height,
                ceiling_field,
                before_value,
                after_value,
            } => {
                println!(
                    "violation:FieldValueChanged:transition_height={}:ceiling_field={}:before_value={}:after_value={}",
                    transition_height,
                    ceiling_field.as_str(),
                    before_value,
                    after_value,
                );
            }
            CeilingViolation::CeilingsUnreadableAtTransition {
                transition_height, ..
            } => {
                println!(
                    "violation:CeilingsUnreadableAtTransition:transition_height={}",
                    transition_height
                );
            }
            CeilingViolation::HistoryStructurallyInvalid { .. } => {
                println!("violation:HistoryStructurallyInvalid");
            }
            CeilingViolation::GenesisCeilingsUnreadable { .. } => {
                println!("violation:GenesisCeilingsUnreadable");
            }
        }
    } else if json_output {
        let payload = serde_json::json!({
            "result": "violation",
            "violation": violation,
        });
        println!("{}", serde_json::to_string(&payload).unwrap());
    } else {
        println!("VIOLATION: {}", violation);
    }
}

fn emit_input_error(json_output: bool, conformance: bool, msg: &str) {
    if conformance {
        // Conformance protocol does not have an explicit input-error
        // line; emit nothing on stdout and only surface on stderr so
        // the cross-language harness still diffs cleanly. Real
        // failures are caught via exit code 2.
        eprintln!("INPUT ERROR: {}", msg);
    } else if json_output {
        let payload = serde_json::json!({
            "result": "input_error",
            "message": msg,
        });
        eprintln!("{}", serde_json::to_string(&payload).unwrap());
    } else {
        eprintln!("INPUT ERROR: {}", msg);
    }
}
