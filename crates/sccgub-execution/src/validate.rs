use sccgub_state::world::ManagedWorldState;
use sccgub_types::transition::SymbolicTransition;

use crate::phi::phi_traversal_tx;
use crate::wh_check::check_transition_wh;

/// Validate a single transition before inclusion in a block.
/// Returns Ok(()) if the transition passes per-transaction Φ phases.
pub fn validate_transition(
    tx: &SymbolicTransition,
    state: &ManagedWorldState,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // Check WHBinding completeness.
    if let Err(e) = check_transition_wh(tx) {
        errors.push(format!("WHBinding: {}", e));
    }

    // Check signature is present.
    if tx.signature.is_empty() {
        errors.push("Missing signature".into());
    }

    // Run per-tx Φ traversal.
    let phi_log = phi_traversal_tx(tx, state);
    if !phi_log.all_phases_passed {
        for result in &phi_log.phases_completed {
            if !result.passed {
                errors.push(format!("Φ {:?}: {}", result.phase, result.details));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
