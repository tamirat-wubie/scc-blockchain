use sccgub_types::governance::Norm;
use sccgub_types::tension::TensionValue;
use sccgub_types::NormId;
use std::collections::HashMap;

/// Maximum norms in the registry.
pub const MAX_NORMS: usize = 10_000;

/// Norm registry managing norm evolution via discrete-time replicator dynamics.
/// Per v2.1 FIX B-11: uses discrete-time (not continuous ODE).
#[derive(Debug, Clone)]
pub struct NormRegistry {
    pub norms: HashMap<NormId, Norm>,
}

impl NormRegistry {
    pub fn new() -> Self {
        Self {
            norms: HashMap::new(),
        }
    }

    /// Register a norm. Updates existing norms (replicator dynamics).
    /// Returns Err if registry is full and the norm is new.
    pub fn register(&mut self, norm: Norm) -> Result<(), String> {
        if !self.norms.contains_key(&norm.id) && self.norms.len() >= MAX_NORMS {
            return Err(format!(
                "Norm registry full ({}/{})",
                self.norms.len(),
                MAX_NORMS
            ));
        }
        self.norms.insert(norm.id, norm);
        Ok(())
    }

    pub fn get(&self, id: &NormId) -> Option<&Norm> {
        self.norms.get(id)
    }

    /// Execute one epoch of discrete-time replicator dynamics.
    ///
    /// ```text
    /// p_ν(t+1) = p_ν(t) · F(ν) / Σ_μ p_μ(t) · F(μ)
    /// where F(ν) = U(ν) - λ·K(ν)
    /// ```
    ///
    /// Applied per governance epoch, not per block.
    pub fn evolve_epoch(&mut self) {
        let active_norms: Vec<NormId> = self
            .norms
            .iter()
            .filter(|(_, n)| n.active)
            .map(|(id, _)| *id)
            .collect();

        if active_norms.is_empty() {
            return;
        }

        // Compute fitness for each norm: F(ν) = max(0, fitness - enforcement_cost).
        // Clamp to zero to prevent negative fitness corrupting dynamics.
        let fitnesses: HashMap<NormId, TensionValue> = active_norms
            .iter()
            .map(|id| {
                let norm = &self.norms[id];
                let f = (norm.fitness - norm.enforcement_cost).max(TensionValue::ZERO);
                (*id, f)
            })
            .collect();

        // Compute mean fitness: F̄ = Σ p_ν · F(ν).
        let mean_fitness: TensionValue = active_norms
            .iter()
            .map(|id| {
                let norm = &self.norms[id];
                norm.population_share.mul_fp(fitnesses[id])
            })
            .fold(TensionValue::ZERO, |acc, v| acc + v);

        // Guard against zero or negative mean fitness.
        if mean_fitness.raw() <= 0 {
            return;
        }

        // Update population shares: p_ν(t+1) = p_ν(t) · F(ν) / F̄.
        // Uses safe division to prevent overflow.
        for id in &active_norms {
            let Some(norm) = self.norms.get_mut(id) else {
                continue;
            };
            let numerator = norm.population_share.mul_fp(fitnesses[id]);
            // Safe fixed-point division: (num / mean) with SCALE preservation.
            // Restructure as (num / mean) * SCALE to avoid intermediate overflow.
            let raw = if mean_fitness.raw() != 0 {
                // (numerator * SCALE) / mean — use split multiply to avoid overflow.
                let a = numerator.raw() / mean_fitness.raw();
                let b = (numerator.raw() % mean_fitness.raw()).saturating_mul(TensionValue::SCALE)
                    / mean_fitness.raw();
                a.saturating_mul(TensionValue::SCALE).saturating_add(b)
            } else {
                0
            };
            // Clamp to [0, SCALE] — shares must not go negative.
            norm.population_share = TensionValue(raw.clamp(0, TensionValue::SCALE));
        }

        // Renormalize: ensure shares sum to exactly SCALE (1.0).
        let total: i128 = active_norms
            .iter()
            .map(|id| self.norms[id].population_share.raw())
            .sum();
        if total > 0 {
            for id in &active_norms {
                let Some(norm) = self.norms.get_mut(id) else {
                    continue;
                };
                let raw = norm
                    .population_share
                    .raw()
                    .saturating_mul(TensionValue::SCALE)
                    / total;
                norm.population_share = TensionValue(raw.max(0));
            }
        } else if !active_norms.is_empty() {
            // All shares collapsed to zero — reset to equal distribution.
            let equal_share = TensionValue::SCALE / active_norms.len() as i128;
            for id in &active_norms {
                if let Some(norm) = self.norms.get_mut(id) {
                    norm.population_share = TensionValue(equal_share);
                }
            }
        }
    }
}

impl Default for NormRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::governance::PrecedenceLevel;

    fn test_norm(id: [u8; 32], share_pct: i128, fitness: i64) -> Norm {
        // share_pct is a percentage (0-100), stored as fraction of 1.
        let share = TensionValue(share_pct * TensionValue::SCALE / 100);
        Norm {
            id,
            name: format!("norm_{}", id[0]),
            description: String::new(),
            precedence: PrecedenceLevel::Meaning,
            population_share: share,
            fitness: TensionValue::from_integer(fitness),
            enforcement_cost: TensionValue::ZERO,
            active: true,
            created_at_height: 0,
        }
    }

    #[test]
    fn test_replicator_dynamics() {
        let mut registry = NormRegistry::new();
        // Norm A: high fitness, Norm B: low fitness. 50% share each.
        registry.register(test_norm([1u8; 32], 50, 10));
        registry.register(test_norm([2u8; 32], 50, 5));

        registry.evolve_epoch();

        let a = registry.get(&[1u8; 32]).unwrap();
        let b = registry.get(&[2u8; 32]).unwrap();
        // Higher fitness norm should gain population share.
        assert!(a.population_share > b.population_share);
    }
}
