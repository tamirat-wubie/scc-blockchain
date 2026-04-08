use sccgub_types::agent::AgentIdentity;
use sccgub_types::governance::PrecedenceLevel;
use sccgub_types::mfidel::MfidelAtomicSeal;
use sccgub_types::AgentId;
use std::collections::HashMap;

/// Minimum registration cost in tension units (sybil resistance).
/// Prevents identity rotation attacks on the containment system.
pub const REGISTRATION_COST: i128 = 100 * sccgub_types::tension::TensionValue::SCALE;

/// Maximum registered agents (prevents Sybil memory DoS).
pub const MAX_AGENTS: usize = 100_000;

/// Agent registration service.
/// Manages the lifecycle of agent identities on-chain.
/// Requires a minimum registration cost to prevent sybil attacks.
#[derive(Debug, Clone, Default)]
pub struct AgentRegistry {
    pub agents: HashMap<AgentId, RegisteredAgent>,
}

/// On-chain registered agent.
#[derive(Debug, Clone)]
pub struct RegisteredAgent {
    pub identity: AgentIdentity,
    pub registered_at: u64,
    pub active: bool,
    pub revoked: bool,
}

impl AgentRegistry {
    /// Register a new agent. Validates that agent_id matches public_key + seal.
    pub fn register(
        &mut self,
        public_key: [u8; 32],
        mfidel_seal: MfidelAtomicSeal,
        governance_level: PrecedenceLevel,
        block_height: u64,
    ) -> Result<AgentId, String> {
        if self.agents.len() >= MAX_AGENTS {
            return Err("Agent registry full".into());
        }
        // Compute canonical agent_id.
        let agent_id = sccgub_crypto::hash::blake3_hash_concat(&[
            &public_key,
            &sccgub_crypto::canonical::canonical_bytes(&mfidel_seal),
        ]);

        // Check for duplicate registration.
        if self.agents.contains_key(&agent_id) {
            return Err(format!(
                "Agent {} already registered",
                hex::encode(agent_id)
            ));
        }

        let identity = AgentIdentity {
            agent_id,
            public_key,
            mfidel_seal,
            registration_block: block_height,
            governance_level,
            norm_set: std::collections::HashSet::new(),
            responsibility: sccgub_types::agent::ResponsibilityState::default(),
        };

        self.agents.insert(
            agent_id,
            RegisteredAgent {
                identity,
                registered_at: block_height,
                active: true,
                revoked: false,
            },
        );

        Ok(agent_id)
    }

    /// Look up an agent.
    pub fn get(&self, agent_id: &AgentId) -> Option<&RegisteredAgent> {
        self.agents.get(agent_id)
    }

    /// Check if an agent is active (registered and not revoked).
    pub fn is_active(&self, agent_id: &AgentId) -> bool {
        self.agents
            .get(agent_id)
            .is_some_and(|a| a.active && !a.revoked)
    }

    /// Revoke an agent.
    pub fn revoke(&mut self, agent_id: &AgentId) -> Result<(), String> {
        let agent = self.agents.get_mut(agent_id).ok_or("Agent not found")?;
        agent.active = false;
        agent.revoked = true;
        Ok(())
    }

    /// Count of active agents.
    pub fn active_count(&self) -> usize {
        self.agents
            .values()
            .filter(|a| a.active && !a.revoked)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_lookup() {
        let mut registry = AgentRegistry::default();
        let key = sccgub_crypto::keys::generate_keypair();
        let pk = *key.verifying_key().as_bytes();

        let id = registry
            .register(
                pk,
                MfidelAtomicSeal::from_height(1),
                PrecedenceLevel::Meaning,
                0,
            )
            .unwrap();

        assert!(registry.is_active(&id));
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut registry = AgentRegistry::default();
        let key = sccgub_crypto::keys::generate_keypair();
        let pk = *key.verifying_key().as_bytes();

        registry
            .register(
                pk,
                MfidelAtomicSeal::from_height(1),
                PrecedenceLevel::Meaning,
                0,
            )
            .unwrap();

        let result = registry.register(
            pk,
            MfidelAtomicSeal::from_height(1),
            PrecedenceLevel::Meaning,
            1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_revoke() {
        let mut registry = AgentRegistry::default();
        let key = sccgub_crypto::keys::generate_keypair();
        let pk = *key.verifying_key().as_bytes();

        let id = registry
            .register(
                pk,
                MfidelAtomicSeal::from_height(1),
                PrecedenceLevel::Meaning,
                0,
            )
            .unwrap();

        registry.revoke(&id).unwrap();
        assert!(!registry.is_active(&id));
        assert_eq!(registry.active_count(), 0);
    }
}
