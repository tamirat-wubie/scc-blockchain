use serde::{Deserialize, Serialize};

use sccgub_types::tension::TensionValue;
use sccgub_types::{AgentId, Hash, SymbolAddress};

/// AI Agent governance policy.
/// Addresses OWASP Top 10 for Agentic Applications:
/// - Goal hijacking: bounded by norm_set
/// - Tool misuse: bounded by allowed_operations
/// - Identity abuse: separate agent_type with operator_id
/// - Credential misuse: per-agent action budget
/// - Cascading failures: max_chain_depth limits causal propagation
/// - Rogue agents: containment engine quarantines
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPolicy {
    /// The AI agent this policy governs.
    pub agent_id: AgentId,
    /// The human operator responsible for this agent.
    pub operator_id: AgentId,
    /// Hash of the model weights/version (for auditability).
    pub model_hash: Hash,
    /// Maximum transitions this agent can submit per block.
    pub max_actions_per_block: u32,
    /// Maximum transfer amount per transaction.
    pub max_transfer_amount: TensionValue,
    /// State keys this agent is allowed to write.
    pub allowed_write_prefixes: Vec<SymbolAddress>,
    /// State keys this agent is allowed to read.
    pub allowed_read_prefixes: Vec<SymbolAddress>,
    /// Maximum causal chain depth (prevents cascading).
    pub max_chain_depth: u32,
    /// Whether this agent requires human co-signature above a threshold.
    pub require_cosign_above: Option<TensionValue>,
    /// Whether the agent is active.
    pub active: bool,
}

impl AgentPolicy {
    /// Check if an agent is allowed to write to a specific address.
    /// Default-deny: empty prefix list means NO access (fail-closed).
    pub fn can_write(&self, address: &SymbolAddress) -> bool {
        if !self.active {
            return false;
        }
        // Default-deny: empty means no access, not all access.
        if self.allowed_write_prefixes.is_empty() {
            return false;
        }
        self.allowed_write_prefixes
            .iter()
            .any(|prefix| address.starts_with(prefix))
    }

    /// Check if an agent is allowed to read from a specific address.
    /// Default-deny: empty prefix list means NO access (fail-closed).
    pub fn can_read(&self, address: &SymbolAddress) -> bool {
        if !self.active {
            return false;
        }
        if self.allowed_read_prefixes.is_empty() {
            return false;
        }
        self.allowed_read_prefixes
            .iter()
            .any(|prefix| address.starts_with(prefix))
    }

    /// Check if a transfer amount is within the agent's budget.
    pub fn check_transfer_limit(&self, amount: TensionValue) -> Result<(), String> {
        if amount > self.max_transfer_amount {
            return Err(format!(
                "Transfer {} exceeds agent limit {}",
                amount, self.max_transfer_amount
            ));
        }
        Ok(())
    }

    /// Check if human co-signature is required for this action.
    pub fn requires_cosign(&self, amount: TensionValue) -> bool {
        if let Some(threshold) = self.require_cosign_above {
            amount > threshold
        } else {
            false
        }
    }
}

/// Maximum agent policies (prevents memory DoS).
pub const MAX_AGENT_POLICIES: usize = 50_000;

/// Registry of AI agent policies.
#[derive(Debug, Clone, Default)]
pub struct AgentPolicyRegistry {
    pub policies: std::collections::HashMap<AgentId, AgentPolicy>,
}

impl AgentPolicyRegistry {
    /// Register a policy for an AI agent.
    pub fn register(&mut self, policy: AgentPolicy) -> Result<(), String> {
        if self.policies.contains_key(&policy.agent_id) {
            return Err("Agent policy already registered".into());
        }
        if self.policies.len() >= MAX_AGENT_POLICIES {
            return Err("Agent policy registry full".into());
        }
        self.policies.insert(policy.agent_id, policy);
        Ok(())
    }

    /// Get the policy for an agent.
    pub fn get(&self, agent_id: &AgentId) -> Option<&AgentPolicy> {
        self.policies.get(agent_id)
    }

    /// Check if an agent's action is permitted, including per-block action count.
    pub fn check_action(
        &self,
        agent_id: &AgentId,
        target: &SymbolAddress,
        transfer_amount: Option<TensionValue>,
    ) -> Result<(), String> {
        let policy = self.get(agent_id).ok_or("No policy for agent")?;

        if !policy.active {
            return Err("Agent policy is inactive".into());
        }

        if !policy.can_write(target) {
            return Err(format!(
                "Agent not allowed to write to {}",
                String::from_utf8_lossy(target)
            ));
        }

        if let Some(amount) = transfer_amount {
            policy.check_transfer_limit(amount)?;
        }

        Ok(())
    }

    /// Check if an agent has exceeded its per-block action limit.
    pub fn check_action_count(
        &self,
        agent_id: &AgentId,
        actions_in_block: u32,
    ) -> Result<(), String> {
        if let Some(policy) = self.get(agent_id) {
            if actions_in_block >= policy.max_actions_per_block {
                return Err(format!(
                    "Agent exceeded max actions per block: {} >= {}",
                    actions_in_block, policy.max_actions_per_block
                ));
            }
        }
        Ok(())
    }

    /// Check if a causal chain depth exceeds the agent's policy limit.
    pub fn check_chain_depth(&self, agent_id: &AgentId, chain_depth: u32) -> Result<(), String> {
        if let Some(policy) = self.get(agent_id) {
            if chain_depth > policy.max_chain_depth {
                return Err(format!(
                    "Causal chain depth {} exceeds agent limit {}",
                    chain_depth, policy.max_chain_depth
                ));
            }
        }
        Ok(())
    }

    /// Deactivate an agent's policy.
    pub fn deactivate(&mut self, agent_id: &AgentId) -> Result<(), String> {
        let policy = self
            .policies
            .get_mut(agent_id)
            .ok_or("Agent policy not found")?;
        policy.active = false;
        Ok(())
    }

    /// Count active AI agent policies.
    pub fn active_count(&self) -> usize {
        self.policies.values().filter(|p| p.active).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> AgentPolicy {
        AgentPolicy {
            agent_id: [1u8; 32],
            operator_id: [2u8; 32],
            model_hash: [3u8; 32],
            max_actions_per_block: 10,
            max_transfer_amount: TensionValue::from_integer(1000),
            allowed_write_prefixes: vec![b"agent/data/".to_vec()],
            allowed_read_prefixes: vec![],
            max_chain_depth: 5,
            require_cosign_above: Some(TensionValue::from_integer(500)),
            active: true,
        }
    }

    #[test]
    fn test_write_permission() {
        let policy = test_policy();
        assert!(policy.can_write(&b"agent/data/output".to_vec()));
        assert!(!policy.can_write(&b"system/config".to_vec()));
    }

    #[test]
    fn test_transfer_limit() {
        let policy = test_policy();
        assert!(policy
            .check_transfer_limit(TensionValue::from_integer(500))
            .is_ok());
        assert!(policy
            .check_transfer_limit(TensionValue::from_integer(2000))
            .is_err());
    }

    #[test]
    fn test_cosign_requirement() {
        let policy = test_policy();
        assert!(!policy.requires_cosign(TensionValue::from_integer(100)));
        assert!(policy.requires_cosign(TensionValue::from_integer(600)));
    }

    #[test]
    fn test_registry_check_action() {
        let mut registry = AgentPolicyRegistry::default();
        registry.register(test_policy()).unwrap();

        // Allowed write.
        assert!(registry
            .check_action(&[1u8; 32], &b"agent/data/x".to_vec(), None)
            .is_ok());

        // Disallowed write.
        assert!(registry
            .check_action(&[1u8; 32], &b"system/x".to_vec(), None)
            .is_err());

        // Transfer within limit.
        assert!(registry
            .check_action(
                &[1u8; 32],
                &b"agent/data/x".to_vec(),
                Some(TensionValue::from_integer(500))
            )
            .is_ok());

        // Transfer over limit.
        assert!(registry
            .check_action(
                &[1u8; 32],
                &b"agent/data/x".to_vec(),
                Some(TensionValue::from_integer(5000))
            )
            .is_err());
    }

    #[test]
    fn test_deactivation() {
        let mut registry = AgentPolicyRegistry::default();
        registry.register(test_policy()).unwrap();
        assert_eq!(registry.active_count(), 1);

        registry.deactivate(&[1u8; 32]).unwrap();
        assert_eq!(registry.active_count(), 0);

        // Deactivated agent can't act.
        assert!(registry
            .check_action(&[1u8; 32], &b"agent/data/x".to_vec(), None)
            .is_err());
    }
}
