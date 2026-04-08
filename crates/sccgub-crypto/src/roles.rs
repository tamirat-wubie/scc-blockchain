use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

/// Operator key roles — separate keys for separate authority domains.
///
/// Production custody requires that a single compromised key cannot
/// escalate to full chain control. Each role has a distinct signing key
/// and a defined scope of authority.
///
/// Role hierarchy (highest to lowest authority):
/// - Genesis: one-time use for chain initialization. Destroyed after genesis.
/// - Governance: can submit constitutional proposals, activate emergency mode.
/// - Treasury: can authorize mints, burns, and reward distributions.
/// - Validator: can sign blocks and votes. Most frequently used, highest exposure.
/// - Operator: can restart nodes, trigger snapshots, rotate validator keys.
/// - Auditor: read-only access to chain state, receipts, and proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyRole {
    Genesis,
    Governance,
    Treasury,
    Validator,
    Operator,
    Auditor,
}

impl KeyRole {
    /// Whether this role can authorize the given action.
    pub fn can_authorize(&self, action: &AuthorizedAction) -> bool {
        match action {
            AuthorizedAction::SignBlock | AuthorizedAction::CastVote => {
                matches!(self, KeyRole::Validator | KeyRole::Genesis)
            }
            AuthorizedAction::SubmitGovernanceProposal | AuthorizedAction::ActivateEmergency => {
                matches!(self, KeyRole::Governance | KeyRole::Genesis)
            }
            AuthorizedAction::AuthorizeMint
            | AuthorizedAction::AuthorizeBurn
            | AuthorizedAction::DistributeReward => {
                matches!(self, KeyRole::Treasury | KeyRole::Genesis)
            }
            AuthorizedAction::RotateKey | AuthorizedAction::TriggerSnapshot => {
                matches!(self, KeyRole::Operator | KeyRole::Genesis)
            }
            AuthorizedAction::QueryState | AuthorizedAction::QueryReceipts => true, // All roles.
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            KeyRole::Genesis => "genesis",
            KeyRole::Governance => "governance",
            KeyRole::Treasury => "treasury",
            KeyRole::Validator => "validator",
            KeyRole::Operator => "operator",
            KeyRole::Auditor => "auditor",
        }
    }
}

/// Actions that require role-based authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizedAction {
    SignBlock,
    CastVote,
    SubmitGovernanceProposal,
    ActivateEmergency,
    AuthorizeMint,
    AuthorizeBurn,
    DistributeReward,
    RotateKey,
    TriggerSnapshot,
    QueryState,
    QueryReceipts,
}

/// A role-tagged key with its purpose and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleKey {
    pub role: KeyRole,
    pub public_key: [u8; 32],
    /// Block height at which this key was activated.
    pub activated_at: u64,
    /// Block height at which this key expires (0 = no expiry).
    pub expires_at: u64,
    /// Whether this key has been revoked.
    pub revoked: bool,
}

/// Operator keyring — manages all role keys for a node operator.
#[derive(Debug, Clone, Default)]
pub struct OperatorKeyring {
    pub keys: std::collections::HashMap<KeyRole, RoleKey>,
}

impl OperatorKeyring {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a key for a specific role.
    pub fn register(&mut self, role: KeyRole, public_key: [u8; 32], activated_at: u64) {
        self.keys.insert(
            role,
            RoleKey {
                role,
                public_key,
                activated_at,
                expires_at: 0,
                revoked: false,
            },
        );
    }

    /// Check if a public key is authorized for an action.
    pub fn authorize(
        &self,
        public_key: &[u8; 32],
        action: &AuthorizedAction,
        current_height: u64,
    ) -> Result<KeyRole, String> {
        for role_key in self.keys.values() {
            if &role_key.public_key != public_key {
                continue;
            }
            if role_key.revoked {
                return Err(format!("Key for role {:?} has been revoked", role_key.role));
            }
            if role_key.expires_at > 0 && current_height > role_key.expires_at {
                return Err(format!(
                    "Key for role {:?} expired at height {}",
                    role_key.role, role_key.expires_at
                ));
            }
            if role_key.role.can_authorize(action) {
                return Ok(role_key.role);
            }
        }
        Err(format!("No authorized key found for action {:?}", action))
    }

    /// Revoke a key by role.
    pub fn revoke(&mut self, role: KeyRole) -> Result<(), String> {
        let key = self.keys.get_mut(&role).ok_or("Role not found")?;
        key.revoked = true;
        Ok(())
    }

    /// Rotate a key: revoke old, register new.
    pub fn rotate(
        &mut self,
        role: KeyRole,
        new_public_key: [u8; 32],
        current_height: u64,
    ) -> Result<[u8; 32], String> {
        let old_pk = self
            .keys
            .get(&role)
            .map(|k| k.public_key)
            .ok_or("Role not found")?;
        self.revoke(role)?;
        self.register(role, new_public_key, current_height);
        Ok(old_pk)
    }

    /// Number of active (non-revoked, non-expired) keys.
    pub fn active_count(&self, current_height: u64) -> usize {
        self.keys
            .values()
            .filter(|k| !k.revoked && (k.expires_at == 0 || current_height <= k.expires_at))
            .count()
    }
}

/// Key rotation event — auditable record of a key change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationEvent {
    pub role: KeyRole,
    pub old_public_key: [u8; 32],
    pub new_public_key: [u8; 32],
    pub rotated_at_height: u64,
    /// Hash of the rotation authorization proof.
    pub authorization_proof: [u8; 32],
}

impl OperatorKeyring {
    /// Perform a full key rotation ceremony:
    /// 1. Verify the old key is active.
    /// 2. Revoke the old key.
    /// 3. Register the new key.
    /// 4. Produce an auditable rotation event.
    pub fn rotate_ceremony(
        &mut self,
        role: KeyRole,
        new_public_key: [u8; 32],
        current_height: u64,
        authorization_proof: [u8; 32],
    ) -> Result<KeyRotationEvent, String> {
        let old_key = self.keys.get(&role).ok_or("Role not found")?;
        if old_key.revoked {
            return Err("Cannot rotate a revoked key — register fresh instead".into());
        }
        let old_pk = old_key.public_key;
        if old_pk == new_public_key {
            return Err("New key must differ from old key".into());
        }

        self.revoke(role)?;
        self.register(role, new_public_key, current_height);

        Ok(KeyRotationEvent {
            role,
            old_public_key: old_pk,
            new_public_key,
            rotated_at_height: current_height,
            authorization_proof,
        })
    }

    /// Get rotation history for audit.
    pub fn rotation_history(&self) -> Vec<&RoleKey> {
        self.keys.values().filter(|k| k.revoked).collect()
    }
}

/// Generate a full set of operator keys for all roles.
pub fn generate_operator_keys() -> Vec<(KeyRole, SigningKey)> {
    let roles = [
        KeyRole::Governance,
        KeyRole::Treasury,
        KeyRole::Validator,
        KeyRole::Operator,
        KeyRole::Auditor,
    ];

    roles
        .iter()
        .map(|role| (*role, crate::keys::generate_keypair()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_authorization() {
        assert!(KeyRole::Validator.can_authorize(&AuthorizedAction::SignBlock));
        assert!(KeyRole::Validator.can_authorize(&AuthorizedAction::CastVote));
        assert!(!KeyRole::Validator.can_authorize(&AuthorizedAction::AuthorizeMint));

        assert!(KeyRole::Treasury.can_authorize(&AuthorizedAction::AuthorizeMint));
        assert!(!KeyRole::Treasury.can_authorize(&AuthorizedAction::SignBlock));

        assert!(KeyRole::Genesis.can_authorize(&AuthorizedAction::SignBlock));
        assert!(KeyRole::Genesis.can_authorize(&AuthorizedAction::AuthorizeMint));

        // All roles can query.
        assert!(KeyRole::Auditor.can_authorize(&AuthorizedAction::QueryState));
    }

    #[test]
    fn test_keyring_register_and_authorize() {
        let mut keyring = OperatorKeyring::new();
        let pk = [1u8; 32];
        keyring.register(KeyRole::Validator, pk, 0);

        assert!(keyring
            .authorize(&pk, &AuthorizedAction::SignBlock, 10)
            .is_ok());
        assert!(keyring
            .authorize(&pk, &AuthorizedAction::AuthorizeMint, 10)
            .is_err());
    }

    #[test]
    fn test_key_revocation() {
        let mut keyring = OperatorKeyring::new();
        let pk = [1u8; 32];
        keyring.register(KeyRole::Validator, pk, 0);

        keyring.revoke(KeyRole::Validator).unwrap();
        assert!(keyring
            .authorize(&pk, &AuthorizedAction::SignBlock, 10)
            .is_err());
    }

    #[test]
    fn test_key_rotation() {
        let mut keyring = OperatorKeyring::new();
        let old_pk = [1u8; 32];
        let new_pk = [2u8; 32];
        keyring.register(KeyRole::Validator, old_pk, 0);

        let returned_old = keyring.rotate(KeyRole::Validator, new_pk, 100).unwrap();
        assert_eq!(returned_old, old_pk);

        // Old key revoked.
        assert!(keyring
            .authorize(&old_pk, &AuthorizedAction::SignBlock, 101)
            .is_err());
        // New key works.
        assert!(keyring
            .authorize(&new_pk, &AuthorizedAction::SignBlock, 101)
            .is_ok());
    }

    #[test]
    fn test_key_expiry() {
        let mut keyring = OperatorKeyring::new();
        let pk = [1u8; 32];
        keyring.register(KeyRole::Operator, pk, 0);
        keyring.keys.get_mut(&KeyRole::Operator).unwrap().expires_at = 50;

        assert!(keyring
            .authorize(&pk, &AuthorizedAction::TriggerSnapshot, 40)
            .is_ok());
        assert!(keyring
            .authorize(&pk, &AuthorizedAction::TriggerSnapshot, 60)
            .is_err());
    }

    #[test]
    fn test_generate_operator_keys() {
        let keys = generate_operator_keys();
        assert_eq!(keys.len(), 5);
        // All roles present and unique.
        let roles: std::collections::HashSet<_> = keys.iter().map(|(r, _)| *r).collect();
        assert_eq!(roles.len(), 5);
    }
}
