use crate::governance::PrecedenceLevel;
use crate::timestamp::CausalTimestamp;
use crate::transition::*;
use crate::{Hash, SymbolAddress};
use std::collections::BTreeSet;

/// SimpleTransaction builder — reduces semantic burden for developers.
/// Wraps the full WHBinding + TransitionIntent + OperationPayload complexity
/// behind a clean fluent API.
///
/// This addresses the fracture risk of "too much protocol" — developers can
/// build valid transactions without understanding all 7 WH dimensions.
///
/// ```text
/// let tx = SimpleTransaction::write(agent_id, b"key", b"value")
///     .nonce(42)
///     .build();
/// ```
pub struct SimpleTransaction {
    actor_id: Hash,
    public_key: [u8; 32],
    target: SymbolAddress,
    payload: OperationPayload,
    kind: TransitionKind,
    nonce: u128,
    purpose: String,
    precedence: PrecedenceLevel,
}

impl SimpleTransaction {
    /// Create a state write transaction.
    pub fn write(actor_id: Hash, public_key: [u8; 32], key: &[u8], value: &[u8]) -> Self {
        Self {
            actor_id,
            public_key,
            target: key.to_vec(),
            payload: OperationPayload::Write {
                key: key.to_vec(),
                value: value.to_vec(),
            },
            kind: TransitionKind::StateWrite,
            nonce: 1,
            purpose: "State write".into(),
            precedence: PrecedenceLevel::Meaning,
        }
    }

    /// Create an asset transfer transaction.
    pub fn transfer(actor_id: Hash, public_key: [u8; 32], to: Hash, amount: i64) -> Self {
        let amount_raw = crate::tension::TensionValue::from_integer(amount).raw();
        Self {
            actor_id,
            public_key,
            target: b"ledger/transfer".to_vec(),
            payload: OperationPayload::AssetTransfer {
                from: actor_id,
                to,
                amount: amount_raw,
            },
            kind: TransitionKind::AssetTransfer,
            nonce: 1,
            purpose: format!("Transfer {} tokens", amount),
            precedence: PrecedenceLevel::Meaning,
        }
    }

    /// Set the nonce (required for replay protection).
    pub fn nonce(mut self, nonce: u128) -> Self {
        self.nonce = nonce;
        self
    }

    /// Set a custom purpose description.
    pub fn purpose(mut self, purpose: &str) -> Self {
        self.purpose = purpose.into();
        self
    }

    /// Set the governance precedence level.
    pub fn precedence(mut self, level: PrecedenceLevel) -> Self {
        self.precedence = level;
        self
    }

    /// Build into a full SymbolicTransition (unsigned — caller must sign).
    pub fn build(self) -> SymbolicTransition {
        let seal = crate::mfidel::MfidelAtomicSeal::from_height(1);
        let agent = crate::agent::AgentIdentity {
            agent_id: self.actor_id,
            public_key: self.public_key,
            mfidel_seal: seal,
            registration_block: 0,
            governance_level: self.precedence,
            norm_set: BTreeSet::new(),
            responsibility: crate::agent::ResponsibilityState::default(),
        };

        let rule_hash = {
            let mut h = [0u8; 32];
            h[0] = self.kind as u8;
            h
        };

        let intent = WHBindingIntent {
            who: self.actor_id,
            when: CausalTimestamp::genesis(),
            r#where: self.target.clone(),
            why: CausalJustification {
                invoking_rule: rule_hash,
                precedence_level: self.precedence,
                causal_ancestors: vec![],
                constraint_proof: vec![],
            },
            how: TransitionMechanism::DirectStateWrite,
            which: BTreeSet::new(),
            what_declared: self.purpose.clone(),
        };

        SymbolicTransition {
            tx_id: [0u8; 32], // Caller computes from canonical bytes.
            actor: agent,
            intent: TransitionIntent {
                kind: self.kind,
                target: self.target,
                declared_purpose: self.purpose,
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: self.payload,
            causal_chain: vec![],
            wh_binding_intent: intent,
            nonce: self.nonce,
            signature: vec![], // Caller signs.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_builder() {
        let tx = SimpleTransaction::write([1u8; 32], [2u8; 32], b"key", b"value")
            .nonce(42)
            .purpose("test write")
            .build();

        assert_eq!(tx.nonce, 42);
        assert_eq!(tx.intent.kind, TransitionKind::StateWrite);
        assert_eq!(tx.intent.target, b"key".to_vec());
        assert_eq!(tx.intent.declared_purpose, "test write");
        assert!(tx.wh_binding_intent.is_complete());
    }

    #[test]
    fn test_transfer_builder() {
        let tx = SimpleTransaction::transfer([1u8; 32], [2u8; 32], [3u8; 32], 1000)
            .nonce(1)
            .build();

        assert_eq!(tx.intent.kind, TransitionKind::AssetTransfer);
        match &tx.payload {
            OperationPayload::AssetTransfer { from, to, amount } => {
                assert_eq!(*from, [1u8; 32]);
                assert_eq!(*to, [3u8; 32]);
                assert!(*amount > 0);
            }
            _ => panic!("Expected AssetTransfer payload"),
        }
    }
}
