pub mod agent;
pub mod block;
pub mod bridge;
pub mod builder;
pub mod causal;
pub mod compliance;
pub mod contract;
pub mod domain;
pub mod economics;
pub mod governance;
pub mod mfidel;
pub mod proof;
pub mod receipt;
pub mod state;
pub mod tension;
pub mod timestamp;
pub mod transition;

/// 32-byte hash used throughout the system.
pub type Hash = [u8; 32];

/// Null hash constant (all zeros).
pub const ZERO_HASH: Hash = [0u8; 32];

/// Symbol address in the state trie.
/// Maximum length enforced at validation boundaries.
pub type SymbolAddress = Vec<u8>;

/// Maximum allowed symbol address length (4 KB).
pub const MAX_SYMBOL_ADDRESS_LEN: usize = 4096;

/// Unique identifier for an agent.
pub type AgentId = Hash;

/// Unique identifier for a node in the network.
pub type NodeId = Hash;

/// Unique identifier for a transition.
pub type TransitionId = Hash;

/// Unique identifier for a norm.
pub type NormId = Hash;

/// Unique identifier for a constraint.
pub type ConstraintId = Hash;

/// Unique identifier for a rule.
pub type RuleId = Hash;

/// Unique identifier for a contract.
pub type ContractId = Hash;

/// Unique identifier for an object.
pub type ObjectId = Hash;

/// Merkle root (same underlying type as Hash).
pub type MerkleRoot = Hash;
