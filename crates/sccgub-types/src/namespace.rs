// Namespace prefix constants — single source of truth for all crates.
// The ontology table in sccgub-execution MUST import these, not redefine them.
pub const NS_SYSTEM: &[u8] = b"system/";
pub const NS_BALANCE: &[u8] = b"balance/";
pub const NS_ESCROW: &[u8] = b"escrow/";
pub const NS_TREASURY: &[u8] = b"treasury/";
pub const NS_AGENTS: &[u8] = b"agents/";
pub const NS_NORMS: &[u8] = b"norms/";
pub const NS_CONSTRAINTS: &[u8] = b"constraints/";
pub const NS_CONTRACT: &[u8] = b"contract/";
pub const NS_DISPUTES: &[u8] = b"disputes/";
pub const NS_DATA: &[u8] = b"data/";

// Namespace key builders — canonical constructors for trie keys.
//
// The ONLY correct way to build keys for each namespace. Using
// format!() inline risks typos in prefixes (the N-8 bug class).
// All namespace prefixes match the ontology table in sccgub-execution.

/// Build a balance ledger key: `balance/<hex(agent_id)>`
pub fn balance_key(agent_id: &[u8; 32]) -> Vec<u8> {
    format!("balance/{}", hex::encode(agent_id)).into_bytes()
}

/// Build a user-data key: `data/<path>`
pub fn data_key(path: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(5 + path.len());
    k.extend_from_slice(b"data/");
    k.extend_from_slice(path);
    k
}

/// Build a norm registry key: `norms/<hex(norm_id)>`
pub fn norm_key(norm_id: &[u8; 32]) -> Vec<u8> {
    format!("norms/{}", hex::encode(norm_id)).into_bytes()
}

/// Build an agent registry key: `agents/<hex(public_key)>`
pub fn agent_key(public_key: &[u8; 32]) -> Vec<u8> {
    format!("agents/{}", hex::encode(public_key)).into_bytes()
}

/// Build a contract key: `contract/<path>`
pub fn contract_key(path: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(9 + path.len());
    k.extend_from_slice(b"contract/");
    k.extend_from_slice(path);
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_balance_key_format() {
        let key = balance_key(&[1u8; 32]);
        assert!(key.starts_with(b"balance/"));
        assert_eq!(key.len(), 8 + 64); // "balance/" + 64 hex chars
    }

    #[test]
    fn test_data_key_format() {
        let key = data_key(b"user/prefs");
        assert_eq!(key, b"data/user/prefs");
    }

    #[test]
    fn test_norm_key_format() {
        let key = norm_key(&[2u8; 32]);
        assert!(key.starts_with(b"norms/"));
    }

    #[test]
    fn test_contract_key_format() {
        let key = contract_key(b"mycontract/state");
        assert_eq!(key, b"contract/mycontract/state");
    }
}
