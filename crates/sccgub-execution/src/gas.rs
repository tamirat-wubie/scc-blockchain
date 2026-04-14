use sccgub_types::consensus_params::ConsensusParams;
use sccgub_types::tension::TensionValue;

/// Gas metering for deterministic resource accounting.
///
/// Every operation costs gas. Gas is bounded per-transaction and per-block.
/// This ensures:
/// - No unbounded computation (even with step-bounded contracts).
/// - Fair resource pricing for fee calculation.
/// - Deterministic execution costs across all nodes.
///
/// Gas costs are denominated in abstract units mapped to real fees
/// by the economic layer.
#[derive(Debug, Clone)]
pub struct GasMeter {
    /// Maximum gas allowed for this execution context.
    pub limit: u64,
    /// Consensus-bound pricing table used for this execution.
    pub pricing: GasPricing,
    /// Gas consumed so far.
    pub used: u64,
    /// Breakdown by resource category.
    pub breakdown: GasBreakdown,
}

#[derive(Debug, Clone, Default)]
pub struct GasBreakdown {
    /// Gas spent on compute operations (contract steps, predicate evaluation).
    pub compute: u64,
    /// Gas spent on state read operations.
    pub state_reads: u64,
    /// Gas spent on state write operations.
    pub state_writes: u64,
    /// Gas spent on signature verification.
    pub sig_verify: u64,
    /// Gas spent on hashing operations.
    pub hashing: u64,
    /// Gas spent on proof construction/verification.
    pub proof: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GasPricing {
    pub tx_base: u64,
    pub compute_step: u64,
    pub state_read: u64,
    pub state_write: u64,
    pub sig_verify: u64,
    pub hash_op: u64,
    pub proof_byte: u64,
    pub payload_byte: u64,
}

/// Legacy default gas costs preserved for compatibility and test fixtures.
/// Live runtime code should prefer `ConsensusParams` as the governing source.
pub mod costs {
    /// Base cost for any transaction (overhead).
    pub const TX_BASE: u64 = 1_000;
    /// Per compute step in contract execution.
    pub const COMPUTE_STEP: u64 = 10;
    /// Per state trie read.
    pub const STATE_READ: u64 = 100;
    /// Per state trie write.
    pub const STATE_WRITE: u64 = 500;
    /// Per signature verification.
    pub const SIG_VERIFY: u64 = 3_000;
    /// Per hash computation.
    pub const HASH_OP: u64 = 50;
    /// Per byte of proof data.
    pub const PROOF_BYTE: u64 = 5;
    /// Per byte of payload data.
    pub const PAYLOAD_BYTE: u64 = 2;
    /// Default per-transaction gas limit.
    pub const DEFAULT_TX_LIMIT: u64 = 1_000_000;
    /// Default per-block gas limit.
    pub const DEFAULT_BLOCK_LIMIT: u64 = 50_000_000;
}

impl Default for GasPricing {
    fn default() -> Self {
        Self::from(&ConsensusParams::default())
    }
}

impl From<&ConsensusParams> for GasPricing {
    fn from(params: &ConsensusParams) -> Self {
        Self {
            tx_base: params.gas_tx_base,
            compute_step: params.gas_compute_step,
            state_read: params.gas_state_read,
            state_write: params.gas_state_write,
            sig_verify: params.gas_sig_verify,
            hash_op: params.gas_hash_op,
            proof_byte: params.gas_proof_byte,
            payload_byte: params.gas_payload_byte,
        }
    }
}

#[derive(Debug, Clone)]
pub enum GasError {
    OutOfGas {
        used: u64,
        limit: u64,
        operation: String,
    },
}

impl std::fmt::Display for GasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GasError::OutOfGas {
                used,
                limit,
                operation,
            } => {
                write!(
                    f,
                    "Out of gas during {}: used {} / limit {}",
                    operation, used, limit
                )
            }
        }
    }
}

impl GasMeter {
    /// Create a new gas meter with the specified limit.
    pub fn new(limit: u64) -> Self {
        Self::with_pricing(limit, GasPricing::default())
    }

    /// Create a gas meter with an explicit pricing table.
    pub fn with_pricing(limit: u64, pricing: GasPricing) -> Self {
        Self {
            limit,
            pricing,
            used: 0,
            breakdown: GasBreakdown::default(),
        }
    }

    /// Create a meter with the default transaction limit.
    pub fn default_tx() -> Self {
        let params = ConsensusParams::default();
        Self::with_pricing(params.default_tx_gas_limit, GasPricing::from(&params))
    }

    /// Charge gas for an operation. Returns error if limit exceeded.
    pub fn charge(&mut self, amount: u64, operation: &str) -> Result<(), GasError> {
        self.used = self.used.saturating_add(amount);
        if self.used > self.limit {
            return Err(GasError::OutOfGas {
                used: self.used,
                limit: self.limit,
                operation: operation.into(),
            });
        }
        Ok(())
    }

    /// Charge for compute steps.
    pub fn charge_compute(&mut self, steps: u64) -> Result<(), GasError> {
        let cost = steps.saturating_mul(self.pricing.compute_step);
        self.breakdown.compute += cost;
        self.charge(cost, "compute")
    }

    /// Charge for a state read.
    pub fn charge_state_read(&mut self) -> Result<(), GasError> {
        self.breakdown.state_reads += self.pricing.state_read;
        self.charge(self.pricing.state_read, "state_read")
    }

    /// Charge for a state write.
    pub fn charge_state_write(&mut self) -> Result<(), GasError> {
        self.breakdown.state_writes += self.pricing.state_write;
        self.charge(self.pricing.state_write, "state_write")
    }

    /// Charge for signature verification.
    pub fn charge_sig_verify(&mut self) -> Result<(), GasError> {
        self.breakdown.sig_verify += self.pricing.sig_verify;
        self.charge(self.pricing.sig_verify, "sig_verify")
    }

    /// Charge for hashing.
    pub fn charge_hash(&mut self) -> Result<(), GasError> {
        self.breakdown.hashing += self.pricing.hash_op;
        self.charge(self.pricing.hash_op, "hash")
    }

    /// Charge for proof data (per byte).
    pub fn charge_proof_bytes(&mut self, bytes: u64) -> Result<(), GasError> {
        let cost = bytes.saturating_mul(self.pricing.proof_byte);
        self.breakdown.proof += cost;
        self.charge(cost, "proof_data")
    }

    /// Charge base transaction overhead.
    pub fn charge_tx_base(&mut self) -> Result<(), GasError> {
        self.charge(self.pricing.tx_base, "tx_base")
    }

    /// Charge for payload bytes.
    pub fn charge_payload(&mut self, bytes: u64) -> Result<(), GasError> {
        self.charge(bytes.saturating_mul(self.pricing.payload_byte), "payload")
    }

    /// Gas remaining before limit.
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// Convert gas used to a fee amount using a gas price.
    /// gas_used is a plain integer; gas_price is fixed-point TensionValue.
    /// fee = gas_used * gas_price (result is fixed-point).
    pub fn compute_fee(&self, gas_price: TensionValue) -> TensionValue {
        TensionValue((self.used as i128).saturating_mul(gas_price.raw()))
    }
}

/// Block-level gas accumulator.
#[derive(Debug, Clone)]
pub struct BlockGasMeter {
    pub limit: u64,
    pub used: u64,
    pub tx_count: u32,
}

impl BlockGasMeter {
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            used: 0,
            tx_count: 0,
        }
    }

    pub fn default_block() -> Self {
        Self::new(ConsensusParams::default().default_block_gas_limit)
    }

    /// Check if a transaction with this gas cost fits in the block.
    pub fn can_fit(&self, tx_gas: u64) -> bool {
        self.used.saturating_add(tx_gas) <= self.limit
    }

    /// Record a transaction's gas usage.
    pub fn record_tx(&mut self, tx_gas: u64) {
        self.used = self.used.saturating_add(tx_gas);
        self.tx_count = self.tx_count.saturating_add(1);
    }

    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// Block utilization as a percentage (0-100).
    pub fn utilization_pct(&self) -> u8 {
        if self.limit == 0 {
            return 100;
        }
        ((self.used as u128 * 100) / self.limit as u128).min(100) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_meter_basic() {
        let mut meter = GasMeter::new(10_000);
        assert!(meter.charge_tx_base().is_ok());
        assert_eq!(meter.used, costs::TX_BASE);
        assert_eq!(meter.remaining(), 10_000 - costs::TX_BASE);
    }

    #[test]
    fn test_gas_meter_out_of_gas() {
        let mut meter = GasMeter::new(100);
        assert!(meter.charge_tx_base().is_err()); // TX_BASE = 1000 > 100
    }

    #[test]
    fn test_gas_breakdown() {
        let mut meter = GasMeter::new(100_000);
        meter.charge_compute(10).unwrap();
        meter.charge_state_read().unwrap();
        meter.charge_state_write().unwrap();
        meter.charge_sig_verify().unwrap();

        assert_eq!(meter.breakdown.compute, 10 * costs::COMPUTE_STEP);
        assert_eq!(meter.breakdown.state_reads, costs::STATE_READ);
        assert_eq!(meter.breakdown.state_writes, costs::STATE_WRITE);
        assert_eq!(meter.breakdown.sig_verify, costs::SIG_VERIFY);
    }

    #[test]
    fn test_compute_fee() {
        let mut meter = GasMeter::new(100_000);
        meter.charge(10_000, "test").unwrap();

        let gas_price = TensionValue::from_integer(2); // 2 tokens per gas unit.
        let fee = meter.compute_fee(gas_price);
        assert_eq!(fee, TensionValue::from_integer(20_000));
    }

    #[test]
    fn test_block_gas_meter() {
        let mut block = BlockGasMeter::default_block();
        assert!(block.can_fit(1_000_000));
        block.record_tx(1_000_000);
        assert_eq!(block.tx_count, 1);
        assert_eq!(block.utilization_pct(), 2); // 1M / 50M = 2%
    }

    #[test]
    fn test_block_gas_limit_enforced() {
        let mut block = BlockGasMeter::new(100);
        assert!(block.can_fit(50));
        block.record_tx(50);
        assert!(block.can_fit(50));
        block.record_tx(50);
        assert!(!block.can_fit(1)); // Full.
    }

    #[test]
    fn test_gas_meter_uses_custom_pricing() {
        let pricing = GasPricing {
            tx_base: 7,
            compute_step: 2,
            state_read: 3,
            state_write: 5,
            sig_verify: 11,
            hash_op: 13,
            proof_byte: 17,
            payload_byte: 19,
        };
        let mut meter = GasMeter::with_pricing(10_000, pricing);

        meter.charge_tx_base().unwrap();
        meter.charge_payload(2).unwrap();
        meter.charge_sig_verify().unwrap();
        meter.charge_hash().unwrap();
        meter.charge_compute(4).unwrap();

        assert_eq!(meter.used, 7 + 38 + 11 + 13 + 8);
        assert_eq!(meter.breakdown.compute, 8);
        assert_eq!(meter.breakdown.sig_verify, 11);
        assert_eq!(meter.pricing.payload_byte, 19);
    }

    #[test]
    fn test_default_tx_meter_matches_consensus_defaults() {
        let params = ConsensusParams::default();
        let meter = GasMeter::default_tx();

        assert_eq!(meter.limit, params.default_tx_gas_limit);
        assert_eq!(meter.pricing, GasPricing::from(&params));
    }

    #[test]
    fn test_default_block_meter_matches_consensus_defaults() {
        let params = ConsensusParams::default();
        let meter = BlockGasMeter::default_block();

        assert_eq!(meter.limit, params.default_block_gas_limit);
        assert_eq!(meter.used, 0);
        assert_eq!(meter.tx_count, 0);
    }
}
