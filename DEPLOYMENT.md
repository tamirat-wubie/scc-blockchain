# SCCGUB Deployment Guide

**Version:** 0.3.0

This guide covers deploying SCCGUB in single-validator and multi-validator configurations. Multi-validator mode
is alpha and not production-hardened yet.

---

## 1. Prerequisites

- **Rust toolchain:** stable (1.80+)
- **OS:** Linux (recommended), Windows, macOS
- **Disk:** 1 GB minimum for block log + snapshots
- **Memory:** 512 MB minimum, 2 GB recommended for large state
- **Network:** TCP port 9000 (configurable) for P2P

```bash
# Build
cargo build --release --workspace

# Verify
cargo test --workspace
```

---

## 2. Single-Validator Deployment

### Initialize

```bash
# Create data directory and generate encrypted validator key
cargo run --release --bin sccgub-node -- init --data-dir ./chain-data

# Set passphrase via environment (preferred over config file)
export SCCGUB_PASSPHRASE="your-strong-passphrase-here"
```

### Run

```bash
cargo run --release --bin sccgub-node -- run \
  --data-dir ./chain-data \
  --api-port 3000
```

The node will:
- Load or create genesis block
- Start the REST API on port 3000
- Produce blocks from mempool transactions
- Save blocks and periodic snapshots to disk

### Submit Transactions

```bash
# Write data to state
cargo run --release --bin sccgub-node -- submit-tx \
  --data-dir ./chain-data \
  --key data/mykey \
  --value myvalue

# Produce a block manually
cargo run --release --bin sccgub-node -- produce-block \
  --data-dir ./chain-data

# View chain state
cargo run --release --bin sccgub-node -- show-chain \
  --data-dir ./chain-data
```

---

## 3. Multi-Validator Deployment

### Generate Keys for Each Validator

On each validator machine:

```bash
cargo run --release --bin sccgub-node -- init --data-dir ./validator-data
```

Record each validator's public key (shown during init).

### Configure Network

Create `config.toml` on each validator:

```toml
[chain]
genesis_supply = 1000000
max_txs_per_block = 1000
initial_finality_mode = "bft:2"

[network]
enable = true
bind = "0.0.0.0"
port = 9000
# List all validator public keys (hex)
validators = [
  "aabbcc...11",  # Validator 1 public key
  "ddeeff...22",  # Validator 2 public key
  "112233...33",  # Validator 3 public key
]
# Seed peers (other validators' addresses)
peers = [
  "validator2.example.com:9000",
  "validator3.example.com:9000",
]
block_interval_ms = 5000
round_timeout_ms = 4000
max_rounds = 3
min_connected_peers = 2
max_same_subnet_pct = 50

[storage]
state_store_enabled = true
state_store_authoritative = true
state_store_dir = "state_db"

[validator]
# SECURITY: Use SCCGUB_PASSPHRASE env var instead
key_passphrase = ""

[api]
enable = true
port = 3000
```

### Start Each Validator

```bash
export SCCGUB_PASSPHRASE="validator-specific-passphrase"
cargo run --release --bin sccgub-node -- run \
  --data-dir ./validator-data \
  --config config.toml
```

### Verify Consensus

Check that validators are connected and producing blocks:

```bash
curl http://localhost:3000/api/v1/status
curl http://localhost:3000/api/v1/health
curl http://localhost:3000/api/v1/governance/params
```

---

## 4. Key Management

### Security Tiers

| Method | Security | Use Case |
|---|---|---|
| `SCCGUB_PASSPHRASE` env var | **Recommended** | Production |
| `config.toml` passphrase field | Development only | Testing |
| `--passphrase` CLI flag | Visible in process list | Never in production |

### Key Storage

Validator keys are encrypted with:
- **KDF:** Argon2id (memory-hard, GPU-resistant)
- **AEAD:** ChaCha20-Poly1305 (256-bit key)
- **Salt:** 32 bytes random per bundle
- **Nonce:** 12 bytes random per encryption

Keys are stored in `{data-dir}/validator.key` as an encrypted JSON bundle.

### Key Rotation

Key rotation requires a Constitutional governance proposal:

```bash
# Submit key rotation proposal
cargo run --release --bin sccgub-node -- submit-tx \
  --key norms/governance/params/propose \
  --value "validators.add=<new_pubkey_hex>"
```

---

## 5. Monitoring

### Health Endpoint

```bash
curl http://localhost:3000/api/v1/health
```

Returns: block height, finality gap, peer count, consensus phase.

### Key Metrics to Watch

| Metric | Healthy Range | Alert Threshold |
|---|---|---|
| Finality gap | 0-2 blocks | >5 blocks |
| Block production interval | 4-6 seconds | >15 seconds |
| Mempool size | 0-100 txs | >500 txs |
| Connected peers | >= min_connected_peers | <min_connected_peers |
| Slashing events | 0 | Any new event |

### Structured Logging

The node uses `tracing` for structured logging. Key log levels:
- `ERROR`: Invariant violations, consensus failures
- `WARN`: Rejected proposals, slashing events, peer disconnects
- `INFO`: Block production, finality advancement, governance activation

---

## 6. Backup and Recovery

### Block Log

Blocks are saved to `{data-dir}/blocks/` as individual JSON files with atomic write-then-rename. No special backup procedure needed — copy the directory.

### Snapshots

Periodic snapshots are saved to `{data-dir}/state/`. Each snapshot contains the full state trie, balances, treasury, slashing, governance limits, finality config, and proposals.

### Recovery Options

| Scenario | Recovery |
|---|---|
| Process crash | Restart — loads from snapshot + replays remaining blocks |
| Corrupted snapshot | Delete snapshot — full replay from block log |
| Corrupted blocks | Restore from backup or re-sync from peers |
| Lost validator key | Generate new key + governance proposal to rotate |

### Full Restore

```bash
# From block log (slow but complete)
cargo run --release --bin sccgub-node -- run --data-dir ./chain-data

# From snapshot (fast)
# Automatic — the node loads the latest valid snapshot on startup
```

---

## 7. Governance Operations

### Submit a Parameter Change

```bash
# Propose changing max_consecutive_proposals to 20
cargo run --release --bin sccgub-node -- submit-tx \
  --key norms/governance/params/propose \
  --value "governance.max_consecutive_proposals=20"
```

### Governable Parameters

| Key | Type | Bounds |
|---|---|---|
| governance.max_consecutive_proposals | u32 | >= 1 |
| governance.max_actions_per_agent_pct | u32 | 1-100 |
| governance.safety_change_min_signers | u32 | >= 1 |
| governance.authority_cooldown_epochs | u64 | <= 1000 |
| finality.confirmation_depth | u64 | >= 1 |
| finality.max_finality_ms | u64 | 1-300000 |
| finality.target_block_time_ms | u64 | >= 1 |
| validators.add | hex pubkey | 32 bytes |
| validators.remove | hex pubkey | 32 bytes |

### Proposal Lifecycle

1. **Submit** — agent proposes change
2. **Vote** — validators vote (governance.safety_change_min_signers required)
3. **Finalize** — voting period ends, proposal accepted/rejected
4. **Timelock** — ordinary: 50 blocks, constitutional: 200 blocks
5. **Activate** — parameter change takes effect

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "Not proposer for height" | Validator set configured but this node isn't the designated proposer for this height | Normal — wait for your turn in round-robin |
| "Consensus epoch mismatch" | Peer is on a different validator set version | Verify all validators have the same config |
| "CPoG validation failed" | Imported block doesn't match local state | Check for chain fork; may need to re-sync |
| "Nonce sequence violation" | Transaction nonce doesn't match expected | Query current nonce via API before submitting |
| LNK1104 on Windows | File lock during build | Run `cargo clean` or use separate target dirs |
