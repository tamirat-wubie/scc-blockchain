use crate::responses::ErrorCode;

/// Render the versioned OpenAPI contract from Rust as the source of truth.
pub fn render_openapi_yaml() -> String {
    let mut yaml = String::new();
    yaml.push_str(
        r##"openapi: 3.1.0
info:
  title: SCCGUB API
  version: "##,
    );
    yaml.push_str(env!("CARGO_PKG_VERSION"));
    yaml.push_str(
        r##"
  description: >
    Versioned REST contract for the SCCGUB single-node reference runtime.
    Legacy `/api/*` routes remain available for backward compatibility, but
    `/api/v1/*` is the supported integration surface.
servers:
  - url: http://localhost:3000
paths:
  /api/v1/status:
    get:
      operationId: getStatus
      summary: Chain summary
      responses:
        "200":
          description: Latest chain status
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ChainStatusApiResponse"
  /api/v1/status/schema:
    get:
      operationId: getStatusSchema
      summary: JSON schema for status output
      responses:
        "200":
          description: Status schema
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/SchemaApiResponse"
  /api/v1/openapi:
    get:
      operationId: getOpenApiSpec
      summary: OpenAPI spec
      responses:
        "200":
          description: OpenAPI YAML
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/OpenApiSpecApiResponse"
  /api/v1/health:
    get:
      operationId: getHealth
      summary: Runtime health and finality SLA
      responses:
        "200":
          description: Health snapshot
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/HealthApiResponse"
  /api/v1/finality/certificates:
    get:
      operationId: getFinalityCertificates
      summary: Finality safety certificates
      responses:
        "200":
          description: Finality certificates
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/FinalityCertificatesApiResponse"
  /api/v1/governance/params:
    get:
      operationId: getGovernanceParams
      summary: Governed parameter values
      responses:
        "200":
          description: Governance parameters
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/GovernanceParamsApiResponse"
  /api/v1/governance/params/schema:
    get:
      operationId: getGovernanceParamsSchema
      summary: JSON schema for governed parameters
      responses:
        "200":
          description: Governed schema
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/SchemaApiResponse"
  /api/v1/governance/proposals:
    get:
      operationId: getGovernanceProposals
      summary: Governance proposal registry summary
      parameters:
        - name: offset
          in: query
          required: false
          schema:
            type: integer
            minimum: 0
        - name: limit
          in: query
          required: false
          schema:
            type: integer
            minimum: 1
            maximum: 1000
        - name: status
          in: query
          required: false
          schema:
            type: string
            enum:
              - Submitted
              - Voting
              - Accepted
              - Rejected
              - Timelocked
              - Activated
              - Expired
      responses:
        "200":
          description: Governance proposals
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/GovernanceProposalsApiResponse"
        "400":
          description: Invalid query parameters
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
  /api/v1/network/peers:
    get:
      operationId: getNetworkPeers
      summary: Peer network stats
      responses:
        "200":
          description: Peer stats
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/NetworkPeersApiResponse"
  /api/v1/network/peers/{validator_id}:
    get:
      operationId: getNetworkPeer
      summary: Peer detail by validator id
      parameters:
        - name: validator_id
          in: path
          required: true
          schema:
            type: string
            pattern: "^[0-9a-fA-F]{64}$"
      responses:
        "400":
          description: Invalid validator ID
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
        "200":
          description: Peer detail
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/NetworkPeerApiResponse"
        "404":
          description: Validator not found
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
  /api/v1/slashing:
    get:
      operationId: getSlashingSummary
      summary: Slashing summary and events
      responses:
        "200":
          description: Slashing summary
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/SlashingSummaryApiResponse"
  /api/v1/slashing/{validator_id}:
    get:
      operationId: getSlashingValidator
      summary: Slashing detail for a validator
      parameters:
        - name: validator_id
          in: path
          required: true
          schema:
            type: string
            pattern: "^[0-9a-fA-F]{64}$"
      responses:
        "400":
          description: Invalid validator ID
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
        "200":
          description: Slashing detail
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/SlashingValidatorApiResponse"
        "404":
          description: Validator not found
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
  /api/v1/slashing/evidence:
    get:
      operationId: getSlashingEvidence
      summary: Equivocation evidence (all validators)
      responses:
        "200":
          description: Equivocation evidence list
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/SlashingEvidenceApiResponse"
  /api/v1/slashing/evidence/{validator_id}:
    get:
      operationId: getSlashingEvidenceForValidator
      summary: Equivocation evidence for a validator
      parameters:
        - name: validator_id
          in: path
          required: true
          schema:
            type: string
            pattern: "^[0-9a-fA-F]{64}$"
      responses:
        "400":
          description: Invalid validator ID
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
        "200":
          description: Equivocation evidence list
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/SlashingEvidenceApiResponse"
        "404":
          description: Validator not found
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
  /api/v1/block/{height}:
    get:
      operationId: getBlock
      summary: Block detail by height
      parameters:
        - name: height
          in: path
          required: true
          schema:
            type: integer
            format: uint64
      responses:
        "400":
          description: Invalid height parameter
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
        "200":
          description: Block found
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/BlockApiResponse"
        "404":
          description: Block not found
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
  /api/v1/block/{height}/receipts:
    get:
      operationId: getBlockReceipts
      summary: Receipts for a specific block
      parameters:
        - name: height
          in: path
          required: true
          schema:
            type: integer
            format: uint64
      responses:
        "400":
          description: Invalid height parameter
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
        "200":
          description: Block receipts found
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/BlockReceiptsApiResponse"
        "404":
          description: Block not found
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
  /api/v1/state:
    get:
      operationId: getState
      summary: Paginated world state
      parameters:
        - name: offset
          in: query
          required: false
          schema:
            type: integer
            minimum: 0
        - name: limit
          in: query
          required: false
          schema:
            type: integer
            minimum: 1
            maximum: 1000
      responses:
        "400":
          description: Invalid pagination parameter
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
        "200":
          description: Paginated state page
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/PaginatedStateApiResponse"
  /api/v1/tx/submit:
    post:
      operationId: submitTransaction
      summary: Submit a signed transaction
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/SubmitTransactionRequest"
      responses:
        "202":
          description: Transaction accepted into the pending pool
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/TxSubmitApiResponse"
        "400":
          description: Submission rejected
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
        "409":
          description: Duplicate or replayed submission
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
        "413":
          description: Request body too large (max 1 MiB)
        "503":
          description: Pending pool full
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
  /api/v1/governance/params/propose:
    post:
      operationId: submitGovernanceParam
      summary: Submit a signed governance parameter proposal
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/SubmitGovernanceParamRequest"
      responses:
        "202":
          description: Proposal accepted into the pending pool
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/TxSubmitApiResponse"
        "400":
          description: Submission rejected
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
        "409":
          description: Duplicate or replayed submission
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
        "413":
          description: Request body too large (max 1 MiB)
        "503":
          description: Pending pool full
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
  /api/v1/governance/proposals/vote:
    post:
      operationId: submitGovernanceVote
      summary: Submit a signed governance proposal vote
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/SubmitGovernanceVoteRequest"
      responses:
        "202":
          description: Vote accepted into the pending pool
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/TxSubmitApiResponse"
        "400":
          description: Submission rejected
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
        "409":
          description: Duplicate or replayed submission
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
        "413":
          description: Request body too large (max 1 MiB)
        "503":
          description: Pending pool full
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
  /api/v1/tx/{tx_id}:
    get:
      operationId: getTransaction
      summary: Transaction detail by hex id
      parameters:
        - name: tx_id
          in: path
          required: true
          schema:
            type: string
            pattern: "^[0-9a-fA-F]{64}$"
      responses:
        "200":
          description: Transaction found
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/TxDetailApiResponse"
        "400":
          description: Invalid tx id
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
        "404":
          description: Transaction not found
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
  /api/v1/receipt/{tx_id}:
    get:
      operationId: getReceipt
      summary: Receipt detail by transaction id
      parameters:
        - name: tx_id
          in: path
          required: true
          schema:
            type: string
            pattern: "^[0-9a-fA-F]{64}$"
      responses:
        "200":
          description: Receipt found
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ReceiptApiResponse"
        "400":
          description: Invalid tx id
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
        "404":
          description: Receipt not found
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorApiResponse"
components:
  schemas:
    ErrorCode:
      type: string
      enum:
"##,
    );
    for error_code in ErrorCode::ALL {
        yaml.push_str("        - ");
        yaml.push_str(error_code.as_str());
        yaml.push('\n');
    }
    yaml.push_str(
        r##"    ApiError:
      type: object
      required: [code, message]
      properties:
        code:
          $ref: "#/components/schemas/ErrorCode"
        message:
          type: string
    SchemaResponse:
      type: object
      required: [$schema, title, type, properties]
      properties:
        $schema: { type: string }
        title: { type: string }
        type: { type: string }
        properties:
          type: object
    OpenApiSpecResponse:
      type: object
      required: [spec]
      properties:
        spec: { type: string }
    ChainStatusResponse:
      type: object
      required:
        [chain_id, height, block_count, total_transactions, state_root, finalized_height, finality_gap, tension, emergency_mode, active_norm_count, finality_expected_ms, finality_sla_met, mfidel_seal, governed_parameters, governed_parameter_values, bandwidth_inbound_bytes, bandwidth_outbound_bytes]
      properties:
        chain_id: { type: string }
        height: { type: integer, format: uint64 }
        block_count: { type: integer, format: uint64 }
        total_transactions: { type: integer, format: uint64 }
        state_root: { type: string }
        finalized_height: { type: integer, format: uint64 }
        finality_gap: { type: integer, format: uint64 }
        tension: { type: string }
        emergency_mode: { type: boolean }
        active_norm_count: { type: integer, format: uint32 }
        finality_expected_ms: { type: integer, format: uint64 }
        finality_sla_met: { type: boolean }
        mfidel_seal: { type: string }
        governed_parameters:
          type: array
          items: { type: string }
        governed_parameter_values:
          type: object
          additionalProperties:
            type: string
        bandwidth_inbound_bytes: { type: integer, format: uint64 }
        bandwidth_outbound_bytes: { type: integer, format: uint64 }
    GovernanceParamsResponse:
      type: object
      required: [governance_limits, finality_config]
      properties:
        governance_limits:
          $ref: "#/components/schemas/GovernanceLimits"
        finality_config:
          $ref: "#/components/schemas/FinalityConfig"
    GovernanceProposalSummary:
      type: object
      required: [id, status, votes_for, votes_against, timelock_until, submitted_at]
      properties:
        id: { type: string }
        status: { type: string }
        votes_for: { type: integer, format: uint32 }
        votes_against: { type: integer, format: uint32 }
        timelock_until: { type: integer, format: uint64 }
        submitted_at: { type: integer, format: uint64 }
    GovernanceProposalsResponse:
      type: object
      required: [count, proposals]
      properties:
        count: { type: integer, format: uint64 }
        proposals:
          type: array
          items:
            $ref: "#/components/schemas/GovernanceProposalSummary"
    GovernanceLimits:
      type: object
      required:
        [max_actions_per_agent_pct, safety_change_min_signers, genesis_change_min_signers, max_consecutive_proposals, max_authority_term_epochs, authority_cooldown_epochs]
      properties:
        max_actions_per_agent_pct: { type: integer, format: uint32 }
        safety_change_min_signers: { type: integer, format: uint32 }
        genesis_change_min_signers: { type: integer, format: uint32 }
        max_consecutive_proposals: { type: integer, format: uint32 }
        max_authority_term_epochs: { type: integer, format: uint64 }
        authority_cooldown_epochs: { type: integer, format: uint64 }
    FinalityConfig:
      type: object
      required: [confirmation_depth, max_finality_ms, target_block_time_ms]
      properties:
        confirmation_depth: { type: integer, format: uint64 }
        max_finality_ms: { type: integer, format: uint64 }
        target_block_time_ms: { type: integer, format: uint64 }
    NetworkPeerResponse:
      type: object
      required:
        [address, score, violations, state, inbound_bytes, outbound_bytes, last_seen_ms]
      properties:
        address: { type: string }
        validator_id:
          type: string
          nullable: true
        score: { type: integer, format: int32 }
        violations: { type: integer, format: uint32 }
        state: { type: string }
        inbound_bytes: { type: integer, format: uint64 }
        outbound_bytes: { type: integer, format: uint64 }
        last_seen_ms: { type: integer, format: uint64 }
    NetworkPeersResponse:
      type: object
      required: [count, peers]
      properties:
        count: { type: integer, format: uint64 }
        peers:
          type: array
          items:
            $ref: "#/components/schemas/NetworkPeerResponse"
    TransactionSummary:
      type: object
      required: [tx_id, kind, target, purpose, actor, nonce]
      properties:
        tx_id: { type: string }
        kind: { type: string }
        target: { type: string }
        purpose: { type: string }
        actor: { type: string }
        nonce:
          type: integer
          format: uint128
          description: JSON integer encoded from a Rust u128.
    BlockResponse:
      type: object
      required:
        [height, block_id, parent_id, state_root, transition_root, mfidel_seal, transaction_count, receipt_count, tension_before, tension_after, validator_id, governance_limits, finality_config, transactions]
      properties:
        height: { type: integer, format: uint64 }
        block_id: { type: string }
        parent_id: { type: string }
        state_root: { type: string }
        transition_root: { type: string }
        mfidel_seal: { type: string }
        transaction_count: { type: integer, format: uint32 }
        receipt_count: { type: integer }
        tension_before: { type: string }
        tension_after: { type: string }
        validator_id: { type: string }
        governance_limits:
          $ref: "#/components/schemas/GovernanceLimits"
        finality_config:
          $ref: "#/components/schemas/FinalityConfig"
        transactions:
          type: array
          items:
            $ref: "#/components/schemas/TransactionSummary"
    StateEntry:
      type: object
      required: [key, value]
      properties:
        key: { type: string }
        value: { type: string, description: Hex-encoded value bytes. }
    PaginatedStateResponse:
      type: object
      required: [entries, total, offset, limit]
      properties:
        entries:
          type: array
          items:
            $ref: "#/components/schemas/StateEntry"
        total: { type: integer }
        offset: { type: integer }
        limit: { type: integer }
    SlashingEventResponse:
      type: object
      required: [validator_id, violation, penalty, epoch, evidence]
      properties:
        validator_id: { type: string }
        violation: { type: string }
        penalty: { type: string }
        epoch: { type: integer, format: uint64 }
        evidence:
          type: object
          additionalProperties: true
    SlashingSummaryResponse:
      type: object
      required: [total_events, total_removed, removed_validators, events]
      properties:
        total_events: { type: integer, format: uint64 }
        total_removed: { type: integer, format: uint64 }
        removed_validators:
          type: array
          items: { type: string }
        events:
          type: array
          items:
            $ref: "#/components/schemas/SlashingEventResponse"
    SlashingValidatorResponse:
      type: object
      required: [validator_id, stake, removed, events]
      properties:
        validator_id: { type: string }
        stake: { type: string }
        removed: { type: boolean }
        events:
          type: array
          items:
            $ref: "#/components/schemas/SlashingEventResponse"
    SlashingEvidenceResponse:
      type: object
      required: [validator_id, height, round, vote_type, block_hash_a, block_hash_b, epoch]
      properties:
        validator_id: { type: string }
        height: { type: integer, format: uint64 }
        round: { type: integer, format: uint32 }
        vote_type: { type: string }
        block_hash_a: { type: string }
        block_hash_b: { type: string }
        epoch: { type: integer, format: uint64 }
    SlashingEvidenceListResponse:
      type: object
      required: [count, evidence]
      properties:
        count: { type: integer, format: uint64 }
        evidence:
          type: array
          items:
            $ref: "#/components/schemas/SlashingEvidenceResponse"
    HealthResponse:
      type: object
      required:
        [status, height, finalized_height, finality_gap, sla_met, blocks_produced, total_transactions, state_entries, causal_edges]
      properties:
        status: { type: string }
        height: { type: integer, format: uint64 }
        finalized_height: { type: integer, format: uint64 }
        finality_gap: { type: integer, format: uint64 }
        sla_met: { type: boolean }
        blocks_produced: { type: integer, format: uint64 }
        total_transactions: { type: integer, format: uint64 }
        state_entries: { type: integer, format: uint64 }
        causal_edges: { type: integer, format: uint64 }
    SafetyCertificateSignatureResponse:
      type: object
      required: [validator_id, signature]
      properties:
        validator_id: { type: string }
        signature: { type: string }
    SafetyCertificateResponse:
      type: object
      required:
        [chain_id, epoch, height, block_hash, round, quorum, validator_count, precommit_signatures]
      properties:
        chain_id: { type: string }
        epoch: { type: integer, format: uint64 }
        height: { type: integer, format: uint64 }
        block_hash: { type: string }
        round: { type: integer, format: uint32 }
        quorum: { type: integer, format: uint32 }
        validator_count: { type: integer, format: uint32 }
        precommit_signatures:
          type: array
          items:
            $ref: "#/components/schemas/SafetyCertificateSignatureResponse"
    FinalityCertificatesResponse:
      type: object
      required: [count, certificates]
      properties:
        count: { type: integer, format: uint64 }
        certificates:
          type: array
          items:
            $ref: "#/components/schemas/SafetyCertificateResponse"
    TxDetailResponse:
      type: object
      required: [tx_id, block_height, block_id, kind, target, purpose, actor, nonce]
      properties:
        tx_id: { type: string }
        block_height: { type: integer, format: uint64 }
        block_id: { type: string }
        kind: { type: string }
        target: { type: string }
        purpose: { type: string }
        actor: { type: string }
        nonce:
          type: integer
          format: uint128
          description: JSON integer encoded from a Rust u128.
    ReceiptSummary:
      type: object
      required: [tx_id, verdict, compute_steps, state_reads, state_writes, phi_phase_reached]
      properties:
        tx_id: { type: string }
        verdict: { type: string }
        compute_steps: { type: integer, format: uint64 }
        state_reads: { type: integer, format: uint32 }
        state_writes: { type: integer, format: uint32 }
        phi_phase_reached: { type: integer, format: uint8 }
    BlockReceiptsResponse:
      type: object
      required: [height, receipt_count, receipts]
      properties:
        height: { type: integer, format: uint64 }
        receipt_count: { type: integer }
        receipts:
          type: array
          items:
            $ref: "#/components/schemas/ReceiptSummary"
    SubmitTransactionRequest:
      type: object
      required: [tx_hex]
      properties:
        tx_hex:
          type: string
          description: Hex-encoded bincode-serialized SymbolicTransition.
    SubmitGovernanceParamRequest:
      type: object
      required: [tx_hex]
      properties:
        tx_hex:
          type: string
          description: Hex-encoded bincode-serialized SymbolicTransition.
    SubmitGovernanceVoteRequest:
      type: object
      required: [tx_hex]
      properties:
        tx_hex:
          type: string
          description: Hex-encoded bincode-serialized SymbolicTransition.
    TxSubmitResponse:
      type: object
      required: [tx_id, status]
      properties:
        tx_id: { type: string }
        status: { type: string }
    ErrorApiResponse:
      type: object
      required: [success, error]
      properties:
        success:
          type: boolean
          const: false
        data:
          nullable: true
        error:
          $ref: "#/components/schemas/ApiError"
    SchemaApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/SchemaResponse"
        error:
          nullable: true
    OpenApiSpecApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/OpenApiSpecResponse"
        error:
          nullable: true
    ChainStatusApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/ChainStatusResponse"
        error:
          nullable: true
    GovernanceParamsApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/GovernanceParamsResponse"
        error:
          nullable: true
    GovernanceProposalsApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/GovernanceProposalsResponse"
        error:
          nullable: true
    NetworkPeersApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/NetworkPeersResponse"
        error:
          nullable: true
    NetworkPeerApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/NetworkPeerResponse"
        error:
          nullable: true
    BlockApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/BlockResponse"
        error:
          nullable: true
    PaginatedStateApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/PaginatedStateResponse"
        error:
          nullable: true
    HealthApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/HealthResponse"
        error:
          nullable: true
    FinalityCertificatesApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/FinalityCertificatesResponse"
        error:
          nullable: true
    SlashingSummaryApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/SlashingSummaryResponse"
        error:
          nullable: true
    SlashingValidatorApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/SlashingValidatorResponse"
        error:
          nullable: true
    SlashingEvidenceApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/SlashingEvidenceListResponse"
        error:
          nullable: true
    TxDetailApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/TxDetailResponse"
        error:
          nullable: true
    ReceiptApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/ReceiptSummary"
        error:
          nullable: true
    BlockReceiptsApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/BlockReceiptsResponse"
        error:
          nullable: true
    TxSubmitApiResponse:
      type: object
      required: [success, data]
      properties:
        success:
          type: boolean
          const: true
        data:
          $ref: "#/components/schemas/TxSubmitResponse"
        error:
          nullable: true
"##,
    );
    yaml
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generated_openapi_matches_checked_in_artifact() {
        let generated = render_openapi_yaml().replace("\r\n", "\n");
        let checked_in = include_str!("../openapi.yaml").replace("\r\n", "\n");
        assert_eq!(generated, checked_in);
    }
}
