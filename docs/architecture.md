# Architecture Guide

This guide covers the MPC Agent Wallet SDK architecture, design decisions and how components work together.

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Application Layer                              │
├───────────────────┬──────────────────┬─────────────────┬────────────────────┤
│   AI Agent App    │   User Mobile    │ Recovery Portal │   DeFi Dashboard   │
│                   │      App         │                 │                    │
└─────────┬─────────┴────────┬─────────┴────────┬────────┴──────────┬─────────┘
          │                  │                  │                   │
┌─────────┴──────────────────┴──────────────────┴───────────────────┴─────────┐
│                                SDK Layer                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐           │
│  │  TypeScript SDK  │  │    Python SDK    │  │   WASM Bindings  │           │
│  │  (@mpc-wallet/   │  │   (mpc-wallet)   │  │                  │           │
│  │      sdk)        │  │                  │  │                  │           │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘           │
└───────────┼─────────────────────┼─────────────────────┼─────────────────────┘
            │                     │                     │
┌───────────┴─────────────────────┴─────────────────────┴─────────────────────┐
│                              Rust Core Layer                                │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   DKLs23     │  │    Policy    │  │  Key Share   │  │    Chain     │     │
│  │  MPC Engine  │  │    Engine    │  │   Storage    │  │   Adapters   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────────────────────┘
            │                     │                     │
┌───────────┴─────────────────────┴─────────────────────┴─────────────────────┐
│                           Infrastructure Layer                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Message    │  │   Approval   │  │   Webhook    │  │    Smart     │     │
│  │    Relay     │  │   Service    │  │   Service    │  │  Contracts   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. MPC Engine (DKLs23)

The cryptographic core implements the DKLs23 threshold ECDSA protocol.

```rust
// crates/mpc-wallet-core/src/
├── keygen/
│   ├── mod.rs          // Key generation coordinator
│   ├── dkg.rs          // Distributed Key Generation protocol
│   ├── messages.rs     // DKG protocol messages
│   └── refresh.rs      // Proactive share refresh
├── sign/
│   ├── mod.rs          // Signing coordinator
│   ├── dsg.rs          // Distributed Signature Generation
│   └── messages.rs     // DSG protocol messages
└── mpc/
    ├── mod.rs          // MPC coordination traits
    └── memory.rs       // In-memory relay for testing
```

**Key Features:**
- **Threshold**: 2-of-3 parties required for signing
- **Protocol**: DKLs23 (asymptotically optimal threshold ECDSA)
- **Curve**: secp256k1 (Ethereum/Bitcoin compatible)
- **Security**: UC-secure in the random oracle model

### 2. Policy Engine

Pre-signing policy enforcement layer.

```rust
pub struct PolicyEngine {
    config: PolicyConfig,
    spending_tracker: SpendingTracker,
}

pub struct PolicyConfig {
    spending_limits: HashMap<ChainType, SpendingLimits>,
    whitelist: HashSet<String>,
    blacklist: HashSet<String>,
    time_bounds: Option<TimeBounds>,
    contract_restrictions: ContractRestriction,
    additional_approval_threshold: Option<u128>,
}

pub enum PolicyDecision {
    Approved,
    Rejected { reason: String },
    RequiresAdditionalApproval { reason: String },
}
```

**Supported Policies:**

| Policy | Description |
|--------|-------------|
| Spending Limits | Per-transaction, daily, weekly limits |
| Address Whitelist | Only allow specific recipients |
| Address Blacklist | Block known malicious addresses |
| Time Bounds | Restrict to specific hours/days |
| Contract Restrictions | Limit contract interactions by selector |
| Additional Approval | High-value txs require recovery guardian |

### 3. Chain Adapters

A common interface that works across different blockchains.

```rust
#[async_trait]
pub trait ChainAdapter: Send + Sync {
    fn chain_type(&self) -> ChainType;
    async fn get_balance(&self, address: &str) -> Result<Balance>;
    async fn build_transaction(&self, params: TxParams) -> Result<UnsignedTx>;
    async fn broadcast(&self, signed_tx: &SignedTx) -> Result<TxHash>;
    fn derive_address(&self, public_key: &[u8]) -> Result<String>;
}
```

**Implemented Adapters:**

| Chain | Features |
|-------|----------|
| EVM | EIP-1559, ERC-4337, RPC failover |
| Solana | Legacy + versioned transactions, priority fees |
| Bitcoin | (Planned) Native SegWit, Taproot |

### 4. Key Share Storage

Encrypted storage interface for key shares.

```rust
#[async_trait]
pub trait KeyShareStore: Send + Sync {
    async fn store(&self, id: &str, share: &EncryptedKeyShare) -> Result<()>;
    async fn load(&self, id: &str) -> Result<EncryptedKeyShare>;
    async fn delete(&self, id: &str) -> Result<()>;
    async fn list(&self) -> Result<Vec<String>>;
}
```

**Security:**
- ChaCha20-Poly1305 AEAD encryption
- Random nonces per encryption
- Password-based key derivation
- File permissions 0600 on Unix

### 5. Message Relay

WebSocket-based relay for MPC protocol coordination.

```rust
pub struct WalletRelayService {
    sessions: SessionManager,
    approvals: ApprovalService,
    webhooks: WebhookService,
    notifications: NotificationService,
}
```

**API Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sessions` | POST | Create signing session |
| `/sessions/:id` | GET | Get session status |
| `/sessions/:id/messages` | POST | Send protocol message |
| `/sessions/:id/approve` | POST | Submit approval |
| `/sessions/:id/stream` | WS | Real-time updates |

## Data Flow

### Key Generation Flow

```
┌─────────┐      ┌─────────┐      ┌─────────┐
│  Agent  │      │  User   │      │Recovery │
└────┬────┘      └────┬────┘      └────┬────┘
     │                │                │
     │    Round 1: Commitments         │
     ├───────────────►│                │
     │◄───────────────┤                │
     ├────────────────┼───────────────►│
     │◄───────────────┼────────────────┤
     │                │                │
     │    Round 2: Key Shares          │
     ├───────────────►│                │
     │◄───────────────┤                │
     ├────────────────┼───────────────►│
     │◄───────────────┼────────────────┤
     │                │                │
     │    Round 3: Verification        │
     ├───────────────►│                │
     │◄───────────────┤                │
     ├────────────────┼───────────────►│
     │◄───────────────┼────────────────┤
     │                │                │
     ▼                ▼                ▼
┌─────────┐      ┌─────────┐      ┌─────────┐
│ Share 1 │      │ Share 2 │      │ Share 3 │
│ Stored  │      │ Stored  │      │ Stored  │
└─────────┘      └─────────┘      └─────────┘
```

### Transaction Signing Flow

```
┌─────────┐      ┌─────────┐      ┌─────────┐      ┌─────────┐
│  Agent  │      │  Relay  │      │  User   │      │  Chain  │
└────┬────┘      └────┬────┘      └────┬────┘      └────┬────┘
     │                │                │                │
     │  1. Build Tx   │                │                │
     ├────────────────┤                │                │
     │                │                │                │
     │  2. Check      │                │                │
     │     Policy     │                │                │
     ├────────────────┤                │                │
     │                │                │                │
     │  3. Request    │                │                │
     │     Approval   │                │                │
     ├───────────────►│  Notify        │                │
     │                ├───────────────►│                │
     │                │                │                │
     │                │  4. Review &   │                │
     │                │     Approve    │                │
     │                │◄───────────────┤                │
     │◄───────────────┤                │                │
     │                │                │                │
     │  5. MPC Sign   │                │                │
     │     (Round 1)  │                │                │
     ├───────────────►│───────────────►│                │
     │◄───────────────┤◄───────────────┤                │
     │                │                │                │
     │  6. MPC Sign   │                │                │
     │     (Round 2+) │                │                │
     ├───────────────►│───────────────►│                │
     │◄───────────────┤◄───────────────┤                │
     │                │                │                │
     │  7. Broadcast  │                │                │
     ├────────────────┼────────────────┼───────────────►│
     │                │                │                │
     │  8. Confirm    │                │                │
     │◄───────────────┼────────────────┼────────────────┤
     │                │                │                │
     ▼                ▼                ▼                ▼
```

## Smart Contract Integration

### ERC-4337 Smart Account

```solidity
contract MpcSmartAccount is ERC4337Account, UUPSUpgradeable {
    // Aggregated MPC public key
    bytes public mpcPublicKey;

    // On-chain policy enforcement
    mapping(address => bool) public whitelist;
    uint256 public dailyLimit;
    uint256 public spentToday;

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        // 1. Verify ECDSA signature from threshold MPC
        // 2. Check on-chain spending limits
        // 3. Verify whitelist (optional)
        // 4. Return validation result
    }
}
```

### Recovery Module

```solidity
contract MpcRecoveryModule {
    uint256 public recoveryDelay = 2 days;

    mapping(address => RecoveryRequest) public pendingRecoveries;

    function initiateRecovery(
        address account,
        bytes calldata newMpcPublicKey
    ) external;

    function executeRecovery(address account) external;
    function cancelRecovery(address account) external;
}
```

## Security Architecture

### Trust Model

```
┌──────────────────────────────────────────────────────────────┐
│                       Trust Boundaries                       │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Trusted Computing Base (TCB)                          │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │  │
│  │  │ MPC Engine  │  │ Key Storage │  │   Policy    │     │  │
│  │  │  (Rust)     │  │ (Encrypted) │  │   Engine    │     │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘     │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Semi-Trusted                                          │  │
│  │  ┌─────────────┐  ┌─────────────┐                      │  │
│  │  │   Relay     │  │  Webhooks   │                      │  │
│  │  │   Service   │  │  (External) │                      │  │
│  │  └─────────────┘  └─────────────┘                      │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Untrusted                                             │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │  │
│  │  │  Network    │  │    RPC      │  │    User     │     │  │
│  │  │ (Internet)  │  │  Providers  │  │   Input     │     │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘     │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Key Share Distribution

| Party | Storage Location | Security |
|-------|-----------------|----------|
| Agent | Server/Cloud | Encrypted at rest, TEE (optional) |
| User | Mobile device | Hardware security module |
| Recovery | Offline/Cold | Air-gapped, multi-sig access |

## Performance Considerations

### Latency Breakdown

| Operation | Typical Latency |
|-----------|----------------|
| Policy Check | < 1ms |
| DKG Round | 50-100ms per party |
| Signing Round | 30-50ms per party |
| Relay RTT | 10-50ms |
| Chain Broadcast | 100ms-2s |

### Optimization Strategies

1. **Parallel Message Processing**: Round messages processed concurrently
2. **Connection Pooling**: Persistent WebSocket connections to relay
3. **Batch Operations**: Multiple signatures in single session
4. **Caching**: Policy evaluation caching for repeated patterns

## Deployment Architectures

### Self-Hosted

```
┌─────────────────────────────────────────────┐
│           Your Infrastructure               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  Agent   │  │  Relay   │  │  Storage │  │
│  │  Server  │  │  Server  │  │   (DB)   │  │
│  └──────────┘  └──────────┘  └──────────┘  │
└─────────────────────────────────────────────┘
```

### Hybrid (Recommended)

```
┌────────────────────┐     ┌────────────────────┐
│  Your Agent Server │     │  Managed Relay     │
│  ┌──────────────┐  │     │  (Cloud Service)   │
│  │ MPC SDK      │  │◄───►│  ┌──────────────┐  │
│  └──────────────┘  │     │  │ High Avail.  │  │
└────────────────────┘     │  │ WebSocket    │  │
                           │  └──────────────┘  │
                           └────────────────────┘
```

## Extension Points

### Custom Policy Rules

```typescript
import { PolicyRule, TransactionRequest, PolicyContext } from '@mpc-wallet/sdk';

class CustomKYCRule implements PolicyRule {
  async evaluate(tx: TransactionRequest, ctx: PolicyContext): PolicyDecision {
    const isKYCVerified = await checkKYC(tx.to);
    if (!isKYCVerified && BigInt(tx.value) > BigInt('10000000000000000000')) {
      return { approved: false, reason: 'Recipient not KYC verified for large transfers' };
    }
    return { approved: true };
  }
}
```

### Custom Notification Channels

```typescript
import { NotificationChannel, ApprovalRequest } from '@mpc-wallet/sdk';

class SlackNotifier implements NotificationChannel {
  async notify(request: ApprovalRequest): Promise<void> {
    await slack.postMessage({
      channel: '#approvals',
      text: `New transaction approval: ${request.tx.value} to ${request.tx.to}`,
    });
  }
}
```

## Related Documentation

- [Security Model](./security-model.md) - Threat model and protections
- [Integration Guide](./integration-guide.md) - AI framework integrations
- [API Reference](./api-reference/) - Full API documentation
