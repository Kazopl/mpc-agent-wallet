# MPC Agent Wallet SDK

A **2-of-3 threshold MPC wallet SDK** built for AI agents. The AI agent can't sign transactions alone - it needs approval from either a user or recovery guardian.

## Key Features

- **2-of-3 Threshold Signing**: AI agent holds 1 share, user holds 1 share, recovery guardian holds 1 share. Any 2 can sign.
- **Policy Engine**: Configurable rules enforced before signing (spending limits, whitelists, time bounds)
- **Rust Core**: High-performance cryptographic operations with WASM compilation support
- **Chain Agnostic**: Works with EVM, Solana and Bitcoin

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         SDK Layer                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │  TypeScript  │  │    Python    │  │     WASM     │       │
│  │     SDK      │  │     SDK      │  │   Bindings   │       │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘       │
└─────────┼─────────────────┼─────────────────┼───────────────┘
          │                 │                 │
┌─────────┴─────────────────┴─────────────────┴───────────────┐
│                        Rust Core                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │  DKLs23 MPC  │  │    Policy    │  │  Key Share   │       │
│  │    Engine    │  │    Engine    │  │   Storage    │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

## Security Model

| Party | Role | Purpose |
|-------|------|---------|
| **Agent** | AI assistant | Initiates transactions |
| **User** | Account owner | Primary approval authority |
| **Recovery** | Guardian | Backup approval for recovery |

**Key Properties:**
- AI agent cannot sign transactions alone
- User maintains full control over their wallet
- Recovery guardian enables wallet recovery without seed phrases
- All transactions pass through configurable policy engine

## Crates

| Crate | Description |
|-------|-------------|
| `mpc-wallet-core` | Core MPC engine, policy enforcement, storage |
| `mpc-wallet-wasm` | WebAssembly bindings for browser/Node.js |
| `mpc-wallet-relay` | Message relay service for MPC coordination |
| `mpc-wallet-cli` | CLI tool for testing and development |

## Packages (SDKs)

| Package | Description |
|---------|-------------|
| `@mpc-wallet/sdk` | TypeScript SDK for Node.js and browsers |
| `mpc-wallet` | Python SDK |

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Kazopl/mpc-agent-wallet.git
cd mpc-agent-wallet

# Build the project
cargo build --release

# Run tests
cargo test
```

### CLI Usage

```bash
# Run local DKG simulation
cargo run --bin mpc-wallet -- keygen

# Show wallet info
cargo run --bin mpc-wallet -- info

# Test policy engine
cargo run --bin mpc-wallet -- test-policy --amount 1.5 --to 0x1234...
```

### Rust API

```rust
use mpc_wallet_core::{
    keygen::run_dkg,
    sign::sign_with_policy,
    policy::{PolicyConfig, PolicyEngine, SpendingLimits},
    mpc::MemoryRelay,
    ChainType, PartyRole, SessionConfig, TransactionRequest,
};

// Configure policy
let policy = PolicyConfig::default()
    .with_spending_limits(
        ChainType::Evm,
        SpendingLimits::with_per_tx(1_000_000_000_000_000_000, "ETH") // 1 ETH
            .daily(10_000_000_000_000_000_000),                         // 10 ETH daily
    )
    .with_whitelist(vec!["0x...".to_string()]);

let engine = PolicyEngine::new(policy);

// Create transaction
let tx = TransactionRequest::new(
    ChainType::Evm,
    "0x...",     // recipient
    "0.5",       // 0.5 ETH
);

// Sign with policy enforcement (requires 2-of-3 parties)
let signature = sign_with_policy(
    &key_share,
    &tx,
    &message_hash,
    &[PartyRole::Agent, PartyRole::User],
    &engine,
    &relay,
).await?;
```

## Policy Engine

The policy engine evaluates transactions before signing:

### Supported Policies

| Policy | Description |
|--------|-------------|
| **Spending Limits** | Per-transaction, daily, weekly limits |
| **Address Whitelist** | Only allow specific recipients |
| **Address Blacklist** | Block specific addresses |
| **Time Bounds** | Restrict to business hours |
| **Contract Restrictions** | Limit allowed contract interactions |

### Example

```rust
use mpc_wallet_core::policy::*;

let policy = PolicyBuilder::new()
    .spending_limits(
        ChainType::Evm,
        SpendingLimits::with_per_tx(10u128.pow(18), "ETH")
            .daily(100 * 10u128.pow(18)),
    )
    .whitelist(["0xUniswap...", "0xAave..."])
    .blacklist(["0xTornado..."])
    .time_bounds(TimeBounds::business_hours())
    .contract_restrictions(
        ContractRestriction::default()
            .allow_contract("0xUniswap...")
            .block_selector("0xa9059cbb") // block raw transfers
    )
    .additional_approval_threshold(50 * 10u128.pow(18)) // >50 ETH needs Recovery
    .build();
```

## Key Share Storage

Key shares are encrypted at rest using ChaCha20-Poly1305:

```rust
use mpc_wallet_core::storage::*;

// Create encrypted storage
let store = FileSystemStore::new("/path/to/shares")?;

// Encrypt and store a key share
let encryption_key = generate_encryption_key();
let encrypted = EncryptedKeyShare::encrypt(&key_share, &encryption_key)?;
store.store("my-wallet", &encrypted).await?;

// Load and decrypt
let encrypted = store.load("my-wallet").await?;
let key_share = encrypted.decrypt(&encryption_key)?;
```

## Development

### Prerequisites

- Rust 1.75+
- For WASM: `wasm-pack`

### Running Tests

```bash
# All tests
cargo test

# Core library tests
cargo test -p mpc-wallet-core

# With logging
RUST_LOG=debug cargo test -- --nocapture
```

### Project Structure

```
mpc-agent-wallet/
├── crates/
│   ├── mpc-wallet-core/     # Core Rust library
│   │   ├── src/
│   │   │   ├── keygen/      # Distributed key generation
│   │   │   ├── sign/        # Threshold signing
│   │   │   ├── chain/       # Chain adapters (EVM, Solana)
│   │   │   ├── policy.rs    # Policy engine
│   │   │   ├── storage.rs   # Key share storage
│   │   │   └── mpc/         # MPC coordination
│   │   └── Cargo.toml
│   ├── mpc-wallet-wasm/     # WASM bindings
│   ├── mpc-wallet-relay/    # Relay service
│   └── mpc-wallet-cli/      # CLI tool
├── packages/
│   ├── mpc-wallet-sdk/      # TypeScript SDK
│   │   ├── src/
│   │   │   ├── wallet.ts    # Main wallet class
│   │   │   ├── keygen.ts    # Key generation
│   │   │   ├── signing.ts   # Threshold signing
│   │   │   ├── policy.ts    # Policy engine
│   │   │   ├── chains/      # Chain adapters
│   │   │   └── storage/     # Key storage
│   │   └── package.json
│   └── mpc-wallet-python/   # Python SDK
│       ├── src/mpc_wallet/
│       │   ├── wallet.py    # Main wallet class
│       │   ├── keygen.py    # Key generation
│       │   ├── signing.py   # Threshold signing
│       │   ├── policy.py    # Policy engine
│       │   ├── chains/      # Chain adapters
│       │   └── storage/     # Key storage
│       └── pyproject.toml
├── contracts/               # Smart contracts (Foundry)
│   ├── src/
│   │   ├── MpcSmartAccount.sol       # ERC-4337 MPC smart account
│   │   ├── MpcSmartAccountFactory.sol # Account factory
│   │   ├── interfaces/               # Contract interfaces
│   │   └── modules/
│   │       ├── MpcRecoveryModule.sol     # Key recovery
│   │       └── MpcSpendingLimitHook.sol  # Spending limits
│   ├── test/                # Foundry tests
│   └── script/              # Deployment scripts
├── Cargo.toml               # Workspace
└── README.md
```

## Documentation

| Document | Description |
|----------|-------------|
| [Quick Start](docs/README.md) | Get started with the SDK |
| [Architecture](docs/architecture.md) | System design and data flows |
| [Security Model](docs/security-model.md) | Threat model and mitigations |
| [Integration Guide](docs/integration-guide.md) | Integrate with AI frameworks |
| [TypeScript API](docs/api-reference/typescript.md) | TypeScript SDK reference |
| [Python API](docs/api-reference/python.md) | Python SDK reference |

## Examples

| Example | Description |
|---------|-------------|
| [Basic Wallet](examples/basic-wallet/) | Minimal wallet setup and signing |
| [ElizaOS Plugin](examples/elizaos-plugin/) | Integration with ElizaOS AI framework |
| [LangChain Tool](examples/langchain-tool/) | LangChain tools for LLM applications |
| [Telegram Bot](examples/telegram-bot/) | Transaction approval via Telegram |
| [DeFi Agent](examples/defi-agent/) | Automated DeFi strategy execution |

## Smart Contracts

The `contracts/` directory contains ERC-4337 smart account contracts:

```bash
cd contracts

# Install dependencies
forge install

# Build
forge build

# Test
forge test

# Deploy (local)
forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast
```

See [contracts/README.md](contracts/README.md) for detailed documentation.

## License

Licensed under MIT OR Apache-2.0.

## Contributing

Contributions welcome! Please read the contributing guidelines first.

---

Built for AI agents that need secure blockchain access with human oversight.
