# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-01-11

### Highlights

- **Rust 2024 Edition** - Using the latest stable Rust features including let chains
- **Trusted Publishing** - PyPI uses OIDC for secure publishing without API tokens
- **Multi-registry** - Packages available on crates.io, npm and PyPI
- **Multi-chain** - Support for EVM chains and Solana

### Added

#### Core Library (`mpc-wallet-core`)
- 2-of-3 threshold MPC key generation using DKLs23 protocol
- Distributed signing with policy enforcement
- Key share refresh for proactive security
- BIP32 hierarchical deterministic key derivation
- Multi-chain support:
  - EVM chains (Ethereum, Base, Arbitrum, etc.)
  - Solana
- ERC-4337 smart account integration
- Policy engine with configurable rules:
  - Per-transaction spending limits
  - Daily/weekly spending limits
  - Address whitelist/blacklist
  - Time-of-day restrictions
  - Contract interaction restrictions

#### Message Relay (`mpc-wallet-relay`)
- WebSocket-based message relay for MPC protocol coordination
- Signing session management
- Approval request handling
- Webhook notifications for user devices
- RESTful API for session status

#### WASM Bindings (`@mpc-wallet/wasm`)
- Browser-compatible WebAssembly bindings
- Full key generation and signing support
- Optimized bundle size

#### TypeScript SDK (`@mpc-wallet/sdk`)
- High-level `MpcAgentWallet` class
- Chain-specific utilities for EVM and Solana
- Browser and Node.js storage adapters
- Full TypeScript type definitions

#### Python SDK (`mpc-wallet`)
- Async/await API design
- Chain adapters for EVM and Solana
- Policy configuration
- Type hints with Pydantic models

#### Smart Contracts
- `MpcSmartAccount` - ERC-4337 compatible smart account
- `MpcRecoveryModule` - Time-locked recovery mechanism
- `SpendingLimitHook` - On-chain spending limit enforcement

#### Documentation
- Architecture overview
- Security model documentation
- Integration guides for AI agent frameworks
- API reference for TypeScript and Python

#### Examples
- Basic wallet usage
- ElizaOS plugin integration
- LangChain tool integration
- Telegram approval bot
- DeFi agent automation

### Security
- Cryptographic operations use constant-time comparisons
- Key shares encrypted at rest
- No single point of failure in key management

---

## Package Versions

| Package | Version | Registry |
|---------|---------|----------|
| mpc-wallet-core | 0.1.0 | [crates.io](https://crates.io/crates/mpc-wallet-core) |
| mpc-wallet-relay | 0.1.0 | [crates.io](https://crates.io/crates/mpc-wallet-relay) |
| @mpc-wallet/wasm | 0.1.0 | [npm](https://www.npmjs.com/package/@mpc-wallet/wasm) |
| @mpc-wallet/sdk | 0.1.0 | [npm](https://www.npmjs.com/package/@mpc-wallet/sdk) |
| mpc-wallet | 0.1.0 | [PyPI](https://pypi.org/project/mpc-wallet/) |

[Unreleased]: https://github.com/Kazopl/mpc-agent-wallet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Kazopl/mpc-agent-wallet/releases/tag/v0.1.0
