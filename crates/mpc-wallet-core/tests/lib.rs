//! MPC Wallet Core Test Suite
//!
//! Comprehensive test coverage for the MPC agent wallet SDK:
//!
//! ## Test Organization
//!
//! - **Unit Tests** (`unit/`): Individual component tests
//!   - `mpc_core_test.rs` - DKG, signing primitives
//!   - `policy_test.rs` - Policy engine enforcement
//!   - `chain_adapter_test.rs` - Chain operations
//!
//! - **Integration Tests** (`integration/`): End-to-end flows
//!   - `full_flow_test.rs` - Complete signing flow
//!   - `multichain_test.rs` - Cross-chain operations
//!
//! - **Fuzz Tests** (`fuzz/`): Property-based testing
//!   - `policy_fuzz.rs` - Policy engine edge cases
//!   - `signing_fuzz.rs` - Signing flow invariants
//!
//! - **Invariant Tests** (`invariant/`): Critical guarantees
//!   - `wallet_invariant.rs` - Key share consistency
//!
//! ## Running Tests
//!
//! ```bash
//! # Run all tests
//! cargo test --package mpc-wallet-core
//!
//! # Run specific test module
//! cargo test --package mpc-wallet-core unit::
//! cargo test --package mpc-wallet-core integration::
//! cargo test --package mpc-wallet-core fuzz::
//! cargo test --package mpc-wallet-core invariant::
//!
//! # Run with all features
//! cargo test --package mpc-wallet-core --all-features
//!
//! # Run with verbose output
//! cargo test --package mpc-wallet-core -- --nocapture
//! ```

mod fuzz;
mod integration;
mod invariant;
mod unit;
