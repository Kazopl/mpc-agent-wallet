//! # MPC Wallet Core
//!
//! Core library for MPC-secured AI agent wallets using 2-of-3 threshold signing.
//!
//! ## Architecture
//!
//! This crate provides:
//! - **2-of-3 Threshold ECDSA**: AI agent holds 1 share, user holds 1 share, recovery guardian holds 1 share
//! - **Policy Engine**: Configurable rules enforced before signing (spending limits, whitelists, time bounds)
//! - **Key Share Storage**: Secure encrypted storage for key shares
//! - **Chain Adapters**: Unified interface for EVM and Solana chains
//! - **ERC-4337 Support**: Account abstraction with UserOperations and paymasters
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use mpc_wallet_core::{AgentWallet, PartyRole, PolicyConfig};
//! use mpc_wallet_core::chain::{ChainAdapter, EvmAdapter, EvmConfig};
//!
//! // Create a new wallet with policy configuration
//! let policy = PolicyConfig::default()
//!     .with_daily_limit("1.0", "ETH")
//!     .with_whitelist(vec!["0x..."]);
//!
//! let wallet = AgentWallet::create(policy).await?;
//!
//! // Generate key shares for all parties
//! let shares = wallet.generate_shares().await?;
//!
//! // Use chain adapter for transactions
//! let evm = EvmAdapter::new(EvmConfig::ethereum_mainnet())?;
//! let balance = evm.get_balance("0x...").await?;
//!
//! // Sign a transaction (requires AI + User or AI + Recovery)
//! let signature = wallet.sign_transaction(tx, &[PartyRole::Agent, PartyRole::User]).await?;
//! ```
//!
//! ## Security Model
//!
//! The 2-of-3 threshold ensures:
//! - AI agent cannot sign alone (prevents rogue AI)
//! - User maintains control (can approve/reject)
//! - Recovery possible if user loses access (with guardian)
//!
//! All signing operations pass through the policy engine before MPC execution.

pub mod agent_identity;
pub mod chain;
pub mod error;
pub mod keygen;
pub mod policy;
pub mod reputation;
pub mod sign;
pub mod types;
pub mod validation;

// Runtime-dependent modules (require tokio)
#[cfg(feature = "runtime")]
pub mod mpc;
#[cfg(feature = "runtime")]
pub mod storage;

pub use agent_identity::{
    AgentIdentity, AgentIdentityManager, AgentRegistrationConfig, AgentRegistrationFile,
    AgentService, IDENTITY_REGISTRY_ADDRESS,
};
pub use error::{Error, Result};
pub use policy::{PolicyConfig, PolicyDecision, PolicyEngine};
pub use reputation::{
    FeedbackParams, FeedbackSignal, ReputationManager, ReputationSummary,
    REPUTATION_REGISTRY_ADDRESS,
};
pub use validation::{
    TeeAttestation, TrustModel, ValidationManager, ValidationRequest, ValidationRequestParams,
    ValidationResponse, ZkMlProof, VALIDATION_REGISTRY_ADDRESS,
};

#[cfg(feature = "runtime")]
pub use storage::{EncryptedKeyShare, KeyShareStore};
pub use types::{
    AgentKeyShare, ChainType, KeyShareMetadata, Message, PartyId, PartyRole, PublicKey,
    SessionConfig, SessionId, Signature, TransactionRequest, keccak256_hash,
};

// Re-export chain types for convenience
#[cfg(feature = "evm")]
pub use chain::{EvmAdapter, EvmConfig};

#[cfg(feature = "solana")]
pub use chain::{SolanaAdapter, SolanaConfig};

#[cfg(feature = "aa")]
pub use chain::evm::aa::{SmartAccountConfig, SmartAccountModule, UserOperation};

pub use chain::{Balance, ChainAdapter, ChainId, SignedTx, TxHash, TxParams, UnsignedTx};

/// Protocol version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Fixed number of parties for AI agent wallet (AI, User, Recovery)
pub const N_PARTIES: usize = 3;

/// Fixed threshold (2-of-3)
pub const THRESHOLD: usize = 2;

/// Party IDs
pub const PARTY_AGENT: PartyId = 0;
pub const PARTY_USER: PartyId = 1;
pub const PARTY_RECOVERY: PartyId = 2;
