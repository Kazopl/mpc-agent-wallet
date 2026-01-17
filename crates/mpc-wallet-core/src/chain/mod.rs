//! # Chain Adapters
//!
//! This module provides chain-agnostic interfaces for interacting with different blockchains.
//! Each chain has its own adapter that implements the common `ChainAdapter` trait.
//!
//! ## Supported Chains
//!
//! - **EVM** - Ethereum and EVM-compatible chains (with EIP-1559 support)
//! - **Solana** - Solana with priority fee estimation and versioned transactions
//!
//! ## Example
//!
//! ```rust,ignore
//! use mpc_wallet_core::chain::{ChainAdapter, EvmAdapter, ChainConfig};
//!
//! // Create an EVM adapter for Ethereum mainnet
//! let adapter = EvmAdapter::new(ChainConfig::ethereum_mainnet());
//!
//! // Get balance
//! let balance = adapter.get_balance("0x...").await?;
//!
//! // Build and sign a transaction
//! let tx = adapter.build_transaction(tx_params).await?;
//! ```

#[cfg(feature = "evm")]
pub mod evm;

#[cfg(feature = "solana")]
pub mod solana;

use crate::{Error, Result, Signature};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

#[cfg(feature = "evm")]
pub use evm::{EvmAdapter, EvmConfig};

#[cfg(feature = "aa")]
pub use evm::aa::{SmartAccountConfig, SmartAccountModule, UserOperation};

#[cfg(feature = "solana")]
pub use solana::{SolanaAdapter, SolanaConfig};

// ============================================================================
// Core Types
// ============================================================================

/// Blockchain identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainId(pub u64);

impl ChainId {
    // EVM chains
    pub const ETHEREUM_MAINNET: ChainId = ChainId(1);
    pub const ETHEREUM_SEPOLIA: ChainId = ChainId(11155111);
    pub const ARBITRUM_ONE: ChainId = ChainId(42161);
    pub const OPTIMISM: ChainId = ChainId(10);
    pub const BASE: ChainId = ChainId(8453);
    pub const BASE_SEPOLIA: ChainId = ChainId(84532);
    pub const POLYGON: ChainId = ChainId(137);
    pub const BSC: ChainId = ChainId(56);
    pub const AVALANCHE: ChainId = ChainId(43114);

    // Solana (uses genesis hash as ID, but we use a conventional value)
    pub const SOLANA_MAINNET: ChainId = ChainId(101);
    pub const SOLANA_DEVNET: ChainId = ChainId(102);
    pub const SOLANA_TESTNET: ChainId = ChainId(103);

    /// Get the name for this chain
    pub fn name(&self) -> &'static str {
        match self.0 {
            1 => "Ethereum Mainnet",
            11155111 => "Ethereum Sepolia",
            42161 => "Arbitrum One",
            10 => "Optimism",
            8453 => "Base",
            84532 => "Base Sepolia",
            137 => "Polygon",
            56 => "BNB Smart Chain",
            43114 => "Avalanche C-Chain",
            101 => "Solana Mainnet",
            102 => "Solana Devnet",
            103 => "Solana Testnet",
            _ => "Unknown Chain",
        }
    }

    /// Check if this is a Solana chain
    pub fn is_solana(&self) -> bool {
        matches!(self.0, 101 | 102 | 103)
    }

    /// Check if this is an EVM chain
    pub fn is_evm(&self) -> bool {
        !self.is_solana()
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.0)
    }
}

impl From<u64> for ChainId {
    fn from(id: u64) -> Self {
        ChainId(id)
    }
}

/// Balance representation for any chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {
    /// Raw balance value (smallest unit: wei for ETH, lamports for SOL)
    pub raw: String,
    /// Human-readable balance with decimals
    pub formatted: String,
    /// Symbol of the token/native currency
    pub symbol: String,
    /// Number of decimals
    pub decimals: u8,
}

impl Balance {
    /// Create a new balance
    pub fn new(raw: impl Into<String>, decimals: u8, symbol: impl Into<String>) -> Self {
        let raw_str = raw.into();
        let symbol_str = symbol.into();
        let formatted = Self::format_balance(&raw_str, decimals);

        Self {
            raw: raw_str,
            formatted,
            symbol: symbol_str,
            decimals,
        }
    }

    /// Format a raw balance with decimals
    fn format_balance(raw: &str, decimals: u8) -> String {
        let raw_value: u128 = raw.parse().unwrap_or(0);
        if raw_value == 0 {
            return "0".to_string();
        }

        let divisor = 10u128.pow(decimals as u32);
        let whole = raw_value / divisor;
        let fraction = raw_value % divisor;

        if fraction == 0 {
            whole.to_string()
        } else {
            let fraction_str = format!("{:0>width$}", fraction, width = decimals as usize);
            let trimmed = fraction_str.trim_end_matches('0');
            format!("{}.{}", whole, trimmed)
        }
    }

    /// Check if balance is zero
    pub fn is_zero(&self) -> bool {
        self.raw == "0" || self.raw.is_empty()
    }

    /// Parse raw value as u128
    pub fn raw_value(&self) -> u128 {
        self.raw.parse().unwrap_or(0)
    }
}

/// Parameters for building a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxParams {
    /// Sender address
    pub from: String,
    /// Recipient address
    pub to: String,
    /// Amount to send (in human-readable format)
    pub value: String,
    /// Contract call data (optional)
    #[serde(default)]
    pub data: Option<Vec<u8>>,
    /// Gas limit (EVM) / Compute units (Solana)
    #[serde(default)]
    pub gas_limit: Option<u64>,
    /// Nonce override
    #[serde(default)]
    pub nonce: Option<u64>,
    /// Priority (for gas price estimation)
    #[serde(default)]
    pub priority: TxPriority,
}

impl TxParams {
    /// Create new transaction parameters
    pub fn new(from: impl Into<String>, to: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            value: value.into(),
            data: None,
            gas_limit: None,
            nonce: None,
            priority: TxPriority::Medium,
        }
    }

    /// Add contract call data
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }

    /// Set gas limit
    pub fn with_gas_limit(mut self, limit: u64) -> Self {
        self.gas_limit = Some(limit);
        self
    }

    /// Set nonce
    pub fn with_nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Set priority
    pub fn with_priority(mut self, priority: TxPriority) -> Self {
        self.priority = priority;
        self
    }
}

/// Transaction priority for gas estimation
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TxPriority {
    /// Low priority - slower but cheaper
    Low,
    /// Medium priority - balanced
    #[default]
    Medium,
    /// High priority - faster but more expensive
    High,
    /// Urgent priority - fastest confirmation
    Urgent,
}

/// Unsigned transaction ready for signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedTx {
    /// Chain identifier
    pub chain_id: ChainId,
    /// Message to be signed (transaction hash or serialized tx)
    pub signing_payload: Vec<u8>,
    /// Serialized transaction (chain-specific format)
    pub raw_tx: Vec<u8>,
    /// Human-readable transaction summary
    pub summary: TxSummary,
}

/// Human-readable transaction summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxSummary {
    /// Transaction type description
    pub tx_type: String,
    /// From address
    pub from: String,
    /// To address
    pub to: String,
    /// Value being transferred
    pub value: String,
    /// Estimated fee
    pub estimated_fee: String,
    /// Additional details
    #[serde(default)]
    pub details: Option<String>,
}

/// Signed transaction ready for broadcast
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTx {
    /// Chain identifier
    pub chain_id: ChainId,
    /// Serialized signed transaction
    pub raw_tx: Vec<u8>,
    /// Transaction hash (pre-computed)
    pub tx_hash: String,
}

/// Transaction hash returned after broadcast
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxHash {
    /// The transaction hash/signature
    pub hash: String,
    /// Explorer URL (if available)
    pub explorer_url: Option<String>,
}

impl TxHash {
    /// Create a new transaction hash
    pub fn new(hash: impl Into<String>) -> Self {
        Self {
            hash: hash.into(),
            explorer_url: None,
        }
    }

    /// Add explorer URL
    pub fn with_explorer_url(mut self, url: impl Into<String>) -> Self {
        self.explorer_url = Some(url.into());
        self
    }
}

/// Gas price information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasPrices {
    /// Low priority gas price
    pub low: GasPrice,
    /// Medium priority gas price
    pub medium: GasPrice,
    /// High priority gas price
    pub high: GasPrice,
    /// Current base fee (EIP-1559)
    pub base_fee: Option<u128>,
}

/// Individual gas price entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasPrice {
    /// Max fee per gas (gwei for EVM)
    pub max_fee: u128,
    /// Max priority fee (tip)
    pub max_priority_fee: u128,
    /// Estimated wait time in seconds
    pub estimated_wait_secs: Option<u64>,
}

// ============================================================================
// Chain Adapter Trait
// ============================================================================

/// Trait for chain-specific operations
///
/// This trait abstracts blockchain interactions, allowing the wallet to work
/// with multiple chains through a unified interface.
#[async_trait]
pub trait ChainAdapter: Send + Sync {
    /// Get the chain identifier
    fn chain_id(&self) -> ChainId;

    /// Get the native currency symbol
    fn native_symbol(&self) -> &str;

    /// Get the native currency decimals
    fn native_decimals(&self) -> u8;

    /// Get the native balance for an address
    async fn get_balance(&self, address: &str) -> Result<Balance>;

    /// Get the current nonce/sequence for an address
    async fn get_nonce(&self, address: &str) -> Result<u64>;

    /// Build an unsigned transaction
    async fn build_transaction(&self, params: TxParams) -> Result<UnsignedTx>;

    /// Broadcast a signed transaction
    async fn broadcast(&self, signed_tx: &SignedTx) -> Result<TxHash>;

    /// Derive address from public key bytes
    fn derive_address(&self, public_key: &[u8]) -> Result<String>;

    /// Get current gas prices (for EVM) or priority fees (for Solana)
    async fn get_gas_prices(&self) -> Result<GasPrices>;

    /// Estimate gas for a transaction
    async fn estimate_gas(&self, params: &TxParams) -> Result<u64>;

    /// Wait for transaction confirmation
    async fn wait_for_confirmation(&self, tx_hash: &str, timeout_secs: u64) -> Result<TxReceipt>;

    /// Check if an address is valid for this chain
    fn is_valid_address(&self, address: &str) -> bool;

    /// Get the explorer URL for a transaction
    fn explorer_tx_url(&self, tx_hash: &str) -> Option<String>;

    /// Get the explorer URL for an address
    fn explorer_address_url(&self, address: &str) -> Option<String>;

    /// Finalize a transaction with signature (chain-specific encoding)
    fn finalize_transaction(
        &self,
        unsigned_tx: &UnsignedTx,
        signature: &Signature,
    ) -> Result<SignedTx>;
}

/// Transaction receipt after confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxReceipt {
    /// Transaction hash
    pub tx_hash: String,
    /// Block number/slot
    pub block_number: u64,
    /// Transaction status
    pub status: TxStatus,
    /// Gas used
    pub gas_used: Option<u64>,
    /// Effective gas price
    pub effective_gas_price: Option<u128>,
}

/// Transaction status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxStatus {
    /// Transaction succeeded
    Success,
    /// Transaction failed
    Failed,
    /// Transaction is pending
    Pending,
}

// ============================================================================
// RPC Client (requires runtime feature)
// ============================================================================

/// HTTP RPC client with failover support
#[cfg(feature = "runtime")]
#[derive(Clone)]
pub struct RpcClient {
    urls: Vec<String>,
    client: reqwest::Client,
    current_index: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(feature = "runtime")]
impl RpcClient {
    /// Create a new RPC client with failover URLs
    pub fn new(urls: Vec<String>) -> Result<Self> {
        if urls.is_empty() {
            return Err(Error::InvalidConfig("At least one RPC URL required".into()));
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| Error::ChainError(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            urls,
            client,
            current_index: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Get the current RPC URL
    fn current_url(&self) -> &str {
        let idx = self
            .current_index
            .load(std::sync::atomic::Ordering::Relaxed);
        &self.urls[idx % self.urls.len()]
    }

    /// Rotate to the next RPC URL
    fn rotate_url(&self) {
        self.current_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Make a JSON-RPC request with automatic failover
    pub async fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T> {
        let mut last_error = None;

        for _ in 0..self.urls.len() {
            let url = self.current_url();

            match self.make_request(url, method, params.clone()).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    tracing::warn!("RPC request failed on {}: {}", url, e);
                    last_error = Some(e);
                    self.rotate_url();
                }
            }
        }

        Err(last_error.unwrap_or_else(|| Error::ChainError("All RPC endpoints failed".into())))
    }

    async fn make_request<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T> {
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        let response = self
            .client
            .post(url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| Error::ChainError(format!("RPC request failed: {}", e)))?;

        let response_body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Error::ChainError(format!("Failed to parse RPC response: {}", e)))?;

        if let Some(error) = response_body.get("error") {
            return Err(Error::ChainError(format!("RPC error: {}", error)));
        }

        let result = response_body
            .get("result")
            .ok_or_else(|| Error::ChainError("Missing result in RPC response".into()))?;

        serde_json::from_value(result.clone())
            .map_err(|e| Error::ChainError(format!("Failed to deserialize result: {}", e)))
    }
}

#[cfg(feature = "runtime")]
impl std::fmt::Debug for RpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcClient")
            .field("urls", &self.urls)
            .field(
                "current_index",
                &self
                    .current_index
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_id_names() {
        assert_eq!(ChainId::ETHEREUM_MAINNET.name(), "Ethereum Mainnet");
        assert_eq!(ChainId::SOLANA_MAINNET.name(), "Solana Mainnet");
        assert!(ChainId::ETHEREUM_MAINNET.is_evm());
        assert!(ChainId::SOLANA_MAINNET.is_solana());
    }

    #[test]
    fn test_balance_formatting() {
        // 1 ETH = 10^18 wei
        let balance = Balance::new("1000000000000000000", 18, "ETH");
        assert_eq!(balance.formatted, "1");

        // 1.5 ETH
        let balance = Balance::new("1500000000000000000", 18, "ETH");
        assert_eq!(balance.formatted, "1.5");

        // 0.001 ETH
        let balance = Balance::new("1000000000000000", 18, "ETH");
        assert_eq!(balance.formatted, "0.001");

        // 0 ETH
        let balance = Balance::new("0", 18, "ETH");
        assert_eq!(balance.formatted, "0");
    }

    #[test]
    fn test_tx_params_builder() {
        let params = TxParams::new("0xfrom", "0xto", "1.0")
            .with_gas_limit(21000)
            .with_priority(TxPriority::High);

        assert_eq!(params.gas_limit, Some(21000));
        assert_eq!(params.priority, TxPriority::High);
    }

    #[test]
    fn test_tx_priority_default() {
        let priority = TxPriority::default();
        assert_eq!(priority, TxPriority::Medium);
    }
}
