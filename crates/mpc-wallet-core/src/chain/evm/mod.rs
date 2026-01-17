//! # EVM Chain Adapter
//!
//! Adapter for Ethereum and EVM-compatible chains with support for:
//! - EIP-1559 transaction building
//! - Gas estimation and priority fees
//! - RPC failover
//! - Nonce management
//!
//! ## Example
//!
//! ```rust,ignore
//! use mpc_wallet_core::chain::evm::{EvmAdapter, EvmConfig};
//!
//! let config = EvmConfig::ethereum_mainnet();
//! let adapter = EvmAdapter::new(config)?;
//!
//! let balance = adapter.get_balance("0x...").await?;
//! ```

#[cfg(feature = "aa")]
pub mod aa;

use super::{
    Balance, ChainAdapter, ChainId, GasPrice, GasPrices, RpcClient, SignedTx, TxHash, TxParams,
    TxPriority, TxReceipt, TxStatus, TxSummary, UnsignedTx,
};
use crate::{Error, Result, Signature};
use alloy_primitives::{Address, Bytes, U256};
use alloy_rlp::{Encodable, RlpEncodable};
use async_trait::async_trait;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for EVM adapter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmConfig {
    /// Chain identifier
    pub chain_id: ChainId,
    /// RPC endpoint URLs (for failover)
    pub rpc_urls: Vec<String>,
    /// Block explorer URL (optional)
    pub explorer_url: Option<String>,
    /// Native currency symbol
    pub symbol: String,
    /// Native currency decimals (18 for most EVM chains)
    pub decimals: u8,
    /// Whether EIP-1559 is supported
    pub eip1559_supported: bool,
}

impl EvmConfig {
    /// Create config for Ethereum Mainnet
    pub fn ethereum_mainnet() -> Self {
        Self {
            chain_id: ChainId::ETHEREUM_MAINNET,
            rpc_urls: vec![
                "https://eth.llamarpc.com".to_string(),
                "https://rpc.ankr.com/eth".to_string(),
                "https://cloudflare-eth.com".to_string(),
            ],
            explorer_url: Some("https://etherscan.io".to_string()),
            symbol: "ETH".to_string(),
            decimals: 18,
            eip1559_supported: true,
        }
    }

    /// Create config for Ethereum Sepolia testnet
    pub fn ethereum_sepolia() -> Self {
        Self {
            chain_id: ChainId::ETHEREUM_SEPOLIA,
            rpc_urls: vec![
                "https://rpc.sepolia.org".to_string(),
                "https://rpc.ankr.com/eth_sepolia".to_string(),
            ],
            explorer_url: Some("https://sepolia.etherscan.io".to_string()),
            symbol: "ETH".to_string(),
            decimals: 18,
            eip1559_supported: true,
        }
    }

    /// Create config for Arbitrum One
    pub fn arbitrum_one() -> Self {
        Self {
            chain_id: ChainId::ARBITRUM_ONE,
            rpc_urls: vec![
                "https://arb1.arbitrum.io/rpc".to_string(),
                "https://rpc.ankr.com/arbitrum".to_string(),
            ],
            explorer_url: Some("https://arbiscan.io".to_string()),
            symbol: "ETH".to_string(),
            decimals: 18,
            eip1559_supported: true,
        }
    }

    /// Create config for Base
    pub fn base() -> Self {
        Self {
            chain_id: ChainId::BASE,
            rpc_urls: vec![
                "https://mainnet.base.org".to_string(),
                "https://base.llamarpc.com".to_string(),
            ],
            explorer_url: Some("https://basescan.org".to_string()),
            symbol: "ETH".to_string(),
            decimals: 18,
            eip1559_supported: true,
        }
    }

    /// Create config for Base Sepolia testnet
    pub fn base_sepolia() -> Self {
        Self {
            chain_id: ChainId::BASE_SEPOLIA,
            rpc_urls: vec![
                "https://sepolia.base.org".to_string(),
                "https://base-sepolia.drpc.org".to_string(),
            ],
            explorer_url: Some("https://sepolia.basescan.org".to_string()),
            symbol: "ETH".to_string(),
            decimals: 18,
            eip1559_supported: true,
        }
    }

    /// Create config for Optimism
    pub fn optimism() -> Self {
        Self {
            chain_id: ChainId::OPTIMISM,
            rpc_urls: vec![
                "https://mainnet.optimism.io".to_string(),
                "https://rpc.ankr.com/optimism".to_string(),
            ],
            explorer_url: Some("https://optimistic.etherscan.io".to_string()),
            symbol: "ETH".to_string(),
            decimals: 18,
            eip1559_supported: true,
        }
    }

    /// Create config for Polygon
    pub fn polygon() -> Self {
        Self {
            chain_id: ChainId::POLYGON,
            rpc_urls: vec![
                "https://polygon-rpc.com".to_string(),
                "https://rpc.ankr.com/polygon".to_string(),
            ],
            explorer_url: Some("https://polygonscan.com".to_string()),
            symbol: "MATIC".to_string(),
            decimals: 18,
            eip1559_supported: true,
        }
    }

    /// Create config for BNB Smart Chain
    pub fn bsc() -> Self {
        Self {
            chain_id: ChainId::BSC,
            rpc_urls: vec![
                "https://bsc-dataseed.binance.org".to_string(),
                "https://rpc.ankr.com/bsc".to_string(),
            ],
            explorer_url: Some("https://bscscan.com".to_string()),
            symbol: "BNB".to_string(),
            decimals: 18,
            eip1559_supported: false,
        }
    }

    /// Create a custom config
    pub fn custom(chain_id: u64, rpc_urls: Vec<String>, symbol: &str) -> Self {
        Self {
            chain_id: ChainId(chain_id),
            rpc_urls,
            explorer_url: None,
            symbol: symbol.to_string(),
            decimals: 18,
            eip1559_supported: true,
        }
    }

    /// Set explorer URL
    pub fn with_explorer(mut self, url: impl Into<String>) -> Self {
        self.explorer_url = Some(url.into());
        self
    }

    /// Set EIP-1559 support
    pub fn with_eip1559(mut self, supported: bool) -> Self {
        self.eip1559_supported = supported;
        self
    }
}

// ============================================================================
// EIP-1559 Transaction Type
// ============================================================================

/// EIP-1559 transaction structure
#[derive(Debug, Clone, RlpEncodable)]
struct Eip1559Transaction {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    to: Address,
    value: U256,
    data: Bytes,
    access_list: Vec<AccessListItem>,
}

/// Access list item for EIP-2930
#[derive(Debug, Clone, RlpEncodable)]
struct AccessListItem {
    address: Address,
    storage_keys: Vec<alloy_primitives::B256>,
}

impl Eip1559Transaction {
    /// Get the signing hash for EIP-1559 transaction
    fn signing_hash(&self) -> [u8; 32] {
        let mut encoded = vec![0x02]; // EIP-1559 type
        self.encode(&mut encoded);

        let mut hasher = Keccak::v256();
        hasher.update(&encoded);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        hash
    }

    /// Encode the transaction with signature
    fn encode_signed(&self, signature: &Signature) -> Vec<u8> {
        // EIP-1559 signed tx: 0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, signatureYParity, signatureR, signatureS])
        let mut stream = alloy_rlp::BytesMut::new();

        // Create the full list including signature
        alloy_rlp::Header {
            list: true,
            payload_length: self.rlp_payload_length() + signature_rlp_length(signature),
        }
        .encode(&mut stream);

        // Encode transaction fields
        self.chain_id.encode(&mut stream);
        self.nonce.encode(&mut stream);
        self.max_priority_fee_per_gas.encode(&mut stream);
        self.max_fee_per_gas.encode(&mut stream);
        self.gas_limit.encode(&mut stream);
        self.to.encode(&mut stream);
        self.value.encode(&mut stream);
        self.data.encode(&mut stream);
        self.access_list.encode(&mut stream);

        // Encode signature (y_parity, r, s)
        let y_parity: u8 = signature.recovery_id;
        y_parity.encode(&mut stream);

        let r = U256::from_be_slice(&signature.r);
        r.encode(&mut stream);

        let s = U256::from_be_slice(&signature.s);
        s.encode(&mut stream);

        // Prepend type byte
        let mut result = vec![0x02];
        result.extend_from_slice(&stream);
        result
    }

    fn rlp_payload_length(&self) -> usize {
        self.chain_id.length()
            + self.nonce.length()
            + self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.gas_limit.length()
            + self.to.length()
            + self.value.length()
            + self.data.length()
            + self.access_list.length()
    }
}

fn signature_rlp_length(sig: &Signature) -> usize {
    let y_parity: u8 = sig.recovery_id;
    let r = U256::from_be_slice(&sig.r);
    let s = U256::from_be_slice(&sig.s);
    y_parity.length() + r.length() + s.length()
}

// ============================================================================
// Legacy Transaction Type
// ============================================================================

/// Legacy transaction for non-EIP-1559 chains
#[derive(Debug, Clone, RlpEncodable)]
struct LegacyTransaction {
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: Address,
    value: U256,
    data: Bytes,
}

impl LegacyTransaction {
    /// Get the signing hash for legacy transaction (EIP-155)
    fn signing_hash(&self, chain_id: u64) -> [u8; 32] {
        // EIP-155 signing: rlp([nonce, gasprice, gas, to, value, data, chainId, 0, 0])
        let mut stream = alloy_rlp::BytesMut::new();

        alloy_rlp::Header {
            list: true,
            payload_length: self.rlp_payload_length()
                + chain_id.length()
                + 0u8.length()
                + 0u8.length(),
        }
        .encode(&mut stream);

        self.nonce.encode(&mut stream);
        self.gas_price.encode(&mut stream);
        self.gas_limit.encode(&mut stream);
        self.to.encode(&mut stream);
        self.value.encode(&mut stream);
        self.data.encode(&mut stream);
        chain_id.encode(&mut stream);
        0u8.encode(&mut stream);
        0u8.encode(&mut stream);

        let mut hasher = Keccak::v256();
        hasher.update(&stream);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        hash
    }

    /// Encode the transaction with signature (EIP-155)
    fn encode_signed(&self, signature: &Signature, chain_id: u64) -> Vec<u8> {
        // v = recovery_id + 35 + chain_id * 2
        let v = signature.recovery_id as u64 + 35 + chain_id * 2;
        let r = U256::from_be_slice(&signature.r);
        let s = U256::from_be_slice(&signature.s);

        let mut stream = alloy_rlp::BytesMut::new();

        alloy_rlp::Header {
            list: true,
            payload_length: self.rlp_payload_length() + v.length() + r.length() + s.length(),
        }
        .encode(&mut stream);

        self.nonce.encode(&mut stream);
        self.gas_price.encode(&mut stream);
        self.gas_limit.encode(&mut stream);
        self.to.encode(&mut stream);
        self.value.encode(&mut stream);
        self.data.encode(&mut stream);
        v.encode(&mut stream);
        r.encode(&mut stream);
        s.encode(&mut stream);

        stream.to_vec()
    }

    fn rlp_payload_length(&self) -> usize {
        self.nonce.length()
            + self.gas_price.length()
            + self.gas_limit.length()
            + self.to.length()
            + self.value.length()
            + self.data.length()
    }
}

// ============================================================================
// EVM Adapter
// ============================================================================

/// EVM chain adapter implementation
#[derive(Debug, Clone)]
pub struct EvmAdapter {
    config: EvmConfig,
    rpc: RpcClient,
}

impl EvmAdapter {
    /// Create a new EVM adapter
    pub fn new(config: EvmConfig) -> Result<Self> {
        let rpc = RpcClient::new(config.rpc_urls.clone())?;
        Ok(Self { config, rpc })
    }

    /// Get the configuration
    pub fn config(&self) -> &EvmConfig {
        &self.config
    }

    /// Parse a value string to wei
    fn parse_value(&self, value: &str) -> Result<U256> {
        // Check if value contains a decimal point
        if value.contains('.') {
            let parts: Vec<&str> = value.split('.').collect();
            if parts.len() != 2 {
                return Err(Error::InvalidConfig(format!("Invalid value: {}", value)));
            }

            let whole: u128 = parts[0]
                .parse()
                .map_err(|_| Error::InvalidConfig(format!("Invalid whole part: {}", parts[0])))?;

            let mut fraction = parts[1].to_string();
            if fraction.len() > self.config.decimals as usize {
                return Err(Error::InvalidConfig(format!(
                    "Too many decimal places: {}",
                    value
                )));
            }

            // Pad with zeros
            while fraction.len() < self.config.decimals as usize {
                fraction.push('0');
            }

            let fraction_value: u128 = fraction.parse().map_err(|_| {
                Error::InvalidConfig(format!("Invalid fraction part: {}", parts[1]))
            })?;

            let multiplier = 10u128.pow(self.config.decimals as u32);
            let total = whole
                .checked_mul(multiplier)
                .and_then(|v| v.checked_add(fraction_value))
                .ok_or_else(|| Error::InvalidConfig("Value overflow".into()))?;

            Ok(U256::from(total))
        } else {
            // Assume raw wei value if no decimal
            let value: u128 = value
                .parse()
                .map_err(|_| Error::InvalidConfig(format!("Invalid value: {}", value)))?;
            Ok(U256::from(value))
        }
    }

    /// Get gas prices using eth_feeHistory
    async fn get_eip1559_prices(&self) -> Result<GasPrices> {
        #[derive(Deserialize)]
        struct FeeHistory {
            #[serde(rename = "baseFeePerGas")]
            base_fee_per_gas: Vec<String>,
            reward: Option<Vec<Vec<String>>>,
        }

        let result: FeeHistory = self
            .rpc
            .request(
                "eth_feeHistory",
                serde_json::json!([20, "latest", [10, 50, 90]]),
            )
            .await?;

        // Parse base fee (last value is predicted next block)
        let base_fee = result
            .base_fee_per_gas
            .last()
            .and_then(|s| parse_hex_u128(s).ok())
            .unwrap_or(0);

        // Calculate priority fees from reward data
        let (low_tip, medium_tip, high_tip) = if let Some(rewards) = &result.reward {
            let low_tips: Vec<u128> = rewards
                .iter()
                .filter_map(|r| r.first().and_then(|s| parse_hex_u128(s).ok()))
                .collect();
            let medium_tips: Vec<u128> = rewards
                .iter()
                .filter_map(|r| r.get(1).and_then(|s| parse_hex_u128(s).ok()))
                .collect();
            let high_tips: Vec<u128> = rewards
                .iter()
                .filter_map(|r| r.get(2).and_then(|s| parse_hex_u128(s).ok()))
                .collect();

            (
                median(&low_tips).unwrap_or(1_000_000_000),    // 1 gwei
                median(&medium_tips).unwrap_or(2_000_000_000), // 2 gwei
                median(&high_tips).unwrap_or(5_000_000_000),   // 5 gwei
            )
        } else {
            // Default fallback values
            (1_000_000_000, 2_000_000_000, 5_000_000_000)
        };

        Ok(GasPrices {
            low: GasPrice {
                max_fee: base_fee + low_tip,
                max_priority_fee: low_tip,
                estimated_wait_secs: Some(60),
            },
            medium: GasPrice {
                max_fee: base_fee * 2 + medium_tip,
                max_priority_fee: medium_tip,
                estimated_wait_secs: Some(30),
            },
            high: GasPrice {
                max_fee: base_fee * 3 + high_tip,
                max_priority_fee: high_tip,
                estimated_wait_secs: Some(15),
            },
            base_fee: Some(base_fee),
        })
    }

    /// Get legacy gas price
    async fn get_legacy_price(&self) -> Result<GasPrices> {
        let gas_price: String = self
            .rpc
            .request("eth_gasPrice", serde_json::json!([]))
            .await?;
        let price = parse_hex_u128(&gas_price)?;

        Ok(GasPrices {
            low: GasPrice {
                max_fee: price,
                max_priority_fee: 0,
                estimated_wait_secs: Some(60),
            },
            medium: GasPrice {
                max_fee: price * 110 / 100, // +10%
                max_priority_fee: 0,
                estimated_wait_secs: Some(30),
            },
            high: GasPrice {
                max_fee: price * 130 / 100, // +30%
                max_priority_fee: 0,
                estimated_wait_secs: Some(15),
            },
            base_fee: None,
        })
    }
}

#[async_trait]
impl ChainAdapter for EvmAdapter {
    fn chain_id(&self) -> ChainId {
        self.config.chain_id
    }

    fn native_symbol(&self) -> &str {
        &self.config.symbol
    }

    fn native_decimals(&self) -> u8 {
        self.config.decimals
    }

    async fn get_balance(&self, address: &str) -> Result<Balance> {
        let result: String = self
            .rpc
            .request("eth_getBalance", serde_json::json!([address, "latest"]))
            .await?;

        let raw_value = parse_hex_u128(&result)?;

        Ok(Balance::new(
            raw_value.to_string(),
            self.config.decimals,
            &self.config.symbol,
        ))
    }

    async fn get_nonce(&self, address: &str) -> Result<u64> {
        let result: String = self
            .rpc
            .request(
                "eth_getTransactionCount",
                serde_json::json!([address, "latest"]),
            )
            .await?;

        parse_hex_u64(&result)
    }

    async fn build_transaction(&self, params: TxParams) -> Result<UnsignedTx> {
        // Get nonce if not provided
        let nonce = match params.nonce {
            Some(n) => n,
            None => self.get_nonce(&params.from).await?,
        };

        // Parse destination address
        let to = Address::from_str(&params.to)
            .map_err(|e| Error::InvalidConfig(format!("Invalid to address: {}", e)))?;

        // Parse value
        let value = self.parse_value(&params.value)?;

        // Get gas prices
        let gas_prices = self.get_gas_prices().await?;
        let gas_price = match params.priority {
            TxPriority::Low => &gas_prices.low,
            TxPriority::Medium => &gas_prices.medium,
            TxPriority::High | TxPriority::Urgent => &gas_prices.high,
        };

        // Estimate gas if not provided
        let gas_limit = match params.gas_limit {
            Some(limit) => limit,
            None => self.estimate_gas(&params).await?,
        };

        // Prepare data
        let data = params
            .data
            .as_ref()
            .map(|d| Bytes::from(d.clone()))
            .unwrap_or_default();

        let (signing_payload, raw_tx) = if self.config.eip1559_supported {
            let tx = Eip1559Transaction {
                chain_id: self.config.chain_id.0,
                nonce,
                max_priority_fee_per_gas: gas_price.max_priority_fee,
                max_fee_per_gas: gas_price.max_fee,
                gas_limit,
                to,
                value,
                data,
                access_list: vec![],
            };

            let signing_hash = tx.signing_hash();
            let mut raw = vec![0x02];
            tx.encode(&mut raw);

            (signing_hash.to_vec(), raw)
        } else {
            let tx = LegacyTransaction {
                nonce,
                gas_price: gas_price.max_fee,
                gas_limit,
                to,
                value,
                data,
            };

            let signing_hash = tx.signing_hash(self.config.chain_id.0);
            let mut raw = alloy_rlp::BytesMut::new();
            tx.encode(&mut raw);

            (signing_hash.to_vec(), raw.to_vec())
        };

        // Calculate estimated fee
        let estimated_fee_wei = gas_price.max_fee * gas_limit as u128;
        let estimated_fee = Balance::new(
            estimated_fee_wei.to_string(),
            self.config.decimals,
            &self.config.symbol,
        )
        .formatted;

        let summary = TxSummary {
            tx_type: if params.data.is_some() {
                "Contract Call".to_string()
            } else {
                "Transfer".to_string()
            },
            from: params.from.clone(),
            to: params.to.clone(),
            value: format!("{} {}", params.value, self.config.symbol),
            estimated_fee: format!("{} {}", estimated_fee, self.config.symbol),
            details: None,
        };

        Ok(UnsignedTx {
            chain_id: self.config.chain_id,
            signing_payload,
            raw_tx,
            summary,
        })
    }

    async fn broadcast(&self, signed_tx: &SignedTx) -> Result<TxHash> {
        let raw_hex = format!("0x{}", hex::encode(&signed_tx.raw_tx));

        let result: String = self
            .rpc
            .request("eth_sendRawTransaction", serde_json::json!([raw_hex]))
            .await?;

        let explorer_url = self.explorer_tx_url(&result);

        Ok(TxHash {
            hash: result,
            explorer_url,
        })
    }

    fn derive_address(&self, public_key: &[u8]) -> Result<String> {
        // Public key should be uncompressed (65 bytes) or compressed (33 bytes)
        let pk_bytes = if public_key.len() == 33 {
            // Decompress the public key
            let point = k256::EncodedPoint::from_bytes(public_key)
                .map_err(|e| Error::Crypto(format!("Invalid public key: {}", e)))?;
            let affine = k256::AffinePoint::from_encoded_point(&point);
            let affine: k256::AffinePoint = Option::from(affine)
                .ok_or_else(|| Error::Crypto("Failed to decompress public key".into()))?;
            affine.to_encoded_point(false).as_bytes()[1..].to_vec() // Skip 0x04 prefix
        } else if public_key.len() == 65 {
            public_key[1..].to_vec() // Skip 0x04 prefix
        } else if public_key.len() == 64 {
            public_key.to_vec()
        } else {
            return Err(Error::Crypto(format!(
                "Invalid public key length: {}",
                public_key.len()
            )));
        };

        // Keccak256 hash of public key
        let mut hasher = Keccak::v256();
        hasher.update(&pk_bytes);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);

        // Take last 20 bytes
        let address = &hash[12..];
        Ok(format!("0x{}", hex::encode(address)))
    }

    async fn get_gas_prices(&self) -> Result<GasPrices> {
        if self.config.eip1559_supported {
            self.get_eip1559_prices().await
        } else {
            self.get_legacy_price().await
        }
    }

    async fn estimate_gas(&self, params: &TxParams) -> Result<u64> {
        let tx_object = serde_json::json!({
            "from": params.from,
            "to": params.to,
            "value": format!("0x{:x}", self.parse_value(&params.value)?),
            "data": params.data.as_ref().map(|d| format!("0x{}", hex::encode(d))),
        });

        let result: String = self
            .rpc
            .request("eth_estimateGas", serde_json::json!([tx_object]))
            .await?;

        let gas = parse_hex_u64(&result)?;
        // Add 20% buffer
        Ok(gas * 120 / 100)
    }

    async fn wait_for_confirmation(&self, tx_hash: &str, timeout_secs: u64) -> Result<TxReceipt> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);

        loop {
            if start.elapsed() > timeout {
                return Err(Error::Timeout(format!(
                    "Transaction {} not confirmed within {} seconds",
                    tx_hash, timeout_secs
                )));
            }

            #[derive(Deserialize)]
            struct Receipt {
                #[serde(rename = "blockNumber")]
                block_number: Option<String>,
                status: Option<String>,
                #[serde(rename = "gasUsed")]
                gas_used: Option<String>,
                #[serde(rename = "effectiveGasPrice")]
                effective_gas_price: Option<String>,
            }

            let result: Option<Receipt> = self
                .rpc
                .request("eth_getTransactionReceipt", serde_json::json!([tx_hash]))
                .await?;

            if let Some(receipt) = result
                && let Some(block_num) = receipt.block_number
            {
                let status = receipt
                    .status
                    .as_ref()
                    .map(|s| {
                        if s == "0x1" {
                            TxStatus::Success
                        } else {
                            TxStatus::Failed
                        }
                    })
                    .unwrap_or(TxStatus::Pending);

                return Ok(TxReceipt {
                    tx_hash: tx_hash.to_string(),
                    block_number: parse_hex_u64(&block_num)?,
                    status,
                    gas_used: receipt
                        .gas_used
                        .as_ref()
                        .and_then(|s| parse_hex_u64(s).ok()),
                    effective_gas_price: receipt
                        .effective_gas_price
                        .as_ref()
                        .and_then(|s| parse_hex_u128(s).ok()),
                });
            }

            // Wait before polling again
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }

    fn is_valid_address(&self, address: &str) -> bool {
        // Check basic format
        if !address.starts_with("0x") || address.len() != 42 {
            return false;
        }
        // Check if all characters after 0x are valid hex
        address[2..].chars().all(|c| c.is_ascii_hexdigit())
    }

    fn explorer_tx_url(&self, tx_hash: &str) -> Option<String> {
        self.config
            .explorer_url
            .as_ref()
            .map(|base| format!("{}/tx/{}", base, tx_hash))
    }

    fn explorer_address_url(&self, address: &str) -> Option<String> {
        self.config
            .explorer_url
            .as_ref()
            .map(|base| format!("{}/address/{}", base, address))
    }

    fn finalize_transaction(
        &self,
        unsigned_tx: &UnsignedTx,
        signature: &Signature,
    ) -> Result<SignedTx> {
        // Decode the raw transaction to get the original structure
        let raw_tx = if unsigned_tx.raw_tx.first() == Some(&0x02) {
            // EIP-1559 transaction
            // Re-decode and re-encode with signature
            // For simplicity, we parse the encoded tx and add signature
            self.finalize_eip1559_tx(unsigned_tx, signature)?
        } else {
            // Legacy transaction
            self.finalize_legacy_tx(unsigned_tx, signature)?
        };

        // Calculate tx hash
        let mut hasher = Keccak::v256();
        hasher.update(&raw_tx);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);

        Ok(SignedTx {
            chain_id: self.config.chain_id,
            raw_tx,
            tx_hash: format!("0x{}", hex::encode(hash)),
        })
    }
}

impl EvmAdapter {
    fn finalize_eip1559_tx(
        &self,
        unsigned_tx: &UnsignedTx,
        signature: &Signature,
    ) -> Result<Vec<u8>> {
        // Skip the 0x02 type byte and decode the RLP
        let rlp_data = &unsigned_tx.raw_tx[1..];
        let decoded: Vec<alloy_rlp::Bytes> = alloy_rlp::Decodable::decode(&mut &rlp_data[..])
            .map_err(|e| Error::ChainError(format!("Failed to decode transaction: {}", e)))?;

        if decoded.len() < 9 {
            return Err(Error::ChainError(
                "Invalid EIP-1559 transaction format".into(),
            ));
        }

        // Reconstruct the transaction
        let chain_id: u64 = decode_u64_from_bytes(&decoded[0])?;
        let nonce: u64 = decode_u64_from_bytes(&decoded[1])?;
        let max_priority_fee: u128 = decode_u128_from_bytes(&decoded[2])?;
        let max_fee: u128 = decode_u128_from_bytes(&decoded[3])?;
        let gas_limit: u64 = decode_u64_from_bytes(&decoded[4])?;
        let to = Address::from_slice(&decoded[5]);
        let value = U256::from_be_slice(&decoded[6]);
        let data = Bytes::from(decoded[7].to_vec());

        let tx = Eip1559Transaction {
            chain_id,
            nonce,
            max_priority_fee_per_gas: max_priority_fee,
            max_fee_per_gas: max_fee,
            gas_limit,
            to,
            value,
            data,
            access_list: vec![], // Empty for now
        };

        Ok(tx.encode_signed(signature))
    }

    fn finalize_legacy_tx(
        &self,
        unsigned_tx: &UnsignedTx,
        signature: &Signature,
    ) -> Result<Vec<u8>> {
        let decoded: Vec<alloy_rlp::Bytes> =
            alloy_rlp::Decodable::decode(&mut &unsigned_tx.raw_tx[..])
                .map_err(|e| Error::ChainError(format!("Failed to decode transaction: {}", e)))?;

        if decoded.len() < 6 {
            return Err(Error::ChainError(
                "Invalid legacy transaction format".into(),
            ));
        }

        let tx = LegacyTransaction {
            nonce: decode_u64_from_bytes(&decoded[0])?,
            gas_price: decode_u128_from_bytes(&decoded[1])?,
            gas_limit: decode_u64_from_bytes(&decoded[2])?,
            to: Address::from_slice(&decoded[3]),
            value: U256::from_be_slice(&decoded[4]),
            data: Bytes::from(decoded[5].to_vec()),
        };

        Ok(tx.encode_signed(signature, self.config.chain_id.0))
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn parse_hex_u128(s: &str) -> Result<u128> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u128::from_str_radix(s, 16)
        .map_err(|e| Error::ChainError(format!("Failed to parse hex: {}", e)))
}

fn parse_hex_u64(s: &str) -> Result<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|e| Error::ChainError(format!("Failed to parse hex: {}", e)))
}

fn decode_u64_from_bytes(bytes: &[u8]) -> Result<u64> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.len() > 8 {
        return Err(Error::ChainError("Value too large for u64".into()));
    }
    let mut buf = [0u8; 8];
    buf[8 - bytes.len()..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(buf))
}

fn decode_u128_from_bytes(bytes: &[u8]) -> Result<u128> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.len() > 16 {
        return Err(Error::ChainError("Value too large for u128".into()));
    }
    let mut buf = [0u8; 16];
    buf[16 - bytes.len()..].copy_from_slice(bytes);
    Ok(u128::from_be_bytes(buf))
}

fn median(values: &[u128]) -> Option<u128> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort();
    Some(sorted[sorted.len() / 2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_value() {
        let adapter = EvmAdapter::new(EvmConfig::ethereum_mainnet()).unwrap();

        // Test decimal values
        let value = adapter.parse_value("1.0").unwrap();
        assert_eq!(value, U256::from(1_000_000_000_000_000_000u128));

        let value = adapter.parse_value("0.5").unwrap();
        assert_eq!(value, U256::from(500_000_000_000_000_000u128));

        let value = adapter.parse_value("1.5").unwrap();
        assert_eq!(value, U256::from(1_500_000_000_000_000_000u128));
    }

    #[test]
    fn test_address_validation() {
        let adapter = EvmAdapter::new(EvmConfig::ethereum_mainnet()).unwrap();

        assert!(adapter.is_valid_address("0x742d35Cc6634C0532925a3b844Bc9e7595f4e123"));
        assert!(!adapter.is_valid_address("0x742d35Cc")); // Too short
        assert!(!adapter.is_valid_address("742d35Cc6634C0532925a3b844Bc9e7595f4e123")); // No prefix
        assert!(!adapter.is_valid_address("0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG")); // Invalid hex
    }

    #[test]
    fn test_derive_address() {
        let adapter = EvmAdapter::new(EvmConfig::ethereum_mainnet()).unwrap();

        // Test with uncompressed public key (65 bytes)
        let pk = hex::decode("04e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39").unwrap();
        let address = adapter.derive_address(&pk).unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_explorer_urls() {
        let adapter = EvmAdapter::new(EvmConfig::ethereum_mainnet()).unwrap();

        let tx_url = adapter.explorer_tx_url("0x123");
        assert_eq!(tx_url, Some("https://etherscan.io/tx/0x123".to_string()));

        let addr_url = adapter.explorer_address_url("0x456");
        assert_eq!(
            addr_url,
            Some("https://etherscan.io/address/0x456".to_string())
        );
    }

    #[test]
    fn test_chain_configs() {
        let mainnet = EvmConfig::ethereum_mainnet();
        assert_eq!(mainnet.chain_id.0, 1);
        assert_eq!(mainnet.symbol, "ETH");
        assert!(mainnet.eip1559_supported);

        let bsc = EvmConfig::bsc();
        assert_eq!(bsc.chain_id.0, 56);
        assert_eq!(bsc.symbol, "BNB");
        assert!(!bsc.eip1559_supported);
    }
}
