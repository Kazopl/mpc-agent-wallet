//! # ERC-4337 Account Abstraction Module
//!
//! This module provides smart account functionality compatible with ERC-4337,
//! including:
//! - UserOperation building
//! - Counterfactual address calculation
//! - Paymaster integration
//! - Session key support
//!
//! ## Example
//!
//! ```rust,ignore
//! use mpc_wallet_core::chain::evm::aa::{SmartAccountModule, SmartAccountConfig, UserOperation};
//!
//! let config = SmartAccountConfig::new(
//!     "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789", // EntryPoint v0.6
//!     "0x...", // Account factory
//! );
//!
//! let module = SmartAccountModule::new(config, evm_adapter)?;
//!
//! // Build a UserOperation
//! let user_op = module.build_user_operation(call_data).await?;
//!
//! // Calculate counterfactual address
//! let address = module.calculate_address(owner_pk, salt)?;
//! ```

use super::{ChainAdapter, EvmAdapter};
use crate::{Error, Result, Signature};
use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

// ============================================================================
// Constants
// ============================================================================

/// ERC-4337 EntryPoint v0.6 address (same on most chains)
pub const ENTRY_POINT_V06: &str = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";

/// ERC-4337 EntryPoint v0.7 address
pub const ENTRY_POINT_V07: &str = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for smart account module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartAccountConfig {
    /// EntryPoint contract address
    pub entry_point: String,
    /// Account factory contract address
    pub account_factory: String,
    /// Paymaster address (optional)
    pub paymaster: Option<String>,
    /// Whether to use sponsored gas (via paymaster)
    pub use_sponsored_gas: bool,
    /// EntryPoint version
    pub version: EntryPointVersion,
}

/// EntryPoint version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum EntryPointVersion {
    /// ERC-4337 v0.6
    #[default]
    V06,
    /// ERC-4337 v0.7
    V07,
}

impl SmartAccountConfig {
    /// Create a new smart account config with v0.6 EntryPoint
    pub fn new(entry_point: impl Into<String>, account_factory: impl Into<String>) -> Self {
        Self {
            entry_point: entry_point.into(),
            account_factory: account_factory.into(),
            paymaster: None,
            use_sponsored_gas: false,
            version: EntryPointVersion::V06,
        }
    }

    /// Create config using the default v0.6 EntryPoint
    pub fn with_default_entry_point_v06(account_factory: impl Into<String>) -> Self {
        Self::new(ENTRY_POINT_V06, account_factory)
    }

    /// Create config using the default v0.7 EntryPoint
    pub fn with_default_entry_point_v07(account_factory: impl Into<String>) -> Self {
        Self {
            entry_point: ENTRY_POINT_V07.to_string(),
            account_factory: account_factory.into(),
            paymaster: None,
            use_sponsored_gas: false,
            version: EntryPointVersion::V07,
        }
    }

    /// Set paymaster
    pub fn with_paymaster(mut self, paymaster: impl Into<String>) -> Self {
        self.paymaster = Some(paymaster.into());
        self.use_sponsored_gas = true;
        self
    }

    /// Enable/disable sponsored gas
    pub fn with_sponsored_gas(mut self, enabled: bool) -> Self {
        self.use_sponsored_gas = enabled;
        self
    }
}

// ============================================================================
// UserOperation
// ============================================================================

/// ERC-4337 UserOperation (v0.6 format)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserOperation {
    /// Smart account address
    pub sender: String,
    /// Anti-replay nonce
    pub nonce: U256,
    /// Account initialization code (empty if account exists)
    #[serde(with = "bytes_hex")]
    pub init_code: Vec<u8>,
    /// Encoded call to execute
    #[serde(with = "bytes_hex")]
    pub call_data: Vec<u8>,
    /// Gas for verification
    pub call_gas_limit: U256,
    /// Gas for account creation
    pub verification_gas_limit: U256,
    /// Pre-verification gas
    pub pre_verification_gas: U256,
    /// Maximum fee per gas
    pub max_fee_per_gas: U256,
    /// Maximum priority fee per gas
    pub max_priority_fee_per_gas: U256,
    /// Paymaster and data (empty if self-paying)
    #[serde(with = "bytes_hex")]
    pub paymaster_and_data: Vec<u8>,
    /// Signature
    #[serde(with = "bytes_hex")]
    pub signature: Vec<u8>,
}

mod bytes_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

impl UserOperation {
    /// Create a new UserOperation
    pub fn new(sender: impl Into<String>, nonce: U256, call_data: Vec<u8>) -> Self {
        Self {
            sender: sender.into(),
            nonce,
            init_code: vec![],
            call_data,
            call_gas_limit: U256::from(100000),
            verification_gas_limit: U256::from(100000),
            pre_verification_gas: U256::from(21000),
            max_fee_per_gas: U256::ZERO,
            max_priority_fee_per_gas: U256::ZERO,
            paymaster_and_data: vec![],
            signature: vec![],
        }
    }

    /// Set init code for account deployment
    pub fn with_init_code(mut self, factory: &str, init_data: Vec<u8>) -> Result<Self> {
        let factory_addr = Address::from_str(factory)
            .map_err(|e| Error::InvalidConfig(format!("Invalid factory address: {}", e)))?;

        let mut init_code = factory_addr.to_vec();
        init_code.extend(init_data);
        self.init_code = init_code;
        Ok(self)
    }

    /// Set gas limits
    pub fn with_gas_limits(
        mut self,
        call_gas: u64,
        verification_gas: u64,
        pre_verification_gas: u64,
    ) -> Self {
        self.call_gas_limit = U256::from(call_gas);
        self.verification_gas_limit = U256::from(verification_gas);
        self.pre_verification_gas = U256::from(pre_verification_gas);
        self
    }

    /// Set gas prices
    pub fn with_gas_prices(mut self, max_fee: u128, max_priority_fee: u128) -> Self {
        self.max_fee_per_gas = U256::from(max_fee);
        self.max_priority_fee_per_gas = U256::from(max_priority_fee);
        self
    }

    /// Set paymaster
    pub fn with_paymaster(mut self, paymaster: &str, data: Vec<u8>) -> Result<Self> {
        let paymaster_addr = Address::from_str(paymaster)
            .map_err(|e| Error::InvalidConfig(format!("Invalid paymaster address: {}", e)))?;

        let mut paymaster_and_data = paymaster_addr.to_vec();
        paymaster_and_data.extend(data);
        self.paymaster_and_data = paymaster_and_data;
        Ok(self)
    }

    /// Set signature
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }

    /// Calculate the UserOperation hash for signing (v0.6 format)
    pub fn hash(&self, entry_point: &str, chain_id: u64) -> Result<[u8; 32]> {
        let entry_point_addr = Address::from_str(entry_point)
            .map_err(|e| Error::InvalidConfig(format!("Invalid EntryPoint address: {}", e)))?;

        // Pack the UserOperation fields
        let packed = self.pack_for_hash()?;

        // keccak256(packed)
        let mut hasher = Keccak::v256();
        hasher.update(&packed);
        let mut inner_hash = [0u8; 32];
        hasher.finalize(&mut inner_hash);

        // keccak256(innerHash || entryPoint || chainId)
        let mut final_hasher = Keccak::v256();
        final_hasher.update(&inner_hash);
        final_hasher.update(entry_point_addr.as_slice());

        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[24..].copy_from_slice(&chain_id.to_be_bytes());
        final_hasher.update(&chain_id_bytes);

        let mut hash = [0u8; 32];
        final_hasher.finalize(&mut hash);
        Ok(hash)
    }

    /// Pack UserOperation for hashing
    fn pack_for_hash(&self) -> Result<Vec<u8>> {
        let sender = Address::from_str(&self.sender)
            .map_err(|e| Error::InvalidConfig(format!("Invalid sender: {}", e)))?;

        let mut packed = Vec::new();

        // sender (address - 32 bytes padded)
        packed.extend_from_slice(&[0u8; 12]);
        packed.extend_from_slice(sender.as_slice());

        // nonce (uint256)
        packed.extend_from_slice(&self.nonce.to_be_bytes::<32>());

        // keccak256(initCode)
        let init_code_hash = keccak256(&self.init_code);
        packed.extend_from_slice(&init_code_hash);

        // keccak256(callData)
        let call_data_hash = keccak256(&self.call_data);
        packed.extend_from_slice(&call_data_hash);

        // callGasLimit
        packed.extend_from_slice(&self.call_gas_limit.to_be_bytes::<32>());

        // verificationGasLimit
        packed.extend_from_slice(&self.verification_gas_limit.to_be_bytes::<32>());

        // preVerificationGas
        packed.extend_from_slice(&self.pre_verification_gas.to_be_bytes::<32>());

        // maxFeePerGas
        packed.extend_from_slice(&self.max_fee_per_gas.to_be_bytes::<32>());

        // maxPriorityFeePerGas
        packed.extend_from_slice(&self.max_priority_fee_per_gas.to_be_bytes::<32>());

        // keccak256(paymasterAndData)
        let paymaster_hash = keccak256(&self.paymaster_and_data);
        packed.extend_from_slice(&paymaster_hash);

        Ok(packed)
    }

    /// Convert to JSON-RPC format
    pub fn to_rpc_format(&self) -> serde_json::Value {
        serde_json::json!({
            "sender": self.sender,
            "nonce": format!("0x{:x}", self.nonce),
            "initCode": format!("0x{}", hex::encode(&self.init_code)),
            "callData": format!("0x{}", hex::encode(&self.call_data)),
            "callGasLimit": format!("0x{:x}", self.call_gas_limit),
            "verificationGasLimit": format!("0x{:x}", self.verification_gas_limit),
            "preVerificationGas": format!("0x{:x}", self.pre_verification_gas),
            "maxFeePerGas": format!("0x{:x}", self.max_fee_per_gas),
            "maxPriorityFeePerGas": format!("0x{:x}", self.max_priority_fee_per_gas),
            "paymasterAndData": format!("0x{}", hex::encode(&self.paymaster_and_data)),
            "signature": format!("0x{}", hex::encode(&self.signature)),
        })
    }
}

// ============================================================================
// Smart Account Module
// ============================================================================

/// Smart account module for ERC-4337 operations
#[derive(Debug, Clone)]
pub struct SmartAccountModule {
    config: SmartAccountConfig,
    evm: EvmAdapter,
}

impl SmartAccountModule {
    /// Create a new smart account module
    pub fn new(config: SmartAccountConfig, evm: EvmAdapter) -> Self {
        Self { config, evm }
    }

    /// Get the configuration
    pub fn config(&self) -> &SmartAccountConfig {
        &self.config
    }

    /// Calculate the counterfactual address for a smart account
    ///
    /// Uses CREATE2: address = keccak256(0xff || factory || salt || keccak256(initCode))[12:]
    pub fn calculate_address(&self, owner: &[u8], salt: &[u8; 32]) -> Result<String> {
        let factory = Address::from_str(&self.config.account_factory)
            .map_err(|e| Error::InvalidConfig(format!("Invalid factory address: {}", e)))?;

        // Build init code (factory-specific, simplified here)
        // Actual init code depends on the factory implementation
        let init_code = self.build_init_code_hash(owner)?;

        // CREATE2: 0xff || factory || salt || keccak256(initCode)
        let mut hasher = Keccak::v256();
        hasher.update(&[0xff]);
        hasher.update(factory.as_slice());
        hasher.update(salt);
        hasher.update(&init_code);

        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);

        // Take last 20 bytes
        Ok(format!("0x{}", hex::encode(&hash[12..])))
    }

    /// Build init code hash for CREATE2 calculation
    fn build_init_code_hash(&self, owner: &[u8]) -> Result<[u8; 32]> {
        // This is a simplified implementation
        // Real implementation depends on the specific factory contract
        let mut hasher = Keccak::v256();
        hasher.update(owner);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        Ok(hash)
    }

    /// Check if an account is already deployed
    pub async fn is_deployed(&self, address: &str) -> Result<bool> {
        let result: String = self
            .evm
            .rpc
            .request("eth_getCode", serde_json::json!([address, "latest"]))
            .await?;

        // "0x" or "0x0" means no code
        Ok(result != "0x" && result != "0x0")
    }

    /// Get the nonce for a smart account from EntryPoint
    pub async fn get_nonce(&self, address: &str, key: u64) -> Result<U256> {
        // Call getNonce(address, key) on EntryPoint
        let call_data = encode_get_nonce(address, key)?;

        let result: String = self
            .evm
            .rpc
            .request(
                "eth_call",
                serde_json::json!([{
                    "to": self.config.entry_point,
                    "data": format!("0x{}", hex::encode(&call_data)),
                }, "latest"]),
            )
            .await?;

        let result_bytes = hex::decode(result.strip_prefix("0x").unwrap_or(&result))
            .map_err(|e| Error::ChainError(format!("Failed to decode nonce: {}", e)))?;

        if result_bytes.len() < 32 {
            return Err(Error::ChainError("Invalid nonce response".into()));
        }

        Ok(U256::from_be_slice(&result_bytes[..32]))
    }

    /// Build a UserOperation for a simple call
    pub async fn build_user_operation(
        &self,
        sender: &str,
        call_data: Vec<u8>,
    ) -> Result<UserOperation> {
        // Check if account is deployed
        let is_deployed = self.is_deployed(sender).await?;

        // Get nonce
        let nonce = self.get_nonce(sender, 0).await?;

        // Get gas prices
        let gas_prices = self.evm.get_gas_prices().await?;

        let mut user_op = UserOperation::new(sender, nonce, call_data).with_gas_prices(
            gas_prices.medium.max_fee,
            gas_prices.medium.max_priority_fee,
        );

        // If account not deployed, add init code
        if !is_deployed {
            // This would need the owner's public key and salt
            // For now, we'll leave init_code empty and expect the caller to set it
            tracing::warn!("Account not deployed, init_code should be provided");
        }

        // Add paymaster if configured
        if let Some(paymaster) = &self.config.paymaster
            && self.config.use_sponsored_gas
        {
            user_op = user_op.with_paymaster(paymaster, vec![])?;
        }

        Ok(user_op)
    }

    /// Estimate gas for a UserOperation using eth_estimateUserOperationGas
    pub async fn estimate_gas(&self, user_op: &UserOperation) -> Result<GasEstimate> {
        let result: serde_json::Value = self
            .evm
            .rpc
            .request(
                "eth_estimateUserOperationGas",
                serde_json::json!([user_op.to_rpc_format(), self.config.entry_point]),
            )
            .await?;

        let call_gas = parse_u256(&result["callGasLimit"])?;
        let verification_gas = parse_u256(&result["verificationGasLimit"])?;
        let pre_verification_gas = parse_u256(&result["preVerificationGas"])?;

        Ok(GasEstimate {
            call_gas_limit: call_gas,
            verification_gas_limit: verification_gas,
            pre_verification_gas,
        })
    }

    /// Send a UserOperation to a bundler
    pub async fn send_user_operation(&self, user_op: &UserOperation) -> Result<String> {
        let result: String = self
            .evm
            .rpc
            .request(
                "eth_sendUserOperation",
                serde_json::json!([user_op.to_rpc_format(), self.config.entry_point]),
            )
            .await?;

        Ok(result)
    }

    /// Get the receipt for a UserOperation
    pub async fn get_user_operation_receipt(
        &self,
        user_op_hash: &str,
    ) -> Result<Option<UserOperationReceipt>> {
        let result: Option<serde_json::Value> = self
            .evm
            .rpc
            .request(
                "eth_getUserOperationReceipt",
                serde_json::json!([user_op_hash]),
            )
            .await?;

        match result {
            Some(receipt) => Ok(Some(UserOperationReceipt {
                user_op_hash: user_op_hash.to_string(),
                sender: receipt["sender"].as_str().unwrap_or_default().to_string(),
                nonce: parse_u256(&receipt["nonce"]).unwrap_or(U256::ZERO),
                success: receipt["success"].as_bool().unwrap_or(false),
                actual_gas_cost: parse_u256(&receipt["actualGasCost"]).unwrap_or(U256::ZERO),
                actual_gas_used: parse_u256(&receipt["actualGasUsed"]).unwrap_or(U256::ZERO),
                tx_hash: receipt["receipt"]["transactionHash"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                block_number: receipt["receipt"]["blockNumber"]
                    .as_str()
                    .and_then(|s| u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok())
                    .unwrap_or(0),
            })),
            None => Ok(None),
        }
    }

    /// Wait for UserOperation confirmation
    pub async fn wait_for_user_operation(
        &self,
        user_op_hash: &str,
        timeout_secs: u64,
    ) -> Result<UserOperationReceipt> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);

        loop {
            if start.elapsed() > timeout {
                return Err(Error::Timeout(format!(
                    "UserOperation {} not confirmed within {} seconds",
                    user_op_hash, timeout_secs
                )));
            }

            if let Some(receipt) = self.get_user_operation_receipt(user_op_hash).await? {
                return Ok(receipt);
            }

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }

    /// Build call data for execute(address,uint256,bytes)
    pub fn encode_execute(&self, to: &str, value: U256, data: &[u8]) -> Result<Vec<u8>> {
        let to_addr = Address::from_str(to)
            .map_err(|e| Error::InvalidConfig(format!("Invalid address: {}", e)))?;

        // Function selector: execute(address,uint256,bytes)
        // keccak256("execute(address,uint256,bytes)")[:4] = 0xb61d27f6
        let selector = [0xb6, 0x1d, 0x27, 0xf6];

        let mut encoded = selector.to_vec();

        // address (32 bytes padded)
        encoded.extend_from_slice(&[0u8; 12]);
        encoded.extend_from_slice(to_addr.as_slice());

        // uint256 value
        encoded.extend_from_slice(&value.to_be_bytes::<32>());

        // bytes data - encoded as (offset, length, data)
        // offset is 96 (3 * 32 bytes)
        let offset: u64 = 96;
        encoded.extend_from_slice(&U256::from(offset).to_be_bytes::<32>());

        // length
        encoded.extend_from_slice(&U256::from(data.len()).to_be_bytes::<32>());

        // data (padded to 32 bytes)
        encoded.extend_from_slice(data);
        let padding = (32 - (data.len() % 32)) % 32;
        encoded.extend_from_slice(&vec![0u8; padding]);

        Ok(encoded)
    }

    /// Build call data for executeBatch(address[],uint256[],bytes[])
    pub fn encode_execute_batch(
        &self,
        targets: &[&str],
        values: &[U256],
        data: &[&[u8]],
    ) -> Result<Vec<u8>> {
        if targets.len() != values.len() || targets.len() != data.len() {
            return Err(Error::InvalidConfig("Array lengths must match".into()));
        }

        // Function selector: executeBatch(address[],uint256[],bytes[])
        // keccak256("executeBatch(address[],uint256[],bytes[])")[:4] = 0x47e1da2a
        let selector = [0x47, 0xe1, 0xda, 0x2a];

        let mut encoded = selector.to_vec();

        // This is a complex ABI encoding - simplified version
        // For production, use a proper ABI encoder

        // Offsets for the three arrays
        let offset_1: u64 = 96;
        let offset_2: u64 = offset_1 + 32 + (targets.len() as u64 * 32);
        let offset_3: u64 = offset_2 + 32 + (values.len() as u64 * 32);

        encoded.extend_from_slice(&U256::from(offset_1).to_be_bytes::<32>());
        encoded.extend_from_slice(&U256::from(offset_2).to_be_bytes::<32>());
        encoded.extend_from_slice(&U256::from(offset_3).to_be_bytes::<32>());

        // Encode addresses array
        encoded.extend_from_slice(&U256::from(targets.len()).to_be_bytes::<32>());
        for target in targets {
            let addr = Address::from_str(target)
                .map_err(|e| Error::InvalidConfig(format!("Invalid address: {}", e)))?;
            encoded.extend_from_slice(&[0u8; 12]);
            encoded.extend_from_slice(addr.as_slice());
        }

        // Encode values array
        encoded.extend_from_slice(&U256::from(values.len()).to_be_bytes::<32>());
        for value in values {
            encoded.extend_from_slice(&value.to_be_bytes::<32>());
        }

        // Encode bytes[] array (simplified - each bytes is empty for now)
        encoded.extend_from_slice(&U256::from(data.len()).to_be_bytes::<32>());
        // Offsets for each bytes element would go here
        // For simplicity, assuming all bytes are empty

        Ok(encoded)
    }

    /// Sign a UserOperation with the MPC signature
    pub fn sign_user_operation(
        &self,
        user_op: &mut UserOperation,
        signature: &Signature,
    ) -> Result<()> {
        // Standard ECDSA signature format: r || s || v
        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(&signature.r);
        sig_bytes.extend_from_slice(&signature.s);
        sig_bytes.push(signature.v());

        user_op.signature = sig_bytes;
        Ok(())
    }
}

// ============================================================================
// Supporting Types
// ============================================================================

/// Gas estimate for a UserOperation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasEstimate {
    pub call_gas_limit: U256,
    pub verification_gas_limit: U256,
    pub pre_verification_gas: U256,
}

/// Receipt for a confirmed UserOperation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOperationReceipt {
    pub user_op_hash: String,
    pub sender: String,
    pub nonce: U256,
    pub success: bool,
    pub actual_gas_cost: U256,
    pub actual_gas_used: U256,
    pub tx_hash: String,
    pub block_number: u64,
}

/// Session key configuration for delegated signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKeyConfig {
    /// Session key public key
    pub session_key: String,
    /// Valid after timestamp (Unix seconds)
    pub valid_after: u64,
    /// Valid until timestamp (Unix seconds)
    pub valid_until: u64,
    /// Allowed target addresses
    pub allowed_targets: Vec<String>,
    /// Maximum value per transaction
    pub max_value_per_tx: Option<U256>,
    /// Maximum total value
    pub max_total_value: Option<U256>,
    /// Allowed function selectors
    pub allowed_selectors: Vec<[u8; 4]>,
}

impl SessionKeyConfig {
    /// Create a new session key config
    pub fn new(session_key: impl Into<String>, valid_for_secs: u64) -> Self {
        let now = chrono::Utc::now().timestamp() as u64;
        Self {
            session_key: session_key.into(),
            valid_after: now,
            valid_until: now + valid_for_secs,
            allowed_targets: vec![],
            max_value_per_tx: None,
            max_total_value: None,
            allowed_selectors: vec![],
        }
    }

    /// Add allowed targets
    pub fn with_targets(mut self, targets: Vec<String>) -> Self {
        self.allowed_targets = targets;
        self
    }

    /// Set maximum value per transaction
    pub fn with_max_value_per_tx(mut self, max: U256) -> Self {
        self.max_value_per_tx = Some(max);
        self
    }

    /// Add allowed function selectors
    pub fn with_selectors(mut self, selectors: Vec<[u8; 4]>) -> Self {
        self.allowed_selectors = selectors;
        self
    }

    /// Check if the session is currently valid
    pub fn is_valid(&self) -> bool {
        let now = chrono::Utc::now().timestamp() as u64;
        now >= self.valid_after && now <= self.valid_until
    }

    /// Encode session key data for the SessionKeyModule contract
    pub fn encode(&self) -> Result<Vec<u8>> {
        let session_key = Address::from_str(&self.session_key)
            .map_err(|e| Error::InvalidConfig(format!("Invalid session key: {}", e)))?;

        let mut encoded = Vec::new();

        // Session key address
        encoded.extend_from_slice(&[0u8; 12]);
        encoded.extend_from_slice(session_key.as_slice());

        // Valid after
        encoded.extend_from_slice(&U256::from(self.valid_after).to_be_bytes::<32>());

        // Valid until
        encoded.extend_from_slice(&U256::from(self.valid_until).to_be_bytes::<32>());

        // Additional fields would be encoded here based on contract requirements

        Ok(encoded)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    hash
}

fn encode_get_nonce(address: &str, key: u64) -> Result<Vec<u8>> {
    let addr = Address::from_str(address)
        .map_err(|e| Error::InvalidConfig(format!("Invalid address: {}", e)))?;

    // Function selector: getNonce(address,uint192)
    // keccak256("getNonce(address,uint192)")[:4] = 0x35567e1a
    let selector = [0x35, 0x56, 0x7e, 0x1a];

    let mut encoded = selector.to_vec();

    // address (32 bytes padded)
    encoded.extend_from_slice(&[0u8; 12]);
    encoded.extend_from_slice(addr.as_slice());

    // uint192 key (32 bytes)
    encoded.extend_from_slice(&U256::from(key).to_be_bytes::<32>());

    Ok(encoded)
}

fn parse_u256(value: &serde_json::Value) -> Result<U256> {
    let s = value
        .as_str()
        .ok_or_else(|| Error::ChainError("Expected hex string".into()))?;
    let s = s.strip_prefix("0x").unwrap_or(s);

    if s.is_empty() || s == "0" {
        return Ok(U256::ZERO);
    }

    let bytes = hex::decode(format!("{:0>64}", s))
        .map_err(|e| Error::ChainError(format!("Failed to decode U256: {}", e)))?;

    Ok(U256::from_be_slice(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_operation_creation() {
        let user_op = UserOperation::new(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f4e123",
            U256::from(0),
            vec![0xb6, 0x1d, 0x27, 0xf6], // execute selector
        );

        assert_eq!(user_op.sender, "0x742d35Cc6634C0532925a3b844Bc9e7595f4e123");
        assert_eq!(user_op.nonce, U256::ZERO);
    }

    #[test]
    fn test_user_operation_hash() {
        let user_op = UserOperation::new(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f4e123",
            U256::from(0),
            vec![],
        )
        .with_gas_limits(100000, 100000, 21000)
        .with_gas_prices(50_000_000_000, 2_000_000_000);

        let hash = user_op.hash(ENTRY_POINT_V06, 1).unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_session_key_validity() {
        let config = SessionKeyConfig::new(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f4e123",
            3600, // 1 hour
        );

        assert!(config.is_valid());
    }

    #[test]
    fn test_smart_account_config() {
        let config = SmartAccountConfig::with_default_entry_point_v06(
            "0x9406Cc6185a346906296840746125a0E44976454",
        );

        assert_eq!(config.entry_point, ENTRY_POINT_V06);
        assert!(!config.use_sponsored_gas);

        let config_with_paymaster =
            config.with_paymaster("0x1234567890123456789012345678901234567890");
        assert!(config_with_paymaster.use_sponsored_gas);
    }

    #[test]
    fn test_encode_execute() {
        let config = SmartAccountConfig::with_default_entry_point_v06(
            "0x9406Cc6185a346906296840746125a0E44976454",
        );
        let evm = EvmAdapter::new(super::super::EvmConfig::ethereum_mainnet()).unwrap();
        let module = SmartAccountModule::new(config, evm);

        let encoded = module
            .encode_execute(
                "0x742d35Cc6634C0532925a3b844Bc9e7595f4e123",
                U256::from(1_000_000_000_000_000_000u128), // 1 ETH
                &[],
            )
            .unwrap();

        // Check selector
        assert_eq!(&encoded[..4], &[0xb6, 0x1d, 0x27, 0xf6]);
    }
}
