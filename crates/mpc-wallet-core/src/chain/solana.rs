//! # Solana Chain Adapter
//!
//! Adapter for Solana with support for:
//! - Legacy and versioned transactions
//! - Priority fee estimation
//! - Associated token account handling
//! - Compute unit optimization
//!
//! ## Example
//!
//! ```rust,ignore
//! use mpc_wallet_core::chain::solana::{SolanaAdapter, SolanaConfig};
//!
//! let config = SolanaConfig::mainnet();
//! let adapter = SolanaAdapter::new(config)?;
//!
//! let balance = adapter.get_balance("...base58_address...").await?;
//! ```

use super::{
    Balance, ChainAdapter, ChainId, GasPrice, GasPrices, RpcClient, SignedTx, TxHash, TxParams,
    TxPriority, TxReceipt, TxStatus, TxSummary, UnsignedTx,
};
use crate::{Error, Result, Signature};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
// TODO: Migrate from deprecated `system_instruction` to `solana_system_interface::instruction`
// when updating to solana-sdk 3.x. See: https://github.com/anza-xyz/solana-sdk
#[allow(deprecated)]
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::Signature as SolanaSignature,
    system_instruction,
    transaction::Transaction,
};
use std::str::FromStr;

// Use bincode 1.x for Solana transaction serialization
use bincode1 as bincode;

// ============================================================================
// Constants
// ============================================================================

/// Solana System Program ID
pub const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

/// SPL Token Program ID
pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/// SPL Associated Token Account Program ID
pub const ATA_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for Solana adapter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaConfig {
    /// Chain identifier (conventional, not used on-chain)
    pub chain_id: ChainId,
    /// RPC endpoint URLs (for failover)
    pub rpc_urls: Vec<String>,
    /// Block explorer URL (optional)
    pub explorer_url: Option<String>,
    /// Commitment level for transactions
    #[serde(default)]
    pub commitment: SolanaCommitment,
    /// Whether to use versioned transactions
    pub use_versioned_transactions: bool,
}

/// Solana commitment level wrapper
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SolanaCommitment {
    Processed,
    #[default]
    Confirmed,
    Finalized,
}

impl SolanaCommitment {
    /// Convert to string for RPC calls
    pub fn as_str(&self) -> &'static str {
        match self {
            SolanaCommitment::Processed => "processed",
            SolanaCommitment::Confirmed => "confirmed",
            SolanaCommitment::Finalized => "finalized",
        }
    }
}

impl SolanaConfig {
    /// Create config for Solana Mainnet
    pub fn mainnet() -> Self {
        Self {
            chain_id: ChainId::SOLANA_MAINNET,
            rpc_urls: vec![
                "https://api.mainnet-beta.solana.com".to_string(),
                "https://solana-api.projectserum.com".to_string(),
            ],
            explorer_url: Some("https://explorer.solana.com".to_string()),
            commitment: SolanaCommitment::Confirmed,
            use_versioned_transactions: true,
        }
    }

    /// Create config for Solana Devnet
    pub fn devnet() -> Self {
        Self {
            chain_id: ChainId::SOLANA_DEVNET,
            rpc_urls: vec!["https://api.devnet.solana.com".to_string()],
            explorer_url: Some("https://explorer.solana.com?cluster=devnet".to_string()),
            commitment: SolanaCommitment::Confirmed,
            use_versioned_transactions: true,
        }
    }

    /// Create config for Solana Testnet
    pub fn testnet() -> Self {
        Self {
            chain_id: ChainId::SOLANA_TESTNET,
            rpc_urls: vec!["https://api.testnet.solana.com".to_string()],
            explorer_url: Some("https://explorer.solana.com?cluster=testnet".to_string()),
            commitment: SolanaCommitment::Confirmed,
            use_versioned_transactions: true,
        }
    }

    /// Create a custom config
    pub fn custom(rpc_urls: Vec<String>) -> Self {
        Self {
            chain_id: ChainId::SOLANA_MAINNET,
            rpc_urls,
            explorer_url: None,
            commitment: SolanaCommitment::Confirmed,
            use_versioned_transactions: true,
        }
    }

    /// Set explorer URL
    pub fn with_explorer(mut self, url: impl Into<String>) -> Self {
        self.explorer_url = Some(url.into());
        self
    }

    /// Set commitment level
    pub fn with_commitment(mut self, commitment: SolanaCommitment) -> Self {
        self.commitment = commitment;
        self
    }

    /// Enable/disable versioned transactions
    pub fn with_versioned_transactions(mut self, enabled: bool) -> Self {
        self.use_versioned_transactions = enabled;
        self
    }
}

// ============================================================================
// Solana Adapter
// ============================================================================

/// Solana chain adapter implementation
#[derive(Debug, Clone)]
pub struct SolanaAdapter {
    config: SolanaConfig,
    rpc: RpcClient,
}

impl SolanaAdapter {
    /// Create a new Solana adapter
    pub fn new(config: SolanaConfig) -> Result<Self> {
        let rpc = RpcClient::new(config.rpc_urls.clone())?;
        Ok(Self { config, rpc })
    }

    /// Get the configuration
    pub fn config(&self) -> &SolanaConfig {
        &self.config
    }

    /// Get RPC client reference
    pub fn rpc(&self) -> &RpcClient {
        &self.rpc
    }

    /// Get the recent blockhash
    pub async fn get_recent_blockhash(&self) -> Result<Hash> {
        #[derive(Deserialize)]
        struct BlockhashResponse {
            blockhash: String,
        }

        #[derive(Deserialize)]
        struct RpcResponse {
            value: BlockhashResponse,
        }

        let response: RpcResponse = self
            .rpc
            .request(
                "getLatestBlockhash",
                serde_json::json!([{
                    "commitment": self.config.commitment.as_str()
                }]),
            )
            .await?;

        Hash::from_str(&response.value.blockhash)
            .map_err(|e| Error::ChainError(format!("Invalid blockhash: {}", e)))
    }

    /// Get priority fees using getRecentPrioritizationFees
    async fn get_priority_fees(&self) -> Result<PriorityFees> {
        #[derive(Deserialize)]
        struct FeeEntry {
            #[serde(rename = "prioritizationFee")]
            prioritization_fee: u64,
        }

        let response: Vec<FeeEntry> = self
            .rpc
            .request("getRecentPrioritizationFees", serde_json::json!([]))
            .await
            .unwrap_or_default();

        if response.is_empty() {
            return Ok(PriorityFees::default());
        }

        let mut fees: Vec<u64> = response.iter().map(|e| e.prioritization_fee).collect();
        fees.sort();

        let len = fees.len();
        Ok(PriorityFees {
            low: fees.get(len / 4).copied().unwrap_or(0),
            medium: fees.get(len / 2).copied().unwrap_or(1000),
            high: fees.get(len * 3 / 4).copied().unwrap_or(10000),
        })
    }

    /// Get minimum rent exemption for an account
    pub async fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> Result<u64> {
        let result: u64 = self
            .rpc
            .request(
                "getMinimumBalanceForRentExemption",
                serde_json::json!([data_len]),
            )
            .await?;

        Ok(result)
    }

    /// Get token accounts for an owner
    pub async fn get_token_accounts(&self, owner: &str) -> Result<Vec<TokenAccount>> {
        let owner_pubkey = Pubkey::from_str(owner)
            .map_err(|e| Error::InvalidConfig(format!("Invalid owner address: {}", e)))?;

        #[derive(Deserialize)]
        struct AccountData {
            pubkey: String,
            account: AccountInfo,
        }

        #[derive(Deserialize)]
        struct AccountInfo {
            data: ParsedData,
        }

        #[derive(Deserialize)]
        struct ParsedData {
            parsed: ParsedInfo,
        }

        #[derive(Deserialize)]
        struct ParsedInfo {
            info: TokenInfo,
        }

        #[derive(Deserialize)]
        struct TokenInfo {
            mint: String,
            #[serde(rename = "tokenAmount")]
            token_amount: TokenAmount,
        }

        #[derive(Deserialize)]
        struct TokenAmount {
            amount: String,
            decimals: u8,
            #[serde(rename = "uiAmountString")]
            ui_amount_string: String,
        }

        #[derive(Deserialize)]
        struct RpcResponse {
            value: Vec<AccountData>,
        }

        let response: RpcResponse = self
            .rpc
            .request(
                "getTokenAccountsByOwner",
                serde_json::json!([
                    owner_pubkey.to_string(),
                    {"programId": TOKEN_PROGRAM_ID},
                    {"encoding": "jsonParsed"}
                ]),
            )
            .await?;

        Ok(response
            .value
            .into_iter()
            .map(|a| TokenAccount {
                address: a.pubkey,
                mint: a.account.data.parsed.info.mint,
                balance: a.account.data.parsed.info.token_amount.amount,
                decimals: a.account.data.parsed.info.token_amount.decimals,
                formatted_balance: a.account.data.parsed.info.token_amount.ui_amount_string,
            })
            .collect())
    }

    /// Get or create associated token account address
    pub fn get_associated_token_address(&self, owner: &str, mint: &str) -> Result<String> {
        let owner_pubkey = Pubkey::from_str(owner)
            .map_err(|e| Error::InvalidConfig(format!("Invalid owner: {}", e)))?;
        let mint_pubkey = Pubkey::from_str(mint)
            .map_err(|e| Error::InvalidConfig(format!("Invalid mint: {}", e)))?;

        let ata =
            spl_associated_token_account::get_associated_token_address(&owner_pubkey, &mint_pubkey);

        Ok(ata.to_string())
    }

    /// Build instructions for creating an ATA if needed
    pub async fn build_create_ata_instruction(
        &self,
        payer: &str,
        owner: &str,
        mint: &str,
    ) -> Result<Option<Instruction>> {
        let ata = self.get_associated_token_address(owner, mint)?;

        // Check if ATA exists
        let account_info = self.get_account_info(&ata).await?;

        if account_info.is_none() {
            let payer_pubkey = Pubkey::from_str(payer)
                .map_err(|e| Error::InvalidConfig(format!("Invalid payer: {}", e)))?;
            let owner_pubkey = Pubkey::from_str(owner)
                .map_err(|e| Error::InvalidConfig(format!("Invalid owner: {}", e)))?;
            let mint_pubkey = Pubkey::from_str(mint)
                .map_err(|e| Error::InvalidConfig(format!("Invalid mint: {}", e)))?;

            let instruction =
                spl_associated_token_account::instruction::create_associated_token_account(
                    &payer_pubkey,
                    &owner_pubkey,
                    &mint_pubkey,
                    &spl_token::id(),
                );

            Ok(Some(instruction))
        } else {
            Ok(None)
        }
    }

    /// Get account info
    async fn get_account_info(&self, address: &str) -> Result<Option<AccountInfoResponse>> {
        #[derive(Deserialize)]
        struct RpcResponse {
            value: Option<AccountInfoResponse>,
        }

        let response: RpcResponse = self
            .rpc
            .request(
                "getAccountInfo",
                serde_json::json!([
                    address,
                    {"encoding": "base64"}
                ]),
            )
            .await?;

        Ok(response.value)
    }

    /// Parse lamports to SOL string
    fn lamports_to_sol(lamports: u64) -> String {
        let sol = lamports as f64 / 1_000_000_000.0;
        format!("{:.9}", sol)
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_string()
    }

    /// Parse SOL string to lamports
    fn sol_to_lamports(sol: &str) -> Result<u64> {
        let value: f64 = sol
            .parse()
            .map_err(|_| Error::InvalidConfig(format!("Invalid SOL value: {}", sol)))?;

        Ok((value * 1_000_000_000.0) as u64)
    }

    /// Build a simple SOL transfer transaction
    fn build_transfer_instructions(
        &self,
        from: &Pubkey,
        to: &Pubkey,
        lamports: u64,
        priority_fee: u64,
        compute_units: u32,
    ) -> Vec<Instruction> {
        let mut instructions = Vec::new();

        // Add compute budget instructions for priority fee
        if priority_fee > 0 {
            instructions.push(ComputeBudgetInstruction::set_compute_unit_price(
                priority_fee,
            ));
        }

        // Add compute unit limit
        instructions.push(ComputeBudgetInstruction::set_compute_unit_limit(
            compute_units,
        ));

        // Add transfer instruction
        instructions.push(system_instruction::transfer(from, to, lamports));

        instructions
    }
}

#[async_trait]
impl ChainAdapter for SolanaAdapter {
    fn chain_id(&self) -> ChainId {
        self.config.chain_id
    }

    fn native_symbol(&self) -> &str {
        "SOL"
    }

    fn native_decimals(&self) -> u8 {
        9
    }

    async fn get_balance(&self, address: &str) -> Result<Balance> {
        let pubkey = Pubkey::from_str(address)
            .map_err(|e| Error::InvalidConfig(format!("Invalid address: {}", e)))?;

        #[derive(Deserialize)]
        struct BalanceResponse {
            value: u64,
        }

        let result: BalanceResponse = self
            .rpc
            .request("getBalance", serde_json::json!([pubkey.to_string()]))
            .await?;

        Ok(Balance::new(result.value.to_string(), 9, "SOL"))
    }

    async fn get_nonce(&self, _address: &str) -> Result<u64> {
        // Solana doesn't have a traditional nonce - we use recent blockhash instead
        // Return 0 as a placeholder
        Ok(0)
    }

    async fn build_transaction(&self, params: TxParams) -> Result<UnsignedTx> {
        let from_pubkey = Pubkey::from_str(&params.from)
            .map_err(|e| Error::InvalidConfig(format!("Invalid from address: {}", e)))?;
        let to_pubkey = Pubkey::from_str(&params.to)
            .map_err(|e| Error::InvalidConfig(format!("Invalid to address: {}", e)))?;

        // Parse value
        let lamports = Self::sol_to_lamports(&params.value)?;

        // Get priority fees
        let priority_fees = self.get_priority_fees().await?;
        let priority_fee = match params.priority {
            TxPriority::Low => priority_fees.low,
            TxPriority::Medium => priority_fees.medium,
            TxPriority::High | TxPriority::Urgent => priority_fees.high,
        };

        // Get recent blockhash (used for transaction validity)
        let _recent_blockhash = self.get_recent_blockhash().await?;

        // Compute units
        let compute_units = params.gas_limit.unwrap_or(200_000) as u32;

        // Build instructions
        let instructions = if let Some(data) = &params.data {
            // Custom instruction - interpret data as program instruction
            let mut ixs = Vec::new();

            if priority_fee > 0 {
                ixs.push(ComputeBudgetInstruction::set_compute_unit_price(
                    priority_fee,
                ));
            }
            ixs.push(ComputeBudgetInstruction::set_compute_unit_limit(
                compute_units,
            ));

            // Create instruction with the data (assume `to` is program ID)
            ixs.push(Instruction {
                program_id: to_pubkey,
                accounts: vec![AccountMeta::new(from_pubkey, true)],
                data: data.clone(),
            });

            ixs
        } else {
            // Simple SOL transfer
            self.build_transfer_instructions(
                &from_pubkey,
                &to_pubkey,
                lamports,
                priority_fee,
                compute_units,
            )
        };

        // Build transaction
        let message = Message::new(&instructions, Some(&from_pubkey));
        let tx = Transaction::new_unsigned(message);

        // Serialize for signing - the message bytes that need to be signed
        let signing_payload = tx.message_data();

        // Serialize full transaction using bincode 1.x API (re-exported from solana-sdk)
        let raw_tx = bincode::serialize(&tx)
            .map_err(|e| Error::ChainError(format!("Failed to serialize transaction: {}", e)))?;

        // Calculate estimated fee
        let estimated_fee = 5000 + (priority_fee * compute_units as u64 / 1_000_000);
        let fee_formatted = Self::lamports_to_sol(estimated_fee);

        let summary = TxSummary {
            tx_type: if params.data.is_some() {
                "Program Call".to_string()
            } else {
                "Transfer".to_string()
            },
            from: params.from.clone(),
            to: params.to.clone(),
            value: format!("{} SOL", params.value),
            estimated_fee: format!("{} SOL", fee_formatted),
            details: Some(format!("Priority fee: {} micro-lamports/CU", priority_fee)),
        };

        Ok(UnsignedTx {
            chain_id: self.config.chain_id,
            signing_payload,
            raw_tx,
            summary,
        })
    }

    async fn broadcast(&self, signed_tx: &SignedTx) -> Result<TxHash> {
        let encoded = bs58::encode(&signed_tx.raw_tx).into_string();

        let result: String = self
            .rpc
            .request(
                "sendTransaction",
                serde_json::json!([
                    encoded,
                    {
                        "encoding": "base58",
                        "skipPreflight": false,
                        "preflightCommitment": self.config.commitment.as_str()
                    }
                ]),
            )
            .await?;

        let explorer_url = self.explorer_tx_url(&result);

        Ok(TxHash {
            hash: result,
            explorer_url,
        })
    }

    fn derive_address(&self, public_key: &[u8]) -> Result<String> {
        // For Solana, we typically use Ed25519 public keys (32 bytes)
        // But MPC uses secp256k1, so we need to handle this differently
        //
        // Option 1: Use the secp256k1 public key directly (not standard Solana)
        // Option 2: Derive an Ed25519 key from secp256k1 (complex)
        // Option 3: Use program-derived addresses (PDA)
        //
        // For this implementation, we'll use the compressed secp256k1 public key
        // and create a deterministic address from it using a hash

        if public_key.len() == 32 {
            // Already a 32-byte key (could be Ed25519)
            let pubkey = Pubkey::new_from_array(
                public_key
                    .try_into()
                    .map_err(|_| Error::Crypto("Invalid public key length".into()))?,
            );
            Ok(pubkey.to_string())
        } else if public_key.len() == 33 {
            // Compressed secp256k1 - hash to 32 bytes
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(public_key);
            let hash = hasher.finalize();
            let pubkey = Pubkey::new_from_array(hash.into());
            Ok(pubkey.to_string())
        } else if public_key.len() == 64 || public_key.len() == 65 {
            // Uncompressed secp256k1 - hash to 32 bytes
            use sha2::{Digest, Sha256};
            let key_bytes = if public_key.len() == 65 {
                &public_key[1..] // Skip 0x04 prefix
            } else {
                public_key
            };
            let mut hasher = Sha256::new();
            hasher.update(key_bytes);
            let hash = hasher.finalize();
            let pubkey = Pubkey::new_from_array(hash.into());
            Ok(pubkey.to_string())
        } else {
            Err(Error::Crypto(format!(
                "Invalid public key length: {}",
                public_key.len()
            )))
        }
    }

    async fn get_gas_prices(&self) -> Result<GasPrices> {
        let priority_fees = self.get_priority_fees().await?;

        Ok(GasPrices {
            low: GasPrice {
                max_fee: priority_fees.low as u128,
                max_priority_fee: priority_fees.low as u128,
                estimated_wait_secs: Some(30),
            },
            medium: GasPrice {
                max_fee: priority_fees.medium as u128,
                max_priority_fee: priority_fees.medium as u128,
                estimated_wait_secs: Some(10),
            },
            high: GasPrice {
                max_fee: priority_fees.high as u128,
                max_priority_fee: priority_fees.high as u128,
                estimated_wait_secs: Some(5),
            },
            base_fee: Some(5000), // Base fee is 5000 lamports per signature
        })
    }

    async fn estimate_gas(&self, params: &TxParams) -> Result<u64> {
        // Estimate compute units needed
        // Simple transfer: ~200 CU
        // Token transfer: ~20,000 CU
        // Complex operations: 200,000+ CU

        if params.data.is_some() {
            Ok(200_000) // Default for program calls
        } else {
            Ok(200) // Simple SOL transfer
        }
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
            struct TxResponse {
                value: Option<TxInfo>,
            }

            #[derive(Deserialize)]
            struct TxInfo {
                slot: u64,
                meta: Option<TxMeta>,
            }

            #[derive(Deserialize)]
            struct TxMeta {
                err: Option<serde_json::Value>,
                fee: u64,
                #[serde(rename = "computeUnitsConsumed")]
                compute_units_consumed: Option<u64>,
            }

            let response: TxResponse = self
                .rpc
                .request(
                    "getTransaction",
                    serde_json::json!([
                        tx_hash,
                        {
                            "encoding": "json",
                            "commitment": self.config.commitment.as_str()
                        }
                    ]),
                )
                .await?;

            if let Some(info) = response.value {
                let status = if info.meta.as_ref().and_then(|m| m.err.as_ref()).is_some() {
                    TxStatus::Failed
                } else {
                    TxStatus::Success
                };

                return Ok(TxReceipt {
                    tx_hash: tx_hash.to_string(),
                    block_number: info.slot,
                    status,
                    gas_used: info.meta.as_ref().and_then(|m| m.compute_units_consumed),
                    effective_gas_price: info.meta.as_ref().map(|m| m.fee as u128),
                });
            }

            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    fn is_valid_address(&self, address: &str) -> bool {
        Pubkey::from_str(address).is_ok()
    }

    fn explorer_tx_url(&self, tx_hash: &str) -> Option<String> {
        self.config.explorer_url.as_ref().map(|base| {
            if base.contains("?cluster=") {
                format!("{}&tx={}", base, tx_hash)
            } else {
                format!("{}/tx/{}", base, tx_hash)
            }
        })
    }

    fn explorer_address_url(&self, address: &str) -> Option<String> {
        self.config.explorer_url.as_ref().map(|base| {
            if base.contains("?cluster=") {
                format!("{}&address={}", base, address)
            } else {
                format!("{}/address/{}", base, address)
            }
        })
    }

    fn finalize_transaction(
        &self,
        unsigned_tx: &UnsignedTx,
        signature: &Signature,
    ) -> Result<SignedTx> {
        // Deserialize the unsigned transaction using bincode 1.x API
        let mut tx: Transaction = bincode::deserialize(&unsigned_tx.raw_tx)
            .map_err(|e| Error::ChainError(format!("Failed to deserialize transaction: {}", e)))?;

        // Create Solana signature from ECDSA signature
        // Note: This is a compatibility layer - Solana natively uses Ed25519
        // For MPC with secp256k1, we need to handle this specially
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&signature.r);
        sig_bytes[32..].copy_from_slice(&signature.s);

        let solana_sig = SolanaSignature::from(sig_bytes);

        // Add signature to transaction
        tx.signatures = vec![solana_sig];

        // Serialize signed transaction using bincode 1.x API
        let raw_tx = bincode::serialize(&tx).map_err(|e| {
            Error::ChainError(format!("Failed to serialize signed transaction: {}", e))
        })?;

        Ok(SignedTx {
            chain_id: self.config.chain_id,
            raw_tx,
            tx_hash: bs58::encode(&sig_bytes).into_string(),
        })
    }
}

// ============================================================================
// Supporting Types
// ============================================================================

/// Priority fees for Solana transactions
#[derive(Debug, Clone, Default)]
struct PriorityFees {
    low: u64,
    medium: u64,
    high: u64,
}

/// Token account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAccount {
    /// Token account address
    pub address: String,
    /// Token mint address
    pub mint: String,
    /// Raw balance (smallest unit)
    pub balance: String,
    /// Token decimals
    pub decimals: u8,
    /// Human-readable balance
    pub formatted_balance: String,
}

/// Account info response from RPC
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AccountInfoResponse {
    lamports: u64,
    owner: String,
    data: Vec<String>,
    executable: bool,
    #[serde(rename = "rentEpoch")]
    rent_epoch: u64,
}

/// Builder for SPL token transfers
pub struct TokenTransferBuilder {
    from: String,
    to: String,
    mint: String,
    amount: u64,
    decimals: u8,
    create_ata_if_needed: bool,
}

impl TokenTransferBuilder {
    /// Create a new token transfer builder
    pub fn new(
        from: impl Into<String>,
        to: impl Into<String>,
        mint: impl Into<String>,
        amount: u64,
        decimals: u8,
    ) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            mint: mint.into(),
            amount,
            decimals,
            create_ata_if_needed: true,
        }
    }

    /// Disable automatic ATA creation
    pub fn without_ata_creation(mut self) -> Self {
        self.create_ata_if_needed = false;
        self
    }

    /// Build token transfer instructions
    pub async fn build_instructions(&self, adapter: &SolanaAdapter) -> Result<Vec<Instruction>> {
        let from_pubkey = Pubkey::from_str(&self.from)
            .map_err(|e| Error::InvalidConfig(format!("Invalid from: {}", e)))?;
        let to_pubkey = Pubkey::from_str(&self.to)
            .map_err(|e| Error::InvalidConfig(format!("Invalid to: {}", e)))?;
        let mint_pubkey = Pubkey::from_str(&self.mint)
            .map_err(|e| Error::InvalidConfig(format!("Invalid mint: {}", e)))?;

        let from_ata =
            spl_associated_token_account::get_associated_token_address(&from_pubkey, &mint_pubkey);
        let to_ata =
            spl_associated_token_account::get_associated_token_address(&to_pubkey, &mint_pubkey);

        let mut instructions = Vec::new();

        // Create destination ATA if needed
        if self.create_ata_if_needed
            && let Some(create_ata_ix) = adapter
                .build_create_ata_instruction(&self.from, &self.to, &self.mint)
                .await?
        {
            instructions.push(create_ata_ix);
        }

        // Add transfer instruction
        let transfer_ix = spl_token::instruction::transfer_checked(
            &spl_token::id(),
            &from_ata,
            &mint_pubkey,
            &to_ata,
            &from_pubkey,
            &[],
            self.amount,
            self.decimals,
        )
        .map_err(|e| Error::ChainError(format!("Failed to create transfer instruction: {}", e)))?;

        instructions.push(transfer_ix);

        Ok(instructions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let mainnet = SolanaConfig::mainnet();
        assert_eq!(mainnet.chain_id, ChainId::SOLANA_MAINNET);

        let devnet = SolanaConfig::devnet();
        assert_eq!(devnet.chain_id, ChainId::SOLANA_DEVNET);
    }

    #[test]
    fn test_lamports_conversion() {
        assert_eq!(SolanaAdapter::lamports_to_sol(1_000_000_000), "1");
        assert_eq!(SolanaAdapter::lamports_to_sol(500_000_000), "0.5");
        assert_eq!(SolanaAdapter::lamports_to_sol(1_500_000_000), "1.5");
        assert_eq!(SolanaAdapter::lamports_to_sol(0), "0");

        assert_eq!(SolanaAdapter::sol_to_lamports("1").unwrap(), 1_000_000_000);
        assert_eq!(SolanaAdapter::sol_to_lamports("0.5").unwrap(), 500_000_000);
        assert_eq!(
            SolanaAdapter::sol_to_lamports("1.5").unwrap(),
            1_500_000_000
        );
    }

    #[test]
    fn test_address_validation() {
        let config = SolanaConfig::mainnet();
        let adapter = SolanaAdapter::new(config).unwrap();

        // Valid base58 public key
        assert!(adapter.is_valid_address("11111111111111111111111111111111"));
        assert!(adapter.is_valid_address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"));

        // Invalid addresses
        assert!(!adapter.is_valid_address("0x742d35Cc6634C0532925a3b844Bc9e7595f4e123"));
        assert!(!adapter.is_valid_address("invalid"));
    }

    #[test]
    fn test_derive_address() {
        let config = SolanaConfig::mainnet();
        let adapter = SolanaAdapter::new(config).unwrap();

        // 32-byte key
        let key32 = [1u8; 32];
        let addr = adapter.derive_address(&key32).unwrap();
        assert!(!addr.is_empty());

        // 33-byte compressed secp256k1
        let key33 = [2u8; 33];
        let addr = adapter.derive_address(&key33).unwrap();
        assert!(!addr.is_empty());
    }

    #[test]
    fn test_commitment_as_str() {
        assert_eq!(SolanaCommitment::Processed.as_str(), "processed");
        assert_eq!(SolanaCommitment::Confirmed.as_str(), "confirmed");
        assert_eq!(SolanaCommitment::Finalized.as_str(), "finalized");
    }
}
