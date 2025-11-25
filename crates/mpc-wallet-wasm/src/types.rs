//! WASM-compatible type definitions
//!
//! These types are designed for easy serialization between Rust and JavaScript.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Party role in the MPC wallet
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartyRole {
    /// AI agent party
    Agent = 0,
    /// User party
    User = 1,
    /// Recovery guardian party
    Recovery = 2,
}

impl From<mpc_wallet_core::PartyRole> for PartyRole {
    fn from(role: mpc_wallet_core::PartyRole) -> Self {
        match role {
            mpc_wallet_core::PartyRole::Agent => PartyRole::Agent,
            mpc_wallet_core::PartyRole::User => PartyRole::User,
            mpc_wallet_core::PartyRole::Recovery => PartyRole::Recovery,
        }
    }
}

impl From<PartyRole> for mpc_wallet_core::PartyRole {
    fn from(role: PartyRole) -> Self {
        match role {
            PartyRole::Agent => mpc_wallet_core::PartyRole::Agent,
            PartyRole::User => mpc_wallet_core::PartyRole::User,
            PartyRole::Recovery => mpc_wallet_core::PartyRole::Recovery,
        }
    }
}

/// Blockchain type
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainType {
    /// Ethereum and EVM-compatible chains
    Evm = 0,
    /// Solana
    Solana = 1,
    /// Bitcoin
    Bitcoin = 2,
}

impl From<mpc_wallet_core::ChainType> for ChainType {
    fn from(chain: mpc_wallet_core::ChainType) -> Self {
        match chain {
            mpc_wallet_core::ChainType::Evm => ChainType::Evm,
            mpc_wallet_core::ChainType::Solana => ChainType::Solana,
            mpc_wallet_core::ChainType::Bitcoin => ChainType::Bitcoin,
        }
    }
}

impl From<ChainType> for mpc_wallet_core::ChainType {
    fn from(chain: ChainType) -> Self {
        match chain {
            ChainType::Evm => mpc_wallet_core::ChainType::Evm,
            ChainType::Solana => mpc_wallet_core::ChainType::Solana,
            ChainType::Bitcoin => mpc_wallet_core::ChainType::Bitcoin,
        }
    }
}

/// ECDSA signature
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// R component (32 bytes, hex)
    pub r: String,
    /// S component (32 bytes, hex)
    pub s: String,
    /// Recovery ID (0 or 1)
    #[wasm_bindgen(js_name = recoveryId)]
    pub recovery_id: u8,
}

#[wasm_bindgen]
impl Signature {
    /// Create a new signature
    #[wasm_bindgen(constructor)]
    pub fn new(r: String, s: String, recovery_id: u8) -> Self {
        Self { r, s, recovery_id }
    }

    /// Convert to bytes (r || s || v)
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsValue> {
        let r = hex::decode(self.r.strip_prefix("0x").unwrap_or(&self.r))
            .map_err(|e| JsValue::from_str(&format!("Invalid r: {}", e)))?;
        let s = hex::decode(self.s.strip_prefix("0x").unwrap_or(&self.s))
            .map_err(|e| JsValue::from_str(&format!("Invalid s: {}", e)))?;

        let mut bytes = Vec::with_capacity(65);
        bytes.extend_from_slice(&r);
        bytes.extend_from_slice(&s);
        bytes.push(self.recovery_id + 27);
        Ok(bytes)
    }

    /// Convert to hex string (0x prefixed)
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> Result<String, JsValue> {
        let bytes = self.to_bytes()?;
        Ok(format!("0x{}", hex::encode(bytes)))
    }

    /// Convert to EIP-155 format for Ethereum
    #[wasm_bindgen(js_name = toEip155)]
    pub fn to_eip155(&self, chain_id: u64) -> Result<Vec<u8>, JsValue> {
        let r = hex::decode(self.r.strip_prefix("0x").unwrap_or(&self.r))
            .map_err(|e| JsValue::from_str(&format!("Invalid r: {}", e)))?;
        let s = hex::decode(self.s.strip_prefix("0x").unwrap_or(&self.s))
            .map_err(|e| JsValue::from_str(&format!("Invalid s: {}", e)))?;

        let mut bytes = Vec::with_capacity(65);
        bytes.extend_from_slice(&r);
        bytes.extend_from_slice(&s);

        // v = recovery_id + 35 + chain_id * 2
        let v = self.recovery_id as u64 + 35 + chain_id * 2;
        bytes.push(v as u8);
        Ok(bytes)
    }
}

impl From<mpc_wallet_core::Signature> for Signature {
    fn from(sig: mpc_wallet_core::Signature) -> Self {
        Self {
            r: format!("0x{}", hex::encode(sig.r)),
            s: format!("0x{}", hex::encode(sig.s)),
            recovery_id: sig.recovery_id,
        }
    }
}

/// Key share metadata (non-sensitive)
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShareInfo {
    /// Share identifier
    #[wasm_bindgen(js_name = shareId)]
    pub share_id: String,
    /// Party role
    pub role: PartyRole,
    /// Public key (compressed, hex)
    #[wasm_bindgen(js_name = publicKey)]
    pub public_key: String,
    /// Ethereum address
    #[wasm_bindgen(js_name = ethAddress)]
    pub eth_address: String,
    /// Creation timestamp (Unix seconds)
    #[wasm_bindgen(js_name = createdAt)]
    pub created_at: i64,
}

#[wasm_bindgen]
impl KeyShareInfo {
    /// Get the party ID (0, 1, or 2)
    #[wasm_bindgen(js_name = partyId)]
    pub fn party_id(&self) -> u8 {
        match self.role {
            PartyRole::Agent => 0,
            PartyRole::User => 1,
            PartyRole::Recovery => 2,
        }
    }

    /// Get as JSON string
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

/// Transaction request for signing
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRequest {
    /// Request ID
    #[wasm_bindgen(js_name = requestId)]
    pub request_id: String,
    /// Target chain
    pub chain: ChainType,
    /// Recipient address
    pub to: String,
    /// Value to send (in wei/lamports as string)
    pub value: String,
    /// Transaction data (hex)
    pub data: Option<String>,
    /// Gas limit
    #[wasm_bindgen(js_name = gasLimit)]
    pub gas_limit: Option<u64>,
    /// Chain ID
    #[wasm_bindgen(js_name = chainId)]
    pub chain_id: Option<u64>,
}

#[wasm_bindgen]
impl TransactionRequest {
    /// Create a new transaction request
    #[wasm_bindgen(constructor)]
    pub fn new(chain: ChainType, to: String, value: String) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            chain,
            to,
            value,
            data: None,
            gas_limit: None,
            chain_id: None,
        }
    }

    /// Set transaction data
    #[wasm_bindgen(js_name = withData)]
    pub fn with_data(mut self, data: String) -> Self {
        self.data = Some(data);
        self
    }

    /// Set gas limit
    #[wasm_bindgen(js_name = withGasLimit)]
    pub fn with_gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = Some(gas_limit);
        self
    }

    /// Set chain ID
    #[wasm_bindgen(js_name = withChainId)]
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Convert to JSON
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Create from JSON
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(json: &str) -> Result<TransactionRequest, JsValue> {
        serde_json::from_str(json).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

impl From<&TransactionRequest> for mpc_wallet_core::TransactionRequest {
    fn from(req: &TransactionRequest) -> Self {
        let mut tx = mpc_wallet_core::TransactionRequest::new(
            req.chain.into(),
            req.to.clone(),
            req.value.clone(),
        );

        if let Some(ref data) = req.data {
            let data_bytes =
                hex::decode(data.strip_prefix("0x").unwrap_or(data)).unwrap_or_default();
            tx = tx.with_data(data_bytes);
        }

        if let Some(gas_limit) = req.gas_limit {
            tx = tx.with_gas_limit(gas_limit);
        }

        if let Some(chain_id) = req.chain_id {
            tx = tx.with_chain_id(chain_id);
        }

        tx
    }
}

/// Balance information
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {
    /// Raw balance (smallest unit)
    pub raw: String,
    /// Formatted balance with decimals
    pub formatted: String,
    /// Token symbol
    pub symbol: String,
    /// Number of decimals
    pub decimals: u8,
}

#[wasm_bindgen]
impl Balance {
    /// Check if balance is zero
    #[wasm_bindgen(js_name = isZero)]
    pub fn is_zero(&self) -> bool {
        self.raw == "0" || self.raw.is_empty()
    }
}

impl From<mpc_wallet_core::chain::Balance> for Balance {
    fn from(b: mpc_wallet_core::chain::Balance) -> Self {
        Self {
            raw: b.raw,
            formatted: b.formatted,
            symbol: b.symbol,
            decimals: b.decimals,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_party_role_conversion() {
        assert_eq!(PartyRole::Agent as u8, 0);
        assert_eq!(PartyRole::User as u8, 1);
        assert_eq!(PartyRole::Recovery as u8, 2);
    }

    #[wasm_bindgen_test]
    fn test_transaction_request() {
        let tx = TransactionRequest::new(ChainType::Evm, "0x1234".to_string(), "1000".to_string())
            .with_gas_limit(21000)
            .with_chain_id(1);

        assert_eq!(tx.gas_limit, Some(21000));
        assert_eq!(tx.chain_id, Some(1));
    }

    #[wasm_bindgen_test]
    fn test_signature() {
        let sig = Signature::new(
            "0x".to_string() + &"ab".repeat(32),
            "0x".to_string() + &"cd".repeat(32),
            0,
        );

        let bytes = sig.to_bytes().unwrap();
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[64], 27); // v = recovery_id + 27
    }
}
