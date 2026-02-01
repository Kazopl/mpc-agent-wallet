//! Validation Module for ERC-8004 Integration
//!
//! Provides validation request management for the ERC-8004 Validation Registry.
//! Supports TEE, zkML, and stake-based validation models.
//!
//! ## Overview
//!
//! The Validation Registry enables independent validator attestations for AI agents.
//! Validators can provide TEE attestations, zkML proofs, or stake-based guarantees.
//!
//! ## Example
//!
//! ```rust,ignore
//! use mpc_wallet_core::validation::{ValidationManager, ValidationRequestParams, TrustModel};
//!
//! let manager = ValidationManager::new();
//!
//! // Submit validation request
//! let params = ValidationRequestParams::new(validator, agent_id)
//!     .with_request_uri("ipfs://QmRequest")
//!     .with_content_hash(content_hash)
//!     .with_trust_model(TrustModel::TeeAttestation);
//!
//! let calldata = manager.encode_validation_request_calldata(&params)?;
//! ```

use crate::{Error, Result};
use serde::{Deserialize, Serialize};

pub const VALIDATION_REGISTRY_ADDRESS: &str = "0x662b40A526cb4017d947e71eAF6753BF3eeE66d8";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustModel {
    Reputation,
    CryptoEconomic,
    TeeAttestation,
    ZkMl,
}

impl TrustModel {
    pub fn as_u8(&self) -> u8 {
        match self {
            TrustModel::Reputation => 0,
            TrustModel::CryptoEconomic => 1,
            TrustModel::TeeAttestation => 2,
            TrustModel::ZkMl => 3,
        }
    }

    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(TrustModel::Reputation),
            1 => Ok(TrustModel::CryptoEconomic),
            2 => Ok(TrustModel::TeeAttestation),
            3 => Ok(TrustModel::ZkMl),
            _ => Err(Error::InvalidConfig(format!(
                "Invalid trust model value: {}",
                value
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TrustModel::Reputation => "reputation",
            TrustModel::CryptoEconomic => "crypto_economic",
            TrustModel::TeeAttestation => "tee_attestation",
            TrustModel::ZkMl => "zkml",
        }
    }
}

impl std::fmt::Display for TrustModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationResponse {
    Pending,
    Approved,
    Rejected,
    Expired,
}

impl ValidationResponse {
    pub fn as_u8(&self) -> u8 {
        match self {
            ValidationResponse::Pending => 0,
            ValidationResponse::Approved => 1,
            ValidationResponse::Rejected => 2,
            ValidationResponse::Expired => 3,
        }
    }

    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(ValidationResponse::Pending),
            1 => Ok(ValidationResponse::Approved),
            2 => Ok(ValidationResponse::Rejected),
            3 => Ok(ValidationResponse::Expired),
            _ => Err(Error::InvalidConfig(format!(
                "Invalid validation response value: {}",
                value
            ))),
        }
    }

    pub fn is_final(&self) -> bool {
        matches!(
            self,
            ValidationResponse::Approved
                | ValidationResponse::Rejected
                | ValidationResponse::Expired
        )
    }

    pub fn is_success(&self) -> bool {
        matches!(self, ValidationResponse::Approved)
    }
}

impl std::fmt::Display for ValidationResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ValidationResponse::Pending => "pending",
            ValidationResponse::Approved => "approved",
            ValidationResponse::Rejected => "rejected",
            ValidationResponse::Expired => "expired",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRequest {
    pub request_hash: [u8; 32],
    pub requester: String,
    pub validator: String,
    pub agent_id: u64,
    pub request_uri: String,
    pub content_hash: [u8; 32],
    pub timestamp: u64,
    pub expires_at: u64,
    pub response: ValidationResponse,
    pub response_data: Vec<u8>,
    pub trust_model: TrustModel,
}

impl ValidationRequest {
    pub fn is_pending(&self) -> bool {
        self.response == ValidationResponse::Pending
    }

    pub fn is_expired(&self) -> bool {
        self.response == ValidationResponse::Expired
    }

    pub fn is_approved(&self) -> bool {
        self.response == ValidationResponse::Approved
    }

    pub fn is_rejected(&self) -> bool {
        self.response == ValidationResponse::Rejected
    }

    pub fn has_response_data(&self) -> bool {
        !self.response_data.is_empty()
    }

    pub fn time_remaining(&self, current_timestamp: u64) -> Option<u64> {
        if self.expires_at > current_timestamp {
            Some(self.expires_at - current_timestamp)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeAttestation {
    pub enclave_quote: Vec<u8>,
    pub enclave_measurement: [u8; 32],
    pub report_data: Vec<u8>,
    pub timestamp: u64,
    pub platform: String,
}

impl TeeAttestation {
    pub fn new(
        enclave_quote: Vec<u8>,
        enclave_measurement: [u8; 32],
        platform: impl Into<String>,
    ) -> Self {
        Self {
            enclave_quote,
            enclave_measurement,
            report_data: Vec::new(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            platform: platform.into(),
        }
    }

    pub fn with_report_data(mut self, data: Vec<u8>) -> Self {
        self.report_data = data;
        self
    }

    pub fn to_response_data(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| Error::Serialization(e.to_string()))
    }

    pub fn from_response_data(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).map_err(|e| Error::Deserialization(e.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkMlProof {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
    pub verification_key_hash: [u8; 32],
    pub model_hash: [u8; 32],
    pub timestamp: u64,
}

impl ZkMlProof {
    pub fn new(
        proof: Vec<u8>,
        verification_key_hash: [u8; 32],
        model_hash: [u8; 32],
    ) -> Self {
        Self {
            proof,
            public_inputs: Vec::new(),
            verification_key_hash,
            model_hash,
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }

    pub fn with_public_inputs(mut self, inputs: Vec<[u8; 32]>) -> Self {
        self.public_inputs = inputs;
        self
    }

    pub fn to_response_data(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| Error::Serialization(e.to_string()))
    }

    pub fn from_response_data(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).map_err(|e| Error::Deserialization(e.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct ValidationRequestParams {
    pub validator: String,
    pub agent_id: u64,
    pub request_uri: String,
    pub content_hash: [u8; 32],
}

impl ValidationRequestParams {
    pub fn new(validator: impl Into<String>, agent_id: u64) -> Self {
        Self {
            validator: validator.into(),
            agent_id,
            request_uri: String::new(),
            content_hash: [0u8; 32],
        }
    }

    pub fn with_request_uri(mut self, uri: impl Into<String>) -> Self {
        self.request_uri = uri.into();
        self
    }

    pub fn with_content_hash(mut self, hash: [u8; 32]) -> Self {
        self.content_hash = hash;
        self
    }

    pub fn with_content_hash_hex(mut self, hash_hex: &str) -> Result<Self> {
        let hash_hex = hash_hex.strip_prefix("0x").unwrap_or(hash_hex);
        if hash_hex.len() != 64 {
            return Err(Error::InvalidConfig(format!(
                "Invalid content hash length: expected 64 hex chars, got {}",
                hash_hex.len()
            )));
        }
        let bytes = hex::decode(hash_hex)?;
        self.content_hash.copy_from_slice(&bytes);
        Ok(self)
    }
}

#[derive(Debug, Clone)]
pub struct ValidationResponseParams {
    pub request_hash: [u8; 32],
    pub response: ValidationResponse,
    pub response_data: Vec<u8>,
}

impl ValidationResponseParams {
    pub fn approve(request_hash: [u8; 32]) -> Self {
        Self {
            request_hash,
            response: ValidationResponse::Approved,
            response_data: Vec::new(),
        }
    }

    pub fn reject(request_hash: [u8; 32]) -> Self {
        Self {
            request_hash,
            response: ValidationResponse::Rejected,
            response_data: Vec::new(),
        }
    }

    pub fn with_response_data(mut self, data: Vec<u8>) -> Self {
        self.response_data = data;
        self
    }

    pub fn with_tee_attestation(mut self, attestation: &TeeAttestation) -> Result<Self> {
        self.response_data = attestation.to_response_data()?;
        Ok(self)
    }

    pub fn with_zkml_proof(mut self, proof: &ZkMlProof) -> Result<Self> {
        self.response_data = proof.to_response_data()?;
        Ok(self)
    }
}

#[derive(Debug, Clone)]
pub struct ValidationManager {
    validation_registry: String,
}

impl ValidationManager {
    pub fn new() -> Self {
        Self {
            validation_registry: VALIDATION_REGISTRY_ADDRESS.to_string(),
        }
    }

    pub fn with_registry_address(mut self, address: impl Into<String>) -> Self {
        self.validation_registry = address.into();
        self
    }

    pub fn registry_address(&self) -> &str {
        &self.validation_registry
    }

    pub fn encode_validation_request_calldata(
        &self,
        params: &ValidationRequestParams,
    ) -> Result<Vec<u8>> {
        self.validate_request_params(params)?;

        let validator_bytes = self.parse_address(&params.validator)?;
        let function_selector = [0x6a, 0x82, 0x1d, 0x13];

        let uri_bytes = params.request_uri.as_bytes();
        let uri_len = uri_bytes.len();
        let uri_padded_len = ((uri_len + 31) / 32) * 32;

        let mut calldata = Vec::with_capacity(4 + 32 + 32 + 32 + 32 + 32 + uri_padded_len);
        calldata.extend_from_slice(&function_selector);

        let mut validator_padded = [0u8; 32];
        validator_padded[12..32].copy_from_slice(&validator_bytes);
        calldata.extend_from_slice(&validator_padded);

        let mut agent_id_bytes = [0u8; 32];
        agent_id_bytes[24..32].copy_from_slice(&params.agent_id.to_be_bytes());
        calldata.extend_from_slice(&agent_id_bytes);

        let uri_offset: u64 = 0x80;
        let mut uri_offset_bytes = [0u8; 32];
        uri_offset_bytes[24..32].copy_from_slice(&uri_offset.to_be_bytes());
        calldata.extend_from_slice(&uri_offset_bytes);

        let mut content_hash_bytes = [0u8; 32];
        content_hash_bytes.copy_from_slice(&params.content_hash);
        calldata.extend_from_slice(&content_hash_bytes);

        let mut uri_len_bytes = [0u8; 32];
        uri_len_bytes[24..32].copy_from_slice(&(uri_len as u64).to_be_bytes());
        calldata.extend_from_slice(&uri_len_bytes);

        if uri_padded_len > 0 {
            let mut uri_padded = vec![0u8; uri_padded_len];
            uri_padded[..uri_len].copy_from_slice(uri_bytes);
            calldata.extend_from_slice(&uri_padded);
        }

        Ok(calldata)
    }

    pub fn encode_validation_response_calldata(
        &self,
        params: &ValidationResponseParams,
    ) -> Result<Vec<u8>> {
        if params.response == ValidationResponse::Pending {
            return Err(Error::InvalidConfig(
                "Cannot respond with Pending status".to_string(),
            ));
        }

        let function_selector = [0x4c, 0x4b, 0x0f, 0x2a];

        let response_data_len = params.response_data.len();
        let response_data_padded_len = ((response_data_len + 31) / 32) * 32;

        let mut calldata = Vec::with_capacity(4 + 32 + 32 + 32 + 32 + response_data_padded_len);
        calldata.extend_from_slice(&function_selector);

        let mut request_hash_bytes = [0u8; 32];
        request_hash_bytes.copy_from_slice(&params.request_hash);
        calldata.extend_from_slice(&request_hash_bytes);

        let mut response_bytes = [0u8; 32];
        response_bytes[31] = params.response.as_u8();
        calldata.extend_from_slice(&response_bytes);

        let data_offset: u64 = 0x60;
        let mut data_offset_bytes = [0u8; 32];
        data_offset_bytes[24..32].copy_from_slice(&data_offset.to_be_bytes());
        calldata.extend_from_slice(&data_offset_bytes);

        let mut data_len_bytes = [0u8; 32];
        data_len_bytes[24..32].copy_from_slice(&(response_data_len as u64).to_be_bytes());
        calldata.extend_from_slice(&data_len_bytes);

        if response_data_padded_len > 0 {
            let mut data_padded = vec![0u8; response_data_padded_len];
            data_padded[..response_data_len].copy_from_slice(&params.response_data);
            calldata.extend_from_slice(&data_padded);
        }

        Ok(calldata)
    }

    pub fn encode_get_validation_status_calldata(
        &self,
        request_hash: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let function_selector = [0x92, 0x74, 0x2c, 0x65];

        let mut calldata = Vec::with_capacity(4 + 32);
        calldata.extend_from_slice(&function_selector);
        calldata.extend_from_slice(request_hash);

        Ok(calldata)
    }

    pub fn encode_get_agent_validations_calldata(&self, agent_id: u64) -> Result<Vec<u8>> {
        let function_selector = [0x3d, 0x5a, 0x8a, 0x83];

        let mut calldata = Vec::with_capacity(4 + 32);
        calldata.extend_from_slice(&function_selector);

        let mut agent_id_bytes = [0u8; 32];
        agent_id_bytes[24..32].copy_from_slice(&agent_id.to_be_bytes());
        calldata.extend_from_slice(&agent_id_bytes);

        Ok(calldata)
    }

    pub fn encode_get_validator_requests_calldata(&self, validator: &str) -> Result<Vec<u8>> {
        let validator_bytes = self.parse_address(validator)?;
        let function_selector = [0x51, 0x8c, 0x2b, 0x78];

        let mut calldata = Vec::with_capacity(4 + 32);
        calldata.extend_from_slice(&function_selector);

        let mut validator_padded = [0u8; 32];
        validator_padded[12..32].copy_from_slice(&validator_bytes);
        calldata.extend_from_slice(&validator_padded);

        Ok(calldata)
    }

    pub fn encode_is_expired_calldata(&self, request_hash: &[u8; 32]) -> Result<Vec<u8>> {
        let function_selector = [0xd9, 0xd9, 0x8c, 0xe4];

        let mut calldata = Vec::with_capacity(4 + 32);
        calldata.extend_from_slice(&function_selector);
        calldata.extend_from_slice(request_hash);

        Ok(calldata)
    }

    pub fn compute_request_hash(
        &self,
        requester: &str,
        validator: &str,
        agent_id: u64,
        content_hash: &[u8; 32],
        timestamp: u64,
    ) -> Result<[u8; 32]> {
        let requester_bytes = self.parse_address(requester)?;
        let validator_bytes = self.parse_address(validator)?;

        let mut data = Vec::with_capacity(20 + 20 + 8 + 32 + 8);
        data.extend_from_slice(&requester_bytes);
        data.extend_from_slice(&validator_bytes);
        data.extend_from_slice(&agent_id.to_be_bytes());
        data.extend_from_slice(content_hash);
        data.extend_from_slice(&timestamp.to_be_bytes());

        use tiny_keccak::{Hasher, Keccak};
        let mut hasher = Keccak::v256();
        hasher.update(&data);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);

        Ok(hash)
    }

    fn validate_request_params(&self, params: &ValidationRequestParams) -> Result<()> {
        if params.request_uri.is_empty() {
            return Err(Error::InvalidConfig(
                "Request URI cannot be empty".to_string(),
            ));
        }

        self.parse_address(&params.validator)?;

        Ok(())
    }

    fn parse_address(&self, address: &str) -> Result<[u8; 20]> {
        let address = address.strip_prefix("0x").unwrap_or(address);
        if address.len() != 40 {
            return Err(Error::InvalidConfig(format!(
                "Invalid address length: expected 40 hex chars, got {}",
                address.len()
            )));
        }
        let bytes = hex::decode(address)?;
        let mut result = [0u8; 20];
        result.copy_from_slice(&bytes);
        Ok(result)
    }
}

impl Default for ValidationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct ValidationRequestBuilder {
    params: ValidationRequestParams,
}

impl ValidationRequestBuilder {
    pub fn new(validator: impl Into<String>, agent_id: u64) -> Self {
        Self {
            params: ValidationRequestParams::new(validator, agent_id),
        }
    }

    pub fn request_uri(mut self, uri: impl Into<String>) -> Self {
        self.params.request_uri = uri.into();
        self
    }

    pub fn content_hash(mut self, hash: [u8; 32]) -> Self {
        self.params.content_hash = hash;
        self
    }

    pub fn build(self) -> Result<ValidationRequestParams> {
        if self.params.request_uri.is_empty() {
            return Err(Error::InvalidConfig(
                "Request URI is required".to_string(),
            ));
        }
        Ok(self.params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_model_conversion() {
        assert_eq!(TrustModel::from_u8(0).unwrap(), TrustModel::Reputation);
        assert_eq!(TrustModel::from_u8(1).unwrap(), TrustModel::CryptoEconomic);
        assert_eq!(TrustModel::from_u8(2).unwrap(), TrustModel::TeeAttestation);
        assert_eq!(TrustModel::from_u8(3).unwrap(), TrustModel::ZkMl);
        assert!(TrustModel::from_u8(4).is_err());
    }

    #[test]
    fn validation_response_conversion() {
        assert_eq!(ValidationResponse::from_u8(0).unwrap(), ValidationResponse::Pending);
        assert_eq!(ValidationResponse::from_u8(1).unwrap(), ValidationResponse::Approved);
        assert_eq!(ValidationResponse::from_u8(2).unwrap(), ValidationResponse::Rejected);
        assert_eq!(ValidationResponse::from_u8(3).unwrap(), ValidationResponse::Expired);
        assert!(ValidationResponse::from_u8(4).is_err());
    }

    #[test]
    fn validation_response_properties() {
        assert!(!ValidationResponse::Pending.is_final());
        assert!(ValidationResponse::Approved.is_final());
        assert!(ValidationResponse::Rejected.is_final());
        assert!(ValidationResponse::Expired.is_final());

        assert!(ValidationResponse::Approved.is_success());
        assert!(!ValidationResponse::Rejected.is_success());
    }

    #[test]
    fn validation_request_properties() {
        let request = ValidationRequest {
            request_hash: [1u8; 32],
            requester: "0x1234".to_string(),
            validator: "0x5678".to_string(),
            agent_id: 1,
            request_uri: "ipfs://test".to_string(),
            content_hash: [2u8; 32],
            timestamp: 1000,
            expires_at: 2000,
            response: ValidationResponse::Pending,
            response_data: Vec::new(),
            trust_model: TrustModel::TeeAttestation,
        };

        assert!(request.is_pending());
        assert!(!request.is_approved());
        assert_eq!(request.time_remaining(1500), Some(500));
        assert_eq!(request.time_remaining(2500), None);
    }

    #[test]
    fn tee_attestation_serialization() {
        let attestation = TeeAttestation::new(
            vec![1, 2, 3, 4],
            [5u8; 32],
            "SGX",
        )
        .with_report_data(vec![6, 7, 8]);

        let data = attestation.to_response_data().unwrap();
        let parsed = TeeAttestation::from_response_data(&data).unwrap();

        assert_eq!(attestation.enclave_quote, parsed.enclave_quote);
        assert_eq!(attestation.platform, parsed.platform);
    }

    #[test]
    fn zkml_proof_serialization() {
        let proof = ZkMlProof::new(
            vec![1, 2, 3],
            [4u8; 32],
            [5u8; 32],
        )
        .with_public_inputs(vec![[6u8; 32]]);

        let data = proof.to_response_data().unwrap();
        let parsed = ZkMlProof::from_response_data(&data).unwrap();

        assert_eq!(proof.proof, parsed.proof);
        assert_eq!(proof.public_inputs.len(), parsed.public_inputs.len());
    }

    #[test]
    fn validation_request_params_builder() {
        let params = ValidationRequestParams::new(
            "0x1234567890123456789012345678901234567890",
            42,
        )
        .with_request_uri("ipfs://QmTest")
        .with_content_hash([1u8; 32]);

        assert_eq!(params.agent_id, 42);
        assert_eq!(params.request_uri, "ipfs://QmTest");
    }

    #[test]
    fn validation_response_params() {
        let approve = ValidationResponseParams::approve([1u8; 32]);
        assert_eq!(approve.response, ValidationResponse::Approved);

        let reject = ValidationResponseParams::reject([2u8; 32])
            .with_response_data(vec![1, 2, 3]);
        assert_eq!(reject.response, ValidationResponse::Rejected);
        assert_eq!(reject.response_data, vec![1, 2, 3]);
    }

    #[test]
    fn encode_validation_request_calldata() {
        let manager = ValidationManager::new();
        let params = ValidationRequestParams::new(
            "0x1234567890123456789012345678901234567890",
            1,
        )
        .with_request_uri("ipfs://test")
        .with_content_hash([0u8; 32]);

        let calldata = manager.encode_validation_request_calldata(&params).unwrap();

        assert_eq!(&calldata[..4], &[0x6a, 0x82, 0x1d, 0x13]);
    }

    #[test]
    fn encode_validation_response_calldata() {
        let manager = ValidationManager::new();
        let params = ValidationResponseParams::approve([1u8; 32]);

        let calldata = manager.encode_validation_response_calldata(&params).unwrap();

        assert_eq!(&calldata[..4], &[0x4c, 0x4b, 0x0f, 0x2a]);
    }

    #[test]
    fn pending_response_validation() {
        let manager = ValidationManager::new();
        let params = ValidationResponseParams {
            request_hash: [1u8; 32],
            response: ValidationResponse::Pending,
            response_data: Vec::new(),
        };

        let result = manager.encode_validation_response_calldata(&params);
        assert!(result.is_err());
    }

    #[test]
    fn empty_uri_validation() {
        let manager = ValidationManager::new();
        let params = ValidationRequestParams::new(
            "0x1234567890123456789012345678901234567890",
            1,
        );

        let result = manager.encode_validation_request_calldata(&params);
        assert!(result.is_err());
    }

    #[test]
    fn validation_request_builder() {
        let params = ValidationRequestBuilder::new(
            "0x1234567890123456789012345678901234567890",
            1,
        )
        .request_uri("ipfs://test")
        .content_hash([1u8; 32])
        .build()
        .unwrap();

        assert_eq!(params.request_uri, "ipfs://test");
    }

    #[test]
    fn builder_validation() {
        let result = ValidationRequestBuilder::new(
            "0x1234567890123456789012345678901234567890",
            1,
        )
        .build();

        assert!(result.is_err());
    }

    #[test]
    fn compute_request_hash() {
        let manager = ValidationManager::new();
        let hash = manager
            .compute_request_hash(
                "0x1234567890123456789012345678901234567890",
                "0xabcdef1234567890abcdef1234567890abcdef12",
                1,
                &[0u8; 32],
                1000,
            )
            .unwrap();

        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn content_hash_from_hex() {
        let params = ValidationRequestParams::new(
            "0x1234567890123456789012345678901234567890",
            1,
        )
        .with_content_hash_hex(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        )
        .unwrap();

        assert_eq!(params.content_hash[0], 0x12);
        assert_eq!(params.content_hash[31], 0xef);
    }
}
