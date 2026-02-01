//! Agent Identity Module for ERC-8004 Integration
//!
//! Provides agent registration, identity management, and registration file generation
//! for the ERC-8004 Identity Registry.
//!
//! ## Overview
//!
//! The Identity Registry (ERC-721) provides portable agent handles pointing to
//! registration files stored on IPFS, Arweave, or other decentralized storage.
//!
//! ## Example
//!
//! ```rust,ignore
//! use mpc_wallet_core::agent_identity::{AgentIdentityManager, AgentRegistrationConfig};
//!
//! let manager = AgentIdentityManager::new(rpc_url, identity_registry_address);
//!
//! // Generate registration file
//! let config = AgentRegistrationConfig::new("my-agent", "A helpful AI assistant")
//!     .with_service("chat", "https://api.example.com/chat")
//!     .with_trust_model(TrustModel::TeeAttestation);
//!
//! let registration_file = manager.generate_registration_file(config)?;
//! ```

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const IDENTITY_REGISTRY_ADDRESS: &str = "0x7177a6867296406881E20d6647232314736Dd09A";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustModel {
    Reputation,
    CryptoEconomic,
    TeeAttestation,
    ZkMl,
}

impl TrustModel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustModel::Reputation => "reputation",
            TrustModel::CryptoEconomic => "crypto_economic",
            TrustModel::TeeAttestation => "tee_attestation",
            TrustModel::ZkMl => "zkml",
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
}

impl std::fmt::Display for TrustModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentService {
    pub name: String,
    pub endpoint: String,
    pub description: Option<String>,
    pub methods: Vec<String>,
    pub rate_limit: Option<RateLimit>,
}

impl AgentService {
    pub fn new(name: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            endpoint: endpoint.into(),
            description: None,
            methods: Vec::new(),
            rate_limit: None,
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_methods(mut self, methods: Vec<String>) -> Self {
        self.methods = methods;
        self
    }

    pub fn with_rate_limit(mut self, requests_per_minute: u32) -> Self {
        self.rate_limit = Some(RateLimit {
            requests_per_minute,
        });
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub requests_per_minute: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCapability {
    pub name: String,
    pub version: String,
    pub parameters: HashMap<String, serde_json::Value>,
}

impl AgentCapability {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            parameters: HashMap::new(),
        }
    }

    pub fn with_parameter(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.parameters.insert(key.into(), value.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRegistrationFile {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "@type")]
    pub type_field: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub services: Vec<AgentService>,
    pub capabilities: Vec<AgentCapability>,
    pub trust_models: Vec<TrustModel>,
    pub metadata: HashMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_policy: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl AgentRegistrationFile {
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::Serialization(e.to_string()))
    }

    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| Error::Deserialization(e.to_string()))
    }

    pub fn content_hash(&self) -> Result<[u8; 32]> {
        let json = self.to_json()?;
        let hash = blake3::hash(json.as_bytes());
        Ok(*hash.as_bytes())
    }
}

#[derive(Debug, Clone)]
pub struct AgentRegistrationConfig {
    pub name: String,
    pub description: String,
    pub version: String,
    pub services: Vec<AgentService>,
    pub capabilities: Vec<AgentCapability>,
    pub trust_models: Vec<TrustModel>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub icon_url: Option<String>,
    pub website: Option<String>,
    pub terms_of_service: Option<String>,
    pub privacy_policy: Option<String>,
}

impl AgentRegistrationConfig {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            version: "1.0.0".to_string(),
            services: Vec::new(),
            capabilities: Vec::new(),
            trust_models: vec![TrustModel::Reputation],
            metadata: HashMap::new(),
            icon_url: None,
            website: None,
            terms_of_service: None,
            privacy_policy: None,
        }
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    pub fn with_service(mut self, service: AgentService) -> Self {
        self.services.push(service);
        self
    }

    pub fn with_capability(mut self, capability: AgentCapability) -> Self {
        self.capabilities.push(capability);
        self
    }

    pub fn with_trust_model(mut self, model: TrustModel) -> Self {
        if !self.trust_models.contains(&model) {
            self.trust_models.push(model);
        }
        self
    }

    pub fn with_metadata(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn with_icon_url(mut self, url: impl Into<String>) -> Self {
        self.icon_url = Some(url.into());
        self
    }

    pub fn with_website(mut self, url: impl Into<String>) -> Self {
        self.website = Some(url.into());
        self
    }

    pub fn with_terms_of_service(mut self, url: impl Into<String>) -> Self {
        self.terms_of_service = Some(url.into());
        self
    }

    pub fn with_privacy_policy(mut self, url: impl Into<String>) -> Self {
        self.privacy_policy = Some(url.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub agent_id: u64,
    pub owner: String,
    pub agent_uri: String,
    pub wallet_address: Option<String>,
    pub metadata: HashMap<String, Vec<u8>>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl AgentIdentity {
    pub fn is_wallet_linked(&self) -> bool {
        self.wallet_address.is_some()
            && self.wallet_address.as_ref() != Some(&"0x0000000000000000000000000000000000000000".to_string())
    }
}

#[derive(Debug, Clone)]
pub struct AgentIdentityManager {
    identity_registry: String,
}

impl AgentIdentityManager {
    pub fn new() -> Self {
        Self {
            identity_registry: IDENTITY_REGISTRY_ADDRESS.to_string(),
        }
    }

    pub fn with_registry_address(mut self, address: impl Into<String>) -> Self {
        self.identity_registry = address.into();
        self
    }

    pub fn registry_address(&self) -> &str {
        &self.identity_registry
    }

    pub fn generate_registration_file(
        &self,
        config: AgentRegistrationConfig,
    ) -> Result<AgentRegistrationFile> {
        if config.name.is_empty() {
            return Err(Error::InvalidConfig(
                "Agent name cannot be empty".to_string(),
            ));
        }

        if config.description.is_empty() {
            return Err(Error::InvalidConfig(
                "Agent description cannot be empty".to_string(),
            ));
        }

        let now = chrono::Utc::now().timestamp();

        Ok(AgentRegistrationFile {
            context: vec![
                "https://schema.org".to_string(),
                "https://erc8004.org/v1".to_string(),
            ],
            type_field: "AIAgent".to_string(),
            name: config.name,
            description: config.description,
            version: config.version,
            services: config.services,
            capabilities: config.capabilities,
            trust_models: config.trust_models,
            metadata: config.metadata,
            icon_url: config.icon_url,
            website: config.website,
            terms_of_service: config.terms_of_service,
            privacy_policy: config.privacy_policy,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn encode_register_calldata(&self, agent_uri: &str) -> Result<Vec<u8>> {
        if agent_uri.is_empty() {
            return Err(Error::InvalidConfig(
                "Agent URI cannot be empty".to_string(),
            ));
        }

        let function_selector = [0x1a, 0xab, 0x38, 0x8b];
        let uri_bytes = agent_uri.as_bytes();
        let uri_len = uri_bytes.len();

        let mut calldata = Vec::with_capacity(4 + 32 + 32 + ((uri_len + 31) / 32) * 32);
        calldata.extend_from_slice(&function_selector);

        let mut offset = [0u8; 32];
        offset[31] = 0x20;
        calldata.extend_from_slice(&offset);

        let mut length = [0u8; 32];
        length[24..32].copy_from_slice(&(uri_len as u64).to_be_bytes());
        calldata.extend_from_slice(&length);

        let padded_len = ((uri_len + 31) / 32) * 32;
        let mut padded_uri = vec![0u8; padded_len];
        padded_uri[..uri_len].copy_from_slice(uri_bytes);
        calldata.extend_from_slice(&padded_uri);

        Ok(calldata)
    }

    pub fn encode_set_agent_uri_calldata(&self, agent_id: u64, new_uri: &str) -> Result<Vec<u8>> {
        if new_uri.is_empty() {
            return Err(Error::InvalidConfig(
                "New URI cannot be empty".to_string(),
            ));
        }

        let function_selector = [0x82, 0x06, 0x77, 0xc7];
        let uri_bytes = new_uri.as_bytes();
        let uri_len = uri_bytes.len();

        let mut calldata = Vec::with_capacity(4 + 32 + 32 + 32 + ((uri_len + 31) / 32) * 32);
        calldata.extend_from_slice(&function_selector);

        let mut agent_id_bytes = [0u8; 32];
        agent_id_bytes[24..32].copy_from_slice(&agent_id.to_be_bytes());
        calldata.extend_from_slice(&agent_id_bytes);

        let mut offset = [0u8; 32];
        offset[31] = 0x40;
        calldata.extend_from_slice(&offset);

        let mut length = [0u8; 32];
        length[24..32].copy_from_slice(&(uri_len as u64).to_be_bytes());
        calldata.extend_from_slice(&length);

        let padded_len = ((uri_len + 31) / 32) * 32;
        let mut padded_uri = vec![0u8; padded_len];
        padded_uri[..uri_len].copy_from_slice(uri_bytes);
        calldata.extend_from_slice(&padded_uri);

        Ok(calldata)
    }

    pub fn encode_set_agent_wallet_calldata(
        &self,
        agent_id: u64,
        wallet: &str,
        deadline: u64,
        signature: &[u8],
    ) -> Result<Vec<u8>> {
        let wallet_bytes = self.parse_address(wallet)?;

        let function_selector = [0x5a, 0x1c, 0x72, 0x4e];

        let mut calldata = Vec::with_capacity(4 + 32 + 32 + 32 + 32 + 32 + ((signature.len() + 31) / 32) * 32);
        calldata.extend_from_slice(&function_selector);

        let mut agent_id_bytes = [0u8; 32];
        agent_id_bytes[24..32].copy_from_slice(&agent_id.to_be_bytes());
        calldata.extend_from_slice(&agent_id_bytes);

        let mut wallet_padded = [0u8; 32];
        wallet_padded[12..32].copy_from_slice(&wallet_bytes);
        calldata.extend_from_slice(&wallet_padded);

        let mut deadline_bytes = [0u8; 32];
        deadline_bytes[24..32].copy_from_slice(&deadline.to_be_bytes());
        calldata.extend_from_slice(&deadline_bytes);

        let mut offset = [0u8; 32];
        offset[31] = 0x80;
        calldata.extend_from_slice(&offset);

        let mut sig_len = [0u8; 32];
        sig_len[24..32].copy_from_slice(&(signature.len() as u64).to_be_bytes());
        calldata.extend_from_slice(&sig_len);

        let padded_len = ((signature.len() + 31) / 32) * 32;
        let mut padded_sig = vec![0u8; padded_len];
        padded_sig[..signature.len()].copy_from_slice(signature);
        calldata.extend_from_slice(&padded_sig);

        Ok(calldata)
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

impl Default for AgentIdentityManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct AgentRegistrationBuilder {
    config: AgentRegistrationConfig,
}

impl AgentRegistrationBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            config: AgentRegistrationConfig::new(name, ""),
        }
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.config.description = description.into();
        self
    }

    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.config.version = version.into();
        self
    }

    pub fn add_service(
        mut self,
        name: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Self {
        self.config.services.push(AgentService::new(name, endpoint));
        self
    }

    pub fn add_capability(
        mut self,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        self.config.capabilities.push(AgentCapability::new(name, version));
        self
    }

    pub fn trust_model(mut self, model: TrustModel) -> Self {
        if !self.config.trust_models.contains(&model) {
            self.config.trust_models.push(model);
        }
        self
    }

    pub fn metadata(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.config.metadata.insert(key.into(), value.into());
        self
    }

    pub fn icon(mut self, url: impl Into<String>) -> Self {
        self.config.icon_url = Some(url.into());
        self
    }

    pub fn website(mut self, url: impl Into<String>) -> Self {
        self.config.website = Some(url.into());
        self
    }

    pub fn build(self) -> Result<AgentRegistrationConfig> {
        if self.config.name.is_empty() {
            return Err(Error::InvalidConfig("Agent name is required".to_string()));
        }
        if self.config.description.is_empty() {
            return Err(Error::InvalidConfig(
                "Agent description is required".to_string(),
            ));
        }
        Ok(self.config)
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
    fn registration_config_builder() {
        let config = AgentRegistrationConfig::new("test-agent", "A test agent")
            .with_version("2.0.0")
            .with_trust_model(TrustModel::TeeAttestation)
            .with_website("https://example.com");

        assert_eq!(config.name, "test-agent");
        assert_eq!(config.version, "2.0.0");
        assert!(config.trust_models.contains(&TrustModel::TeeAttestation));
    }

    #[test]
    fn generate_registration_file() {
        let manager = AgentIdentityManager::new();
        let config = AgentRegistrationConfig::new("my-agent", "My helpful agent")
            .with_service(AgentService::new("chat", "https://api.example.com/chat"));

        let file = manager.generate_registration_file(config).unwrap();

        assert_eq!(file.name, "my-agent");
        assert_eq!(file.type_field, "AIAgent");
        assert_eq!(file.services.len(), 1);
    }

    #[test]
    fn registration_file_serialization() {
        let manager = AgentIdentityManager::new();
        let config = AgentRegistrationConfig::new("test", "Test agent");
        let file = manager.generate_registration_file(config).unwrap();

        let json = file.to_json().unwrap();
        let parsed = AgentRegistrationFile::from_json(&json).unwrap();

        assert_eq!(file.name, parsed.name);
    }

    #[test]
    fn empty_name_validation() {
        let manager = AgentIdentityManager::new();
        let config = AgentRegistrationConfig::new("", "Description");
        let result = manager.generate_registration_file(config);

        assert!(result.is_err());
    }

    #[test]
    fn encode_register_calldata() {
        let manager = AgentIdentityManager::new();
        let calldata = manager
            .encode_register_calldata("ipfs://QmTest")
            .unwrap();

        assert_eq!(&calldata[..4], &[0x1a, 0xab, 0x38, 0x8b]);
    }

    #[test]
    fn agent_identity_wallet_check() {
        let identity = AgentIdentity {
            agent_id: 1,
            owner: "0x1234".to_string(),
            agent_uri: "ipfs://test".to_string(),
            wallet_address: Some("0x5678".to_string()),
            metadata: HashMap::new(),
            created_at: 0,
            updated_at: 0,
        };

        assert!(identity.is_wallet_linked());

        let unlinked = AgentIdentity {
            wallet_address: Some("0x0000000000000000000000000000000000000000".to_string()),
            ..identity.clone()
        };

        assert!(!unlinked.is_wallet_linked());
    }

    #[test]
    fn registration_builder_pattern() {
        let config = AgentRegistrationBuilder::new("builder-agent")
            .description("Built with builder")
            .version("1.0.0")
            .add_service("api", "https://api.example.com")
            .trust_model(TrustModel::ZkMl)
            .build()
            .unwrap();

        assert_eq!(config.name, "builder-agent");
        assert_eq!(config.services.len(), 1);
    }

    #[test]
    fn builder_validation() {
        let result = AgentRegistrationBuilder::new("")
            .description("test")
            .build();

        assert!(result.is_err());
    }
}
