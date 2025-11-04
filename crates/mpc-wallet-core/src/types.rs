//! Core types for MPC agent wallet
//!
//! This module defines the fundamental types used throughout the wallet SDK,
//! including key shares with role metadata, session configurations, and
//! transaction requests.

use crate::{Error, Result, THRESHOLD};
use k256::{
    AffinePoint, ProjectivePoint, Scalar, ecdsa,
    elliptic_curve::{
        bigint::U256,
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Unique identifier for a party in the MPC network (0, 1, or 2)
pub type PartyId = usize;

/// Unique identifier for a session
pub type SessionId = [u8; 32];

/// Compressed public key bytes (33 bytes for secp256k1)
pub type PublicKey = [u8; 33];

/// Role of a party in the AI agent wallet
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartyRole {
    /// AI agent party - can initiate transactions
    Agent,
    /// User party - primary approval authority
    User,
    /// Recovery guardian - backup approval for recovery scenarios
    Recovery,
}

impl PartyRole {
    /// Get the party ID for this role
    pub fn party_id(&self) -> PartyId {
        match self {
            PartyRole::Agent => 0,
            PartyRole::User => 1,
            PartyRole::Recovery => 2,
        }
    }

    /// Create a role from a party ID
    pub fn from_party_id(id: PartyId) -> Result<Self> {
        match id {
            0 => Ok(PartyRole::Agent),
            1 => Ok(PartyRole::User),
            2 => Ok(PartyRole::Recovery),
            _ => Err(Error::InvalidPartyId(id)),
        }
    }

    /// Get all party roles
    pub fn all() -> [PartyRole; 3] {
        [PartyRole::Agent, PartyRole::User, PartyRole::Recovery]
    }
}

impl fmt::Display for PartyRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PartyRole::Agent => write!(f, "Agent"),
            PartyRole::User => write!(f, "User"),
            PartyRole::Recovery => write!(f, "Recovery"),
        }
    }
}

/// Supported blockchain types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainType {
    /// Ethereum and EVM-compatible chains
    Evm,
    /// Solana
    Solana,
    /// Bitcoin
    Bitcoin,
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainType::Evm => write!(f, "EVM"),
            ChainType::Solana => write!(f, "Solana"),
            ChainType::Bitcoin => write!(f, "Bitcoin"),
        }
    }
}

/// ECDSA signature (r, s, v)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// R component (32 bytes)
    pub r: [u8; 32],
    /// S component (32 bytes)
    pub s: [u8; 32],
    /// Recovery ID (0 or 1)
    pub recovery_id: u8,
}

impl Signature {
    /// Create a new signature
    pub fn new(r: [u8; 32], s: [u8; 32], recovery_id: u8) -> Self {
        Self { r, s, recovery_id }
    }

    /// Convert to DER format
    pub fn to_der(&self) -> Vec<u8> {
        let sig = ecdsa::Signature::from_scalars(
            *k256::FieldBytes::from_slice(&self.r),
            *k256::FieldBytes::from_slice(&self.s),
        )
        .expect("valid signature");
        sig.to_der().as_bytes().to_vec()
    }

    /// Convert to bytes (r || s)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.r);
        bytes[32..].copy_from_slice(&self.s);
        bytes
    }

    /// Convert to EIP-155 format (r || s || v)
    pub fn to_eip155(&self, chain_id: u64) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(65);
        bytes.extend_from_slice(&self.r);
        bytes.extend_from_slice(&self.s);
        // v = recovery_id + 35 + chain_id * 2
        let v = self.recovery_id as u64 + 35 + chain_id * 2;
        bytes.push(v as u8);
        bytes
    }

    /// Get v value for legacy Ethereum transactions
    pub fn v(&self) -> u8 {
        self.recovery_id + 27
    }
}

/// Metadata associated with a key share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShareMetadata {
    /// Unique identifier for this key share
    pub share_id: String,
    /// Role of the party holding this share
    pub role: PartyRole,
    /// Creation timestamp (Unix seconds)
    pub created_at: i64,
    /// Last refresh timestamp (Unix seconds)
    pub last_refreshed_at: Option<i64>,
    /// Wallet address (derived from public key)
    pub addresses: std::collections::HashMap<ChainType, String>,
    /// Optional label for this share
    pub label: Option<String>,
}

mod scalar_serde {
    use k256::{
        Scalar,
        elliptic_curve::{bigint::U256, ops::Reduce},
    };
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = scalar.to_bytes();
        serializer.serialize_bytes(bytes.as_slice())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("Invalid scalar length"))?;
        Ok(<Scalar as Reduce<U256>>::reduce_bytes(&array.into()))
    }
}

/// Key share for AI agent wallet (2-of-3 threshold)
///
/// Each party (Agent, User, Recovery) holds one share. Any 2 shares
/// can combine to sign a transaction.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AgentKeyShare {
    /// This party's ID (0=Agent, 1=User, 2=Recovery)
    pub party_id: PartyId,

    /// Role of this party
    #[zeroize(skip)]
    pub role: PartyRole,

    /// This party's secret share (x_i)
    #[zeroize(skip)]
    #[serde(with = "scalar_serde")]
    pub secret_share: Scalar,

    /// Aggregated public key (compressed, 33 bytes)
    #[zeroize(skip)]
    pub public_key: Vec<u8>,

    /// Public key shares of all parties (for verification)
    #[zeroize(skip)]
    pub public_shares: Vec<Vec<u8>>,

    /// Chain code for BIP32 derivation
    pub chain_code: [u8; 32],

    /// Metadata about this share
    #[zeroize(skip)]
    pub metadata: KeyShareMetadata,
}

impl AgentKeyShare {
    /// Get the public key as a ProjectivePoint
    pub fn public_key_point(&self) -> Result<ProjectivePoint> {
        let encoded = k256::EncodedPoint::from_bytes(&self.public_key)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let affine_opt = AffinePoint::from_encoded_point(&encoded);
        let affine: AffinePoint =
            Option::<AffinePoint>::from(affine_opt).ok_or(Error::Crypto("Invalid point".into()))?;
        Ok(ProjectivePoint::from(affine))
    }

    /// Derive a child key share using non-hardened BIP32 derivation
    pub fn derive_child(&self, path: &str) -> Result<AgentKeyShare> {
        use derivation_path::DerivationPath;

        let derivation_path: DerivationPath = path
            .parse()
            .map_err(|e| Error::Derivation(format!("Invalid path: {}", e)))?;

        let mut current_share = self.clone();
        let mut current_chain_code = self.chain_code;

        for child_index in derivation_path.into_iter() {
            if child_index.is_hardened() {
                return Err(Error::HardenedDerivationNotSupported);
            }

            let index = match child_index {
                derivation_path::ChildIndex::Normal(idx) => *idx,
                derivation_path::ChildIndex::Hardened(_) => {
                    return Err(Error::HardenedDerivationNotSupported);
                }
            };

            let (new_share, new_chain_code) =
                derive_non_hardened(&current_share, current_chain_code, index)?;

            current_share.secret_share = new_share;
            current_chain_code = new_chain_code;
        }

        current_share.chain_code = current_chain_code;
        Ok(current_share)
    }

    /// Get the Ethereum address for this key share
    pub fn eth_address(&self) -> Result<String> {
        use tiny_keccak::{Hasher, Keccak};

        // Get uncompressed public key (65 bytes)
        let point = self.public_key_point()?;
        let encoded = point.to_affine().to_encoded_point(false);
        let pk_bytes = encoded.as_bytes();

        // Skip the 0x04 prefix and hash with Keccak256
        let mut hasher = Keccak::v256();
        hasher.update(&pk_bytes[1..]);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);

        // Take last 20 bytes
        Ok(format!("0x{}", hex::encode(&hash[12..])))
    }
}

impl std::fmt::Debug for AgentKeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentKeyShare")
            .field("party_id", &self.party_id)
            .field("role", &self.role)
            .field("secret_share", &"[REDACTED]")
            .field("public_key", &hex::encode(&self.public_key))
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Derive non-hardened child key
fn derive_non_hardened(
    parent: &AgentKeyShare,
    chain_code: [u8; 32],
    index: u32,
) -> Result<(Scalar, [u8; 32])> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    let mut hmac = Hmac::<Sha512>::new_from_slice(&chain_code)
        .map_err(|e| Error::Derivation(e.to_string()))?;

    hmac.update(&parent.public_key);
    hmac.update(&index.to_be_bytes());

    let result = hmac.finalize().into_bytes();

    let secret_bytes: [u8; 32] = result[..32].try_into().unwrap();
    let secret_add = <Scalar as Reduce<U256>>::reduce_bytes(&secret_bytes.into());
    let new_chain_code: [u8; 32] = result[32..].try_into().unwrap();

    let new_secret = parent.secret_share + secret_add;

    Ok((new_secret, new_chain_code))
}

/// Configuration for DKG/DSG sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Session identifier
    pub session_id: SessionId,

    /// Number of parties (always 3 for agent wallet)
    pub n_parties: usize,

    /// Threshold (always 2 for agent wallet)
    pub threshold: usize,

    /// This party's ID
    pub party_id: PartyId,

    /// This party's role
    pub role: PartyRole,

    /// List of participating party IDs
    pub parties: Vec<PartyId>,

    /// Session timeout in seconds
    pub timeout_secs: u64,
}

impl SessionConfig {
    /// Create a new session configuration for the 2-of-3 agent wallet
    pub fn new_agent_wallet(party_id: PartyId) -> Result<Self> {
        if party_id > 2 {
            return Err(Error::InvalidPartyId(party_id));
        }

        let session_id = rand::random();
        let parties = vec![0, 1, 2];
        let role = PartyRole::from_party_id(party_id)?;

        Ok(Self {
            session_id,
            n_parties: 3,
            threshold: THRESHOLD,
            party_id,
            role,
            parties,
            timeout_secs: 300, // 5 minute default
        })
    }

    /// Create a signing session with specific participants
    pub fn new_signing_session(party_id: PartyId, participants: &[PartyRole]) -> Result<Self> {
        if participants.len() < THRESHOLD {
            return Err(Error::ThresholdNotMet {
                required: THRESHOLD,
                actual: participants.len(),
            });
        }

        let session_id = rand::random();
        let parties: Vec<PartyId> = participants.iter().map(|r| r.party_id()).collect();
        let role = PartyRole::from_party_id(party_id)?;

        if !parties.contains(&party_id) {
            return Err(Error::InvalidSigningParties(
                "This party is not in the signing set".into(),
            ));
        }

        Ok(Self {
            session_id,
            n_parties: participants.len(),
            threshold: THRESHOLD,
            party_id,
            role,
            parties,
            timeout_secs: 60, // 1 minute for signing
        })
    }
}

/// Transaction request for signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRequest {
    /// Unique request ID
    pub request_id: String,

    /// Target chain
    pub chain: ChainType,

    /// Recipient address
    pub to: String,

    /// Value to send (in native token)
    pub value: String,

    /// Transaction data (for contract calls)
    pub data: Option<Vec<u8>>,

    /// Gas limit (for EVM)
    pub gas_limit: Option<u64>,

    /// Max fee per gas (for EIP-1559)
    pub max_fee_per_gas: Option<u64>,

    /// Max priority fee per gas (for EIP-1559)
    pub max_priority_fee_per_gas: Option<u64>,

    /// Nonce (if not provided, will be fetched)
    pub nonce: Option<u64>,

    /// Chain ID (for EVM)
    pub chain_id: Option<u64>,

    /// Request timestamp
    pub timestamp: i64,

    /// Optional metadata
    pub metadata: Option<serde_json::Value>,
}

impl TransactionRequest {
    /// Create a new transaction request
    pub fn new(chain: ChainType, to: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            chain,
            to: to.into(),
            value: value.into(),
            data: None,
            gas_limit: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: None,
            chain_id: None,
            timestamp: chrono::Utc::now().timestamp(),
            metadata: None,
        }
    }

    /// Add contract call data
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }

    /// Set gas limit
    pub fn with_gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = Some(gas_limit);
        self
    }

    /// Set chain ID
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Check if this is a contract interaction
    pub fn is_contract_call(&self) -> bool {
        self.data.as_ref().map(|d| !d.is_empty()).unwrap_or(false)
    }

    /// Get the function selector for contract calls (first 4 bytes of data)
    pub fn function_selector(&self) -> Option<[u8; 4]> {
        self.data.as_ref().and_then(|d| {
            if d.len() >= 4 {
                let mut selector = [0u8; 4];
                selector.copy_from_slice(&d[..4]);
                Some(selector)
            } else {
                None
            }
        })
    }
}

/// Message types exchanged during protocol execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Broadcast message to all parties
    Broadcast {
        from: PartyId,
        round: u32,
        data: Vec<u8>,
    },
    /// Point-to-point message
    Direct {
        from: PartyId,
        to: PartyId,
        round: u32,
        data: Vec<u8>,
    },
}

impl Message {
    /// Get the sender of this message
    pub fn sender(&self) -> PartyId {
        match self {
            Message::Broadcast { from, .. } => *from,
            Message::Direct { from, .. } => *from,
        }
    }

    /// Get the round number
    pub fn round(&self) -> u32 {
        match self {
            Message::Broadcast { round, .. } => *round,
            Message::Direct { round, .. } => *round,
        }
    }
}

/// Compute Keccak256 hash of data
pub fn keccak256_hash(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_party_role_conversion() {
        assert_eq!(PartyRole::Agent.party_id(), 0);
        assert_eq!(PartyRole::User.party_id(), 1);
        assert_eq!(PartyRole::Recovery.party_id(), 2);

        assert_eq!(PartyRole::from_party_id(0).unwrap(), PartyRole::Agent);
        assert_eq!(PartyRole::from_party_id(1).unwrap(), PartyRole::User);
        assert_eq!(PartyRole::from_party_id(2).unwrap(), PartyRole::Recovery);
        assert!(PartyRole::from_party_id(3).is_err());
    }

    #[test]
    fn test_signature_formats() {
        let r = [1u8; 32];
        let s = [2u8; 32];
        let sig = Signature::new(r, s, 0);

        assert_eq!(sig.v(), 27);
        assert_eq!(sig.to_bytes().len(), 64);

        let eip155 = sig.to_eip155(1);
        assert_eq!(eip155.len(), 65);
    }

    #[test]
    fn test_transaction_request() {
        let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "1.0")
            .with_gas_limit(21000)
            .with_chain_id(1);

        assert!(!tx.is_contract_call());
        assert!(tx.function_selector().is_none());

        let tx_with_data = tx.with_data(vec![0xa9, 0x05, 0x9c, 0xbb, 0x00]);
        assert!(tx_with_data.is_contract_call());
        assert_eq!(
            tx_with_data.function_selector(),
            Some([0xa9, 0x05, 0x9c, 0xbb])
        );
    }

    #[test]
    fn test_session_config() {
        let config = SessionConfig::new_agent_wallet(0).unwrap();
        assert_eq!(config.n_parties, 3);
        assert_eq!(config.threshold, 2);
        assert_eq!(config.role, PartyRole::Agent);

        // Test signing session
        let signing_config =
            SessionConfig::new_signing_session(0, &[PartyRole::Agent, PartyRole::User]).unwrap();
        assert_eq!(signing_config.parties.len(), 2);
    }
}
