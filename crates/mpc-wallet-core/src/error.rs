//! Error types for MPC wallet operations

use thiserror::Error;

/// Result type alias for MPC wallet operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during MPC wallet operations
#[derive(Debug, Error)]
pub enum Error {
    // ============ Configuration Errors ============
    /// Invalid party configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Invalid party ID
    #[error("Invalid party ID: {0}")]
    InvalidPartyId(usize),

    /// Invalid party role
    #[error("Invalid party role: {0}")]
    InvalidPartyRole(String),

    // ============ Threshold Errors ============
    /// Threshold requirements not met
    #[error("Threshold not met: required {required}, got {actual}")]
    ThresholdNotMet { required: usize, actual: usize },

    /// Invalid signing party combination
    #[error("Invalid signing party combination: {0}")]
    InvalidSigningParties(String),

    // ============ Policy Errors ============
    /// Policy violation - transaction rejected
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// Spending limit exceeded
    #[error("Spending limit exceeded: {limit} {currency} (attempted: {attempted})")]
    SpendingLimitExceeded {
        limit: String,
        attempted: String,
        currency: String,
    },

    /// Address not in whitelist
    #[error("Address not whitelisted: {0}")]
    AddressNotWhitelisted(String),

    /// Address is blacklisted
    #[error("Address is blacklisted: {0}")]
    AddressBlacklisted(String),

    /// Transaction outside allowed time window
    #[error("Transaction outside allowed time window: {0}")]
    TimeWindowViolation(String),

    /// Contract interaction not allowed
    #[error("Contract interaction not allowed: {0}")]
    ContractNotAllowed(String),

    // ============ Cryptographic Errors ============
    /// Message verification failed
    #[error("Message verification failed: {0}")]
    VerificationFailed(String),

    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    // ============ Storage Errors ============
    /// Key share not found
    #[error("Key share not found: {0}")]
    KeyShareNotFound(String),

    /// Storage operation failed
    #[error("Storage error: {0}")]
    Storage(String),

    /// Encryption/decryption failed
    #[error("Encryption error: {0}")]
    Encryption(String),

    // ============ Serialization Errors ============
    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    // ============ Network/Protocol Errors ============
    /// Network/relay error
    #[error("Relay error: {0}")]
    Relay(String),

    /// Timeout waiting for message
    #[error("Timeout waiting for {0}")]
    Timeout(String),

    /// Session not found
    #[error("Session not found: {0}")]
    SessionNotFound(String),

    /// Session expired
    #[error("Session expired: {0}")]
    SessionExpired(String),

    // ============ Key Derivation Errors ============
    /// Key derivation error
    #[error("Key derivation error: {0}")]
    Derivation(String),

    /// Hardened derivation not supported
    #[error("Hardened derivation not supported in threshold setting")]
    HardenedDerivationNotSupported,

    // ============ Chain Errors ============
    /// Unsupported chain
    #[error("Unsupported chain: {0}")]
    UnsupportedChain(String),

    /// Chain operation failed
    #[error("Chain error: {0}")]
    ChainError(String),

    // ============ Internal Errors ============
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Error::Deserialization(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::SpendingLimitExceeded {
            limit: "1.0".to_string(),
            attempted: "2.0".to_string(),
            currency: "ETH".to_string(),
        };
        assert!(err.to_string().contains("1.0"));
        assert!(err.to_string().contains("2.0"));
        assert!(err.to_string().contains("ETH"));
    }

    #[test]
    fn test_policy_violation() {
        let err = Error::PolicyViolation("daily limit exceeded".to_string());
        assert!(err.to_string().contains("daily limit"));
    }
}
