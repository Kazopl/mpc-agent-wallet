//! Error types for the relay service

use thiserror::Error;

/// Relay service errors
#[derive(Debug, Error)]
pub enum RelayError {
    /// Session not found
    #[error("Session not found: {0}")]
    SessionNotFound(String),

    /// Session expired
    #[error("Session expired: {0}")]
    SessionExpired(String),

    /// Session already exists
    #[error("Session already exists: {0}")]
    SessionAlreadyExists(String),

    /// Invalid session state
    #[error("Invalid session state: expected {expected}, got {actual}")]
    InvalidSessionState { expected: String, actual: String },

    /// Approval not found
    #[error("Approval not found: {0}")]
    ApprovalNotFound(String),

    /// Approval already processed
    #[error("Approval already processed: {0}")]
    ApprovalAlreadyProcessed(String),

    /// Invalid approval
    #[error("Invalid approval: {0}")]
    InvalidApproval(String),

    /// Message not found
    #[error("Message not found: {0}")]
    MessageNotFound(String),

    /// Invalid message format
    #[error("Invalid message format: {0}")]
    InvalidMessageFormat(String),

    /// Webhook error
    #[error("Webhook error: {0}")]
    WebhookError(String),

    /// Notification error
    #[error("Notification error: {0}")]
    NotificationError(String),

    /// Unauthorized
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Rate limited
    #[error("Rate limited: {0}")]
    RateLimited(String),

    /// Invalid party
    #[error("Invalid party: {0}")]
    InvalidParty(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl RelayError {
    /// Get HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            RelayError::SessionNotFound(_) => 404,
            RelayError::ApprovalNotFound(_) => 404,
            RelayError::MessageNotFound(_) => 404,
            RelayError::SessionExpired(_) => 410,
            RelayError::SessionAlreadyExists(_) => 409,
            RelayError::ApprovalAlreadyProcessed(_) => 409,
            RelayError::InvalidSessionState { .. } => 400,
            RelayError::InvalidApproval(_) => 400,
            RelayError::InvalidMessageFormat(_) => 400,
            RelayError::InvalidParty(_) => 400,
            RelayError::Serialization(_) => 400,
            RelayError::Unauthorized(_) => 401,
            RelayError::RateLimited(_) => 429,
            RelayError::WebhookError(_) => 502,
            RelayError::NotificationError(_) => 502,
            RelayError::Network(_) => 503,
            RelayError::Internal(_) => 500,
        }
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            RelayError::Network(_) | RelayError::RateLimited(_) | RelayError::WebhookError(_)
        )
    }
}

impl From<serde_json::Error> for RelayError {
    fn from(err: serde_json::Error) -> Self {
        RelayError::Serialization(err.to_string())
    }
}

/// Result type alias
pub type Result<T> = std::result::Result<T, RelayError>;
