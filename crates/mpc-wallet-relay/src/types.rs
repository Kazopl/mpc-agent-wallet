//! Core types for the relay service

use chrono::{DateTime, Utc};
use mpc_wallet_core::{ChainType, PartyRole, TransactionRequest};
use serde::{Deserialize, Serialize};

/// Unique identifier for a signing session
pub type SessionId = String;

/// Unique identifier for an approval request
pub type ApprovalId = String;

/// Party identifier
pub type PartyId = usize;

/// Approval method requested by user
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMethod {
    /// Push notification to mobile device
    PushNotification,
    /// Polling (user app checks periodically)
    Polling,
    /// QR code scan
    QrCode,
    /// Telegram bot command
    Telegram,
    /// Discord bot command
    Discord,
    /// WebSocket real-time
    WebSocket,
    /// Email link
    Email,
}

impl Default for ApprovalMethod {
    fn default() -> Self {
        ApprovalMethod::Polling
    }
}

/// Transaction summary for display in approval request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSummary {
    /// Transaction request ID
    pub request_id: String,
    /// Target chain
    pub chain: ChainType,
    /// Human-readable chain name
    pub chain_name: String,
    /// Recipient address
    pub to: String,
    /// Value to send (formatted string)
    pub value: String,
    /// Value in USD (if available)
    pub value_usd: Option<String>,
    /// Transaction type description
    pub tx_type: String,
    /// Function name for contract calls
    pub function_name: Option<String>,
    /// Contract name (if known)
    pub contract_name: Option<String>,
    /// Risk level assessment
    pub risk_level: RiskLevel,
    /// Additional notes
    pub notes: Option<String>,
}

impl TransactionSummary {
    /// Create a summary from a transaction request
    pub fn from_request(tx: &TransactionRequest) -> Self {
        let tx_type = if tx.is_contract_call() {
            "Contract Call".to_string()
        } else {
            "Transfer".to_string()
        };

        let chain_name = match tx.chain {
            ChainType::Evm => "Ethereum".to_string(),
            ChainType::Solana => "Solana".to_string(),
            ChainType::Bitcoin => "Bitcoin".to_string(),
        };

        Self {
            request_id: tx.request_id.clone(),
            chain: tx.chain,
            chain_name,
            to: tx.to.clone(),
            value: tx.value.clone(),
            value_usd: None,
            tx_type,
            function_name: tx
                .function_selector()
                .map(|s| format!("0x{}", hex::encode(s))),
            contract_name: None,
            risk_level: RiskLevel::Medium, // Default, should be computed
            notes: None,
        }
    }

    /// Add USD value estimation
    pub fn with_usd_value(mut self, usd: impl Into<String>) -> Self {
        self.value_usd = Some(usd.into());
        self
    }

    /// Set risk level
    pub fn with_risk_level(mut self, level: RiskLevel) -> Self {
        self.risk_level = level;
        self
    }

    /// Add notes
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }
}

/// Risk level for a transaction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Low risk (known recipient, small amount)
    Low,
    /// Medium risk (typical transaction)
    Medium,
    /// High risk (large amount, unknown contract)
    High,
    /// Critical risk (suspicious activity)
    Critical,
}

/// Partial signature from a party
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSignature {
    /// Session ID this signature belongs to
    pub session_id: SessionId,
    /// Party ID that created this signature
    pub party_id: PartyId,
    /// Party role
    pub role: PartyRole,
    /// Signature data (protocol-specific)
    pub signature_data: Vec<u8>,
    /// Timestamp
    pub created_at: DateTime<Utc>,
}

/// Device information for notifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device identifier
    pub device_id: String,
    /// Device type (mobile, desktop, etc.)
    pub device_type: String,
    /// Push token (for push notifications)
    pub push_token: Option<String>,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// Notification preferences
    pub notification_prefs: NotificationPreferences,
}

/// Notification preferences
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotificationPreferences {
    /// Enable push notifications
    pub push_enabled: bool,
    /// Enable email notifications
    pub email_enabled: bool,
    /// Enable Telegram notifications
    pub telegram_enabled: bool,
    /// Telegram chat ID
    pub telegram_chat_id: Option<String>,
    /// Enable Discord notifications
    pub discord_enabled: bool,
    /// Discord user ID
    pub discord_user_id: Option<String>,
}

/// Rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per minute per IP
    pub requests_per_minute: u32,
    /// Maximum sessions per wallet per day
    pub sessions_per_day: u32,
    /// Maximum pending approvals per wallet
    pub max_pending_approvals: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            sessions_per_day: 100,
            max_pending_approvals: 10,
        }
    }
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Service status
    pub status: String,
    /// Service name
    pub service: String,
    /// Version
    pub version: String,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Number of active sessions
    pub active_sessions: usize,
    /// Number of pending approvals
    pub pending_approvals: usize,
}

/// Statistics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsResponse {
    /// Total sessions created
    pub total_sessions: u64,
    /// Total approvals processed
    pub total_approvals: u64,
    /// Approval rate (approved / total)
    pub approval_rate: f64,
    /// Average approval time in seconds
    pub avg_approval_time_secs: f64,
    /// Active webhooks count
    pub active_webhooks: usize,
}
