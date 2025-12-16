//! Transaction approval handling
//!
//! Manages approval requests and responses for MPC wallet transactions.

use crate::{
    ApprovalId, ApprovalMethod, PartialSignature, RelayError, Result, RiskLevel, SessionId,
    TransactionSummary,
};
use chrono::{DateTime, Utc};
use mpc_wallet_core::{PartyRole, PolicyDecision, TransactionRequest};
use serde::{Deserialize, Serialize};

/// Status of an approval request
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Waiting for approval
    Pending,
    /// Approved by user
    Approved,
    /// Rejected by user
    Rejected,
    /// Expired without response
    Expired,
    /// Cancelled by requester
    Cancelled,
}

impl ApprovalStatus {
    /// Check if the approval is still pending
    pub fn is_pending(&self) -> bool {
        matches!(self, ApprovalStatus::Pending)
    }

    /// Check if the approval was successful
    pub fn is_approved(&self) -> bool {
        matches!(self, ApprovalStatus::Approved)
    }

    /// Check if the approval is finalized (no longer pending)
    pub fn is_finalized(&self) -> bool {
        !self.is_pending()
    }
}

/// Approval request sent to user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique approval ID
    pub id: ApprovalId,
    /// Associated signing session ID
    pub session_id: SessionId,
    /// Role of the party requesting approval (usually Agent)
    pub requester_role: PartyRole,
    /// Role of the approver (usually User)
    pub approver_role: PartyRole,
    /// Transaction to approve
    pub transaction: TransactionRequest,
    /// Human-readable summary
    pub summary: TransactionSummary,
    /// Policy evaluation result
    pub policy_decision: PolicyDecision,
    /// Current status
    pub status: ApprovalStatus,
    /// Preferred approval method
    pub approval_method: ApprovalMethod,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Response (if approved/rejected)
    pub response: Option<ApprovalResponse>,
    /// Number of notification attempts
    pub notification_attempts: u32,
    /// Last notification timestamp
    pub last_notification_at: Option<DateTime<Utc>>,
    /// Metadata
    pub metadata: Option<serde_json::Value>,
}

impl ApprovalRequest {
    /// Create a new approval request
    pub fn new(
        session_id: impl Into<SessionId>,
        requester_role: PartyRole,
        approver_role: PartyRole,
        transaction: TransactionRequest,
        policy_decision: PolicyDecision,
    ) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let summary = TransactionSummary::from_request(&transaction);
        let now = Utc::now();
        let expires_at = now + chrono::Duration::minutes(5); // 5 minute default

        Self {
            id,
            session_id: session_id.into(),
            requester_role,
            approver_role,
            transaction,
            summary,
            policy_decision,
            status: ApprovalStatus::Pending,
            approval_method: ApprovalMethod::default(),
            created_at: now,
            expires_at,
            response: None,
            notification_attempts: 0,
            last_notification_at: None,
            metadata: None,
        }
    }

    /// Set approval method
    pub fn with_approval_method(mut self, method: ApprovalMethod) -> Self {
        self.approval_method = method;
        self
    }

    /// Set expiration time
    pub fn with_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Set expiration duration
    pub fn with_ttl_secs(mut self, ttl_secs: i64) -> Self {
        self.expires_at = Utc::now() + chrono::Duration::seconds(ttl_secs);
        self
    }

    /// Set risk level
    pub fn with_risk_level(mut self, level: RiskLevel) -> Self {
        self.summary.risk_level = level;
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Check if the request has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Update status to expired if applicable
    pub fn check_expiration(&mut self) {
        if self.status == ApprovalStatus::Pending && self.is_expired() {
            self.status = ApprovalStatus::Expired;
        }
    }

    /// Record a notification attempt
    pub fn record_notification(&mut self) {
        self.notification_attempts += 1;
        self.last_notification_at = Some(Utc::now());
    }

    /// Process approval response
    pub fn process_response(&mut self, response: ApprovalResponse) -> Result<()> {
        if self.status != ApprovalStatus::Pending {
            return Err(RelayError::ApprovalAlreadyProcessed(self.id.clone()));
        }

        if self.is_expired() {
            self.status = ApprovalStatus::Expired;
            return Err(RelayError::SessionExpired(self.id.clone()));
        }

        // Validate approver
        if response.approver_role != self.approver_role {
            return Err(RelayError::InvalidApproval(format!(
                "Expected approver role {:?}, got {:?}",
                self.approver_role, response.approver_role
            )));
        }

        self.status = if response.approved {
            ApprovalStatus::Approved
        } else {
            ApprovalStatus::Rejected
        };

        self.response = Some(response);
        Ok(())
    }

    /// Cancel the approval request
    pub fn cancel(&mut self) -> Result<()> {
        if self.status != ApprovalStatus::Pending {
            return Err(RelayError::ApprovalAlreadyProcessed(self.id.clone()));
        }

        self.status = ApprovalStatus::Cancelled;
        Ok(())
    }

    /// Get time remaining until expiration
    pub fn time_remaining(&self) -> chrono::Duration {
        self.expires_at - Utc::now()
    }

    /// Get time remaining in seconds (0 if expired)
    pub fn time_remaining_secs(&self) -> i64 {
        self.time_remaining().num_seconds().max(0)
    }
}

/// Response to an approval request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResponse {
    /// Approval request ID
    pub approval_id: ApprovalId,
    /// Role of the approving party
    pub approver_role: PartyRole,
    /// Whether the transaction was approved
    pub approved: bool,
    /// Rejection reason (if rejected)
    pub rejection_reason: Option<String>,
    /// Partial signature (if approved)
    pub partial_signature: Option<PartialSignature>,
    /// Response timestamp
    pub timestamp: DateTime<Utc>,
    /// Device ID that submitted the response
    pub device_id: Option<String>,
    /// IP address (for audit)
    pub ip_address: Option<String>,
}

impl ApprovalResponse {
    /// Create an approval response
    pub fn approve(approval_id: impl Into<ApprovalId>, approver_role: PartyRole) -> Self {
        Self {
            approval_id: approval_id.into(),
            approver_role,
            approved: true,
            rejection_reason: None,
            partial_signature: None,
            timestamp: Utc::now(),
            device_id: None,
            ip_address: None,
        }
    }

    /// Create a rejection response
    pub fn reject(
        approval_id: impl Into<ApprovalId>,
        approver_role: PartyRole,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            approval_id: approval_id.into(),
            approver_role,
            approved: false,
            rejection_reason: Some(reason.into()),
            partial_signature: None,
            timestamp: Utc::now(),
            device_id: None,
            ip_address: None,
        }
    }

    /// Attach partial signature
    pub fn with_signature(mut self, signature: PartialSignature) -> Self {
        self.partial_signature = Some(signature);
        self
    }

    /// Set device ID
    pub fn with_device_id(mut self, device_id: impl Into<String>) -> Self {
        self.device_id = Some(device_id.into());
        self
    }

    /// Set IP address
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }
}

/// Summary of approval for audit/display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalSummary {
    /// Approval ID
    pub id: ApprovalId,
    /// Session ID
    pub session_id: SessionId,
    /// Current status
    pub status: ApprovalStatus,
    /// Transaction value
    pub value: String,
    /// Target address
    pub to: String,
    /// Chain type
    pub chain: String,
    /// Time remaining (seconds)
    pub time_remaining_secs: i64,
    /// Created at
    pub created_at: DateTime<Utc>,
}

impl From<&ApprovalRequest> for ApprovalSummary {
    fn from(req: &ApprovalRequest) -> Self {
        Self {
            id: req.id.clone(),
            session_id: req.session_id.clone(),
            status: req.status,
            value: req.summary.value.clone(),
            to: req.summary.to.clone(),
            chain: req.summary.chain_name.clone(),
            time_remaining_secs: req.time_remaining_secs(),
            created_at: req.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_wallet_core::ChainType;

    fn create_test_tx() -> TransactionRequest {
        TransactionRequest::new(ChainType::Evm, "0x1234", "1000000000000000000")
    }

    #[test]
    fn test_approval_request_creation() {
        let tx = create_test_tx();
        let req = ApprovalRequest::new(
            "session1",
            PartyRole::Agent,
            PartyRole::User,
            tx,
            PolicyDecision::Approve,
        );

        assert!(req.status.is_pending());
        assert!(!req.is_expired());
        assert!(req.time_remaining_secs() > 0);
    }

    #[test]
    fn test_approval_response() {
        let tx = create_test_tx();
        let mut req = ApprovalRequest::new(
            "session1",
            PartyRole::Agent,
            PartyRole::User,
            tx,
            PolicyDecision::Approve,
        );

        let response = ApprovalResponse::approve(&req.id, PartyRole::User);
        req.process_response(response).unwrap();

        assert!(req.status.is_approved());
        assert!(req.response.is_some());
    }

    #[test]
    fn test_rejection_response() {
        let tx = create_test_tx();
        let mut req = ApprovalRequest::new(
            "session1",
            PartyRole::Agent,
            PartyRole::User,
            tx,
            PolicyDecision::Approve,
        );

        let response = ApprovalResponse::reject(&req.id, PartyRole::User, "Not now");
        req.process_response(response).unwrap();

        assert_eq!(req.status, ApprovalStatus::Rejected);
        assert!(req.response.as_ref().unwrap().rejection_reason.is_some());
    }

    #[test]
    fn test_double_response_error() {
        let tx = create_test_tx();
        let mut req = ApprovalRequest::new(
            "session1",
            PartyRole::Agent,
            PartyRole::User,
            tx,
            PolicyDecision::Approve,
        );

        let response1 = ApprovalResponse::approve(&req.id, PartyRole::User);
        req.process_response(response1).unwrap();

        let response2 = ApprovalResponse::approve(&req.id, PartyRole::User);
        assert!(req.process_response(response2).is_err());
    }

    #[test]
    fn test_wrong_approver_error() {
        let tx = create_test_tx();
        let mut req = ApprovalRequest::new(
            "session1",
            PartyRole::Agent,
            PartyRole::User,
            tx,
            PolicyDecision::Approve,
        );

        // Recovery trying to approve when User was expected
        let response = ApprovalResponse::approve(&req.id, PartyRole::Recovery);
        assert!(req.process_response(response).is_err());
    }

    #[test]
    fn test_cancellation() {
        let tx = create_test_tx();
        let mut req = ApprovalRequest::new(
            "session1",
            PartyRole::Agent,
            PartyRole::User,
            tx,
            PolicyDecision::Approve,
        );

        req.cancel().unwrap();
        assert_eq!(req.status, ApprovalStatus::Cancelled);

        // Can't cancel twice
        assert!(req.cancel().is_err());
    }

    #[test]
    fn test_expiration() {
        let tx = create_test_tx();
        let mut req = ApprovalRequest::new(
            "session1",
            PartyRole::Agent,
            PartyRole::User,
            tx,
            PolicyDecision::Approve,
        )
        .with_ttl_secs(-1); // Already expired

        assert!(req.is_expired());
        req.check_expiration();
        assert_eq!(req.status, ApprovalStatus::Expired);
    }
}
