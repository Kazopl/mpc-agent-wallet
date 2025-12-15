//! Signing session management
//!
//! Manages the lifecycle of MPC signing sessions, including approval flows.

use crate::{
    ApprovalId, ApprovalRequest, ApprovalResponse, ApprovalStatus, MessageStore, PartialSignature,
    RelayError, Result, SessionId,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use mpc_wallet_core::{PartyRole, PolicyDecision, TransactionRequest};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Status of a signing session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// Session created, waiting for participants
    Created,
    /// Waiting for approval
    PendingApproval,
    /// Approved, MPC signing in progress
    Signing,
    /// Signing complete
    Completed,
    /// Session rejected
    Rejected,
    /// Session expired
    Expired,
    /// Session cancelled
    Cancelled,
    /// Session failed
    Failed,
}

impl SessionStatus {
    /// Check if the session is still active
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            SessionStatus::Created | SessionStatus::PendingApproval | SessionStatus::Signing
        )
    }

    /// Check if the session is finalized
    pub fn is_finalized(&self) -> bool {
        matches!(
            self,
            SessionStatus::Completed
                | SessionStatus::Rejected
                | SessionStatus::Expired
                | SessionStatus::Cancelled
                | SessionStatus::Failed
        )
    }
}

/// A signing session for MPC wallet transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningSession {
    /// Unique session ID
    pub id: SessionId,
    /// Wallet address
    pub wallet_address: String,
    /// Transaction to sign
    pub transaction: TransactionRequest,
    /// Policy decision
    pub policy_decision: PolicyDecision,
    /// Requesting party (usually Agent)
    pub requester: PartyRole,
    /// Participating parties for signing
    pub participants: Vec<PartyRole>,
    /// Current status
    pub status: SessionStatus,
    /// Approval request (if applicable)
    pub approval: Option<ApprovalRequest>,
    /// Collected partial signatures
    pub partial_signatures: HashMap<PartyRole, PartialSignature>,
    /// Final combined signature (when complete)
    pub final_signature: Option<Vec<u8>>,
    /// Current MPC round
    pub current_round: u32,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Completion timestamp
    pub completed_at: Option<DateTime<Utc>>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Session metadata
    pub metadata: Option<serde_json::Value>,
}

impl SigningSession {
    /// Create a new signing session
    pub fn new(
        wallet_address: impl Into<String>,
        transaction: TransactionRequest,
        policy_decision: PolicyDecision,
        requester: PartyRole,
        participants: Vec<PartyRole>,
    ) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::minutes(10); // 10 minute default

        Self {
            id,
            wallet_address: wallet_address.into(),
            transaction,
            policy_decision,
            requester,
            participants,
            status: SessionStatus::Created,
            approval: None,
            partial_signatures: HashMap::new(),
            final_signature: None,
            current_round: 0,
            created_at: now,
            expires_at,
            completed_at: None,
            error: None,
            metadata: None,
        }
    }

    /// Create an approval request for this session
    pub fn create_approval(&mut self, approver_role: PartyRole) -> Result<&ApprovalRequest> {
        if self.approval.is_some() {
            return Err(RelayError::InvalidSessionState {
                expected: "No existing approval".to_string(),
                actual: "Approval already exists".to_string(),
            });
        }

        let approval = ApprovalRequest::new(
            &self.id,
            self.requester,
            approver_role,
            self.transaction.clone(),
            self.policy_decision.clone(),
        );

        self.approval = Some(approval);
        self.status = SessionStatus::PendingApproval;

        Ok(self.approval.as_ref().unwrap())
    }

    /// Process an approval response
    pub fn process_approval(&mut self, response: ApprovalResponse) -> Result<()> {
        let approval = self
            .approval
            .as_mut()
            .ok_or_else(|| RelayError::ApprovalNotFound(self.id.clone()))?;

        approval.process_response(response)?;

        match approval.status {
            ApprovalStatus::Approved => {
                self.status = SessionStatus::Signing;
            }
            ApprovalStatus::Rejected => {
                self.status = SessionStatus::Rejected;
            }
            ApprovalStatus::Expired => {
                self.status = SessionStatus::Expired;
            }
            ApprovalStatus::Cancelled => {
                self.status = SessionStatus::Cancelled;
            }
            _ => {}
        }

        Ok(())
    }

    /// Add a partial signature
    pub fn add_partial_signature(&mut self, signature: PartialSignature) -> Result<()> {
        if self.status != SessionStatus::Signing {
            return Err(RelayError::InvalidSessionState {
                expected: "Signing".to_string(),
                actual: format!("{:?}", self.status),
            });
        }

        if !self.participants.contains(&signature.role) {
            return Err(RelayError::InvalidParty(format!(
                "{:?} is not a participant",
                signature.role
            )));
        }

        self.partial_signatures.insert(signature.role, signature);

        // Check if we have enough signatures (threshold = 2)
        if self.partial_signatures.len() >= 2 {
            // Ready to combine signatures
        }

        Ok(())
    }

    /// Complete the session with final signature
    pub fn complete(&mut self, signature: Vec<u8>) -> Result<()> {
        if self.status != SessionStatus::Signing {
            return Err(RelayError::InvalidSessionState {
                expected: "Signing".to_string(),
                actual: format!("{:?}", self.status),
            });
        }

        self.final_signature = Some(signature);
        self.status = SessionStatus::Completed;
        self.completed_at = Some(Utc::now());

        Ok(())
    }

    /// Mark session as failed
    pub fn fail(&mut self, error: impl Into<String>) {
        self.status = SessionStatus::Failed;
        self.error = Some(error.into());
        self.completed_at = Some(Utc::now());
    }

    /// Cancel the session
    pub fn cancel(&mut self) -> Result<()> {
        if self.status.is_finalized() {
            return Err(RelayError::InvalidSessionState {
                expected: "Active session".to_string(),
                actual: format!("{:?}", self.status),
            });
        }

        if let Some(approval) = &mut self.approval {
            let _ = approval.cancel();
        }

        self.status = SessionStatus::Cancelled;
        self.completed_at = Some(Utc::now());

        Ok(())
    }

    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Update status if expired
    pub fn check_expiration(&mut self) {
        if self.status.is_active() && self.is_expired() {
            self.status = SessionStatus::Expired;
            self.completed_at = Some(Utc::now());
        }
    }

    /// Advance to next MPC round
    pub fn advance_round(&mut self) {
        self.current_round += 1;
    }

    /// Get time remaining in seconds
    pub fn time_remaining_secs(&self) -> i64 {
        (self.expires_at - Utc::now()).num_seconds().max(0)
    }
}

/// Session manager configuration
#[derive(Debug, Clone)]
pub struct SessionManagerConfig {
    /// Session TTL in seconds
    pub session_ttl_secs: i64,
    /// Maximum concurrent sessions per wallet
    pub max_sessions_per_wallet: usize,
    /// Cleanup interval in seconds
    pub cleanup_interval_secs: u64,
}

impl Default for SessionManagerConfig {
    fn default() -> Self {
        Self {
            session_ttl_secs: 600, // 10 minutes
            max_sessions_per_wallet: 5,
            cleanup_interval_secs: 60,
        }
    }
}

/// Session manager for tracking signing sessions
pub struct SessionManager {
    /// Sessions indexed by ID
    sessions: DashMap<SessionId, SigningSession>,
    /// Sessions indexed by wallet address
    wallet_sessions: DashMap<String, Vec<SessionId>>,
    /// Approvals indexed by ID
    approvals: DashMap<ApprovalId, SessionId>,
    /// Message store for MPC messages
    message_store: MessageStore,
    /// Configuration
    config: SessionManagerConfig,
    /// Statistics
    stats: Arc<RwLock<SessionStats>>,
}

/// Session statistics
#[derive(Debug, Default, Clone)]
pub struct SessionStats {
    pub total_created: u64,
    pub total_completed: u64,
    pub total_rejected: u64,
    pub total_expired: u64,
    pub total_failed: u64,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        Self::with_config(SessionManagerConfig::default())
    }

    /// Create with configuration
    pub fn with_config(config: SessionManagerConfig) -> Self {
        Self {
            sessions: DashMap::new(),
            wallet_sessions: DashMap::new(),
            approvals: DashMap::new(),
            message_store: MessageStore::new(),
            config,
            stats: Arc::new(RwLock::new(SessionStats::default())),
        }
    }

    /// Create a new signing session
    pub fn create_session(
        &self,
        wallet_address: impl Into<String>,
        transaction: TransactionRequest,
        policy_decision: PolicyDecision,
        requester: PartyRole,
        participants: Vec<PartyRole>,
    ) -> Result<SigningSession> {
        let wallet = wallet_address.into();

        // Check session limit per wallet
        if let Some(sessions) = self.wallet_sessions.get(&wallet) {
            let active_count = sessions
                .iter()
                .filter(|id| {
                    self.sessions
                        .get(*id)
                        .map(|s| s.status.is_active())
                        .unwrap_or(false)
                })
                .count();

            if active_count >= self.config.max_sessions_per_wallet {
                return Err(RelayError::RateLimited(format!(
                    "Maximum {} active sessions per wallet",
                    self.config.max_sessions_per_wallet
                )));
            }
        }

        let mut session = SigningSession::new(
            &wallet,
            transaction,
            policy_decision,
            requester,
            participants,
        );
        session.expires_at = Utc::now() + chrono::Duration::seconds(self.config.session_ttl_secs);

        let session_id = session.id.clone();

        // Store session
        self.sessions.insert(session_id.clone(), session.clone());

        // Track by wallet
        self.wallet_sessions
            .entry(wallet)
            .or_insert_with(Vec::new)
            .push(session_id);

        // Update stats
        self.stats.write().total_created += 1;

        Ok(session)
    }

    /// Get a session by ID
    pub fn get_session(&self, session_id: &str) -> Result<SigningSession> {
        self.sessions
            .get(session_id)
            .map(|s| s.value().clone())
            .ok_or_else(|| RelayError::SessionNotFound(session_id.to_string()))
    }

    /// Get sessions for a wallet
    pub fn get_wallet_sessions(&self, wallet_address: &str) -> Vec<SigningSession> {
        self.wallet_sessions
            .get(wallet_address)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.sessions.get(id).map(|s| s.value().clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Create approval for a session
    pub fn create_approval(
        &self,
        session_id: &str,
        approver_role: PartyRole,
    ) -> Result<ApprovalRequest> {
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| RelayError::SessionNotFound(session_id.to_string()))?;

        let approval = session.create_approval(approver_role)?;
        let approval_id = approval.id.clone();
        let approval_clone = approval.clone();

        // Index approval
        self.approvals.insert(approval_id, session_id.to_string());

        Ok(approval_clone)
    }

    /// Get approval by ID
    pub fn get_approval(&self, approval_id: &str) -> Result<ApprovalRequest> {
        let session_id = self
            .approvals
            .get(approval_id)
            .ok_or_else(|| RelayError::ApprovalNotFound(approval_id.to_string()))?;

        let session = self.get_session(&session_id)?;

        session
            .approval
            .ok_or_else(|| RelayError::ApprovalNotFound(approval_id.to_string()))
    }

    /// Get pending approvals for a role
    pub fn get_pending_approvals(&self, approver_role: PartyRole) -> Vec<ApprovalRequest> {
        self.sessions
            .iter()
            .filter_map(|entry| {
                let session = entry.value();
                session.approval.as_ref().and_then(|a| {
                    if a.status.is_pending() && a.approver_role == approver_role {
                        Some(a.clone())
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    /// Process approval response
    pub fn process_approval(&self, response: ApprovalResponse) -> Result<SigningSession> {
        let session_id = self
            .approvals
            .get(&response.approval_id)
            .ok_or_else(|| RelayError::ApprovalNotFound(response.approval_id.clone()))?
            .clone();

        let mut session = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| RelayError::SessionNotFound(session_id.clone()))?;

        session.process_approval(response)?;

        // Update stats
        let mut stats = self.stats.write();
        match session.status {
            SessionStatus::Rejected => stats.total_rejected += 1,
            SessionStatus::Expired => stats.total_expired += 1,
            _ => {}
        }

        Ok(session.clone())
    }

    /// Add partial signature to session
    pub fn add_partial_signature(
        &self,
        session_id: &str,
        signature: PartialSignature,
    ) -> Result<SigningSession> {
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| RelayError::SessionNotFound(session_id.to_string()))?;

        session.add_partial_signature(signature)?;
        Ok(session.clone())
    }

    /// Complete a session
    pub fn complete_session(&self, session_id: &str, signature: Vec<u8>) -> Result<SigningSession> {
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| RelayError::SessionNotFound(session_id.to_string()))?;

        session.complete(signature)?;
        self.stats.write().total_completed += 1;

        Ok(session.clone())
    }

    /// Fail a session
    pub fn fail_session(&self, session_id: &str, error: impl Into<String>) -> Result<()> {
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| RelayError::SessionNotFound(session_id.to_string()))?;

        session.fail(error);
        self.stats.write().total_failed += 1;

        Ok(())
    }

    /// Cancel a session
    pub fn cancel_session(&self, session_id: &str) -> Result<()> {
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| RelayError::SessionNotFound(session_id.to_string()))?;

        session.cancel()
    }

    /// Get message store
    pub fn message_store(&self) -> &MessageStore {
        &self.message_store
    }

    /// Cleanup expired sessions and messages
    pub fn cleanup(&self) {
        let now = Utc::now();
        let mut expired_stats = 0u64;

        // Check and expire sessions
        for mut entry in self.sessions.iter_mut() {
            if entry.status.is_active() && entry.is_expired() {
                entry.status = SessionStatus::Expired;
                entry.completed_at = Some(now);
                expired_stats += 1;
            }
        }

        // Remove old finalized sessions (keep for 1 hour after completion)
        let cutoff = now - chrono::Duration::hours(1);
        self.sessions
            .retain(|_, session| session.completed_at.map(|t| t > cutoff).unwrap_or(true));

        // Cleanup approval index
        self.approvals
            .retain(|_, session_id| self.sessions.contains_key(session_id));

        // Cleanup wallet session index
        for mut entry in self.wallet_sessions.iter_mut() {
            entry
                .value_mut()
                .retain(|id| self.sessions.contains_key(id));
        }
        self.wallet_sessions.retain(|_, ids| !ids.is_empty());

        // Cleanup messages
        self.message_store.cleanup();

        // Update stats
        if expired_stats > 0 {
            self.stats.write().total_expired += expired_stats;
        }
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get active session count
    pub fn active_session_count(&self) -> usize {
        self.sessions
            .iter()
            .filter(|e| e.value().status.is_active())
            .count()
    }

    /// Get statistics
    pub fn stats(&self) -> SessionStats {
        self.stats.read().clone()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
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
    fn test_session_creation() {
        let manager = SessionManager::new();

        let session = manager
            .create_session(
                "0xWallet",
                create_test_tx(),
                PolicyDecision::Approve,
                PartyRole::Agent,
                vec![PartyRole::Agent, PartyRole::User],
            )
            .unwrap();

        assert_eq!(session.status, SessionStatus::Created);
        assert_eq!(session.requester, PartyRole::Agent);
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_approval_flow() {
        let manager = SessionManager::new();

        // Create session
        let session = manager
            .create_session(
                "0xWallet",
                create_test_tx(),
                PolicyDecision::Approve,
                PartyRole::Agent,
                vec![PartyRole::Agent, PartyRole::User],
            )
            .unwrap();

        // Create approval
        let approval = manager
            .create_approval(&session.id, PartyRole::User)
            .unwrap();

        assert!(approval.status.is_pending());

        // Approve
        let response = ApprovalResponse::approve(&approval.id, PartyRole::User);
        let updated = manager.process_approval(response).unwrap();

        assert_eq!(updated.status, SessionStatus::Signing);
    }

    #[test]
    fn test_rejection_flow() {
        let manager = SessionManager::new();

        let session = manager
            .create_session(
                "0xWallet",
                create_test_tx(),
                PolicyDecision::Approve,
                PartyRole::Agent,
                vec![PartyRole::Agent, PartyRole::User],
            )
            .unwrap();

        let approval = manager
            .create_approval(&session.id, PartyRole::User)
            .unwrap();

        let response = ApprovalResponse::reject(&approval.id, PartyRole::User, "Not now");
        let updated = manager.process_approval(response).unwrap();

        assert_eq!(updated.status, SessionStatus::Rejected);
    }

    #[test]
    fn test_session_limit() {
        let config = SessionManagerConfig {
            max_sessions_per_wallet: 2,
            ..Default::default()
        };
        let manager = SessionManager::with_config(config);

        // First two should succeed
        manager
            .create_session(
                "0xWallet",
                create_test_tx(),
                PolicyDecision::Approve,
                PartyRole::Agent,
                vec![PartyRole::Agent, PartyRole::User],
            )
            .unwrap();

        manager
            .create_session(
                "0xWallet",
                create_test_tx(),
                PolicyDecision::Approve,
                PartyRole::Agent,
                vec![PartyRole::Agent, PartyRole::User],
            )
            .unwrap();

        // Third should fail
        let result = manager.create_session(
            "0xWallet",
            create_test_tx(),
            PolicyDecision::Approve,
            PartyRole::Agent,
            vec![PartyRole::Agent, PartyRole::User],
        );

        assert!(matches!(result, Err(RelayError::RateLimited(_))));
    }

    #[test]
    fn test_pending_approvals() {
        let manager = SessionManager::new();

        // Create session with approval for User
        let session = manager
            .create_session(
                "0xWallet",
                create_test_tx(),
                PolicyDecision::Approve,
                PartyRole::Agent,
                vec![PartyRole::Agent, PartyRole::User],
            )
            .unwrap();

        manager
            .create_approval(&session.id, PartyRole::User)
            .unwrap();

        // Get pending for User
        let pending = manager.get_pending_approvals(PartyRole::User);
        assert_eq!(pending.len(), 1);

        // Get pending for Recovery (should be empty)
        let pending_recovery = manager.get_pending_approvals(PartyRole::Recovery);
        assert!(pending_recovery.is_empty());
    }
}
