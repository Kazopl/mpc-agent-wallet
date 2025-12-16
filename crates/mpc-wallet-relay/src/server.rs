//! HTTP/WebSocket server for the wallet relay service
//!
//! Provides REST endpoints for session management and approval flows,
//! plus WebSocket support for real-time updates.
//!
//! ## Production Features
//!
//! - Graceful shutdown on SIGTERM/SIGINT
//! - Request timeout middleware
//! - CORS configuration
//! - Health checks and metrics
//! - WebSocket real-time streaming

use crate::{
    ApprovalMethod, ApprovalResponse, ApprovalStatus, HealthResponse, MessageId,
    NotificationService, NotificationTarget, PartialSignature, PollingChannel, QrCodeChannel,
    RelayError, SessionManager, SessionStatus, StatsResponse, WebhookConfig, WebhookService,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State, WebSocketUpgrade},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use chrono::{DateTime, Utc};
use futures_util::{SinkExt, StreamExt};
use mpc_wallet_core::{PartyRole, PolicyDecision, TransactionRequest};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

/// Relay service configuration
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Base URL for the service
    pub base_url: String,
    /// Session TTL in seconds
    pub session_ttl_secs: i64,
    /// Maximum sessions per wallet
    pub max_sessions_per_wallet: usize,
    /// Message TTL in seconds
    pub message_ttl_secs: i64,
    /// Cleanup interval in seconds
    pub cleanup_interval_secs: u64,
    /// Enable CORS
    pub cors_enabled: bool,
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
    /// Shutdown timeout in seconds
    pub shutdown_timeout_secs: u64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:8080".to_string(),
            session_ttl_secs: 600,
            max_sessions_per_wallet: 5,
            message_ttl_secs: 3600,
            cleanup_interval_secs: 60,
            cors_enabled: true,
            request_timeout_secs: 30,
            shutdown_timeout_secs: 30,
        }
    }
}

impl RelayConfig {
    /// Create with custom base URL
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Set request timeout
    pub fn with_request_timeout(mut self, secs: u64) -> Self {
        self.request_timeout_secs = secs;
        self
    }

    /// Set shutdown timeout
    pub fn with_shutdown_timeout(mut self, secs: u64) -> Self {
        self.shutdown_timeout_secs = secs;
        self
    }

    /// Disable CORS
    pub fn without_cors(mut self) -> Self {
        self.cors_enabled = false;
        self
    }
}

/// Application state shared across handlers
pub struct AppState {
    /// Session manager
    pub sessions: SessionManager,
    /// Webhook service
    pub webhooks: WebhookService,
    /// Notification service
    pub notifications: NotificationService,
    /// Event broadcaster for WebSocket
    pub event_tx: broadcast::Sender<SessionEvent>,
    /// Service start time
    pub started_at: Instant,
    /// Configuration
    pub config: RelayConfig,
}

/// Events broadcast to WebSocket clients
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEvent {
    /// Session created
    SessionCreated {
        session_id: String,
        wallet_address: String,
    },
    /// Approval requested
    ApprovalRequested {
        session_id: String,
        approval_id: String,
        expires_at: DateTime<Utc>,
    },
    /// Approval processed
    ApprovalProcessed {
        session_id: String,
        approval_id: String,
        status: ApprovalStatus,
    },
    /// Session status changed
    SessionStatusChanged {
        session_id: String,
        status: SessionStatus,
    },
    /// MPC message available
    MessageAvailable {
        session_id: String,
        round: u32,
        from: usize,
    },
}

/// Wallet relay service
pub struct WalletRelayService {
    state: Arc<AppState>,
}

impl WalletRelayService {
    /// Create a new relay service
    pub fn new(config: RelayConfig) -> Self {
        let (event_tx, _) = broadcast::channel(1000);

        let notifications = NotificationService::new(&config.base_url);

        let state = Arc::new(AppState {
            sessions: SessionManager::new(),
            webhooks: WebhookService::new(),
            notifications,
            event_tx,
            started_at: Instant::now(),
            config,
        });

        Self { state }
    }

    /// Get a reference to the session manager
    pub fn sessions(&self) -> &SessionManager {
        &self.state.sessions
    }

    /// Get a reference to the webhook service
    pub fn webhooks(&self) -> &WebhookService {
        &self.state.webhooks
    }

    /// Get a reference to the notification service
    pub fn notifications(&self) -> &NotificationService {
        &self.state.notifications
    }

    /// Add a webhook
    pub async fn add_webhook(&self, config: WebhookConfig) {
        self.state.webhooks.add_webhook(config).await;
    }

    /// Register default notification channels
    pub async fn register_default_channels(&self) {
        self.state
            .notifications
            .register_channel(Arc::new(PollingChannel))
            .await;
        self.state
            .notifications
            .register_channel(Arc::new(QrCodeChannel))
            .await;
    }

    /// Build the router
    pub fn router(&self) -> Router {
        let state = Arc::clone(&self.state);
        let timeout = Duration::from_secs(self.state.config.request_timeout_secs);

        let mut router = Router::new()
            // Health and stats
            .route("/health", get(health))
            .route("/ready", get(ready))
            .route("/stats", get(stats))
            // Session management
            .route("/v1/sessions", post(create_session))
            .route("/v1/sessions/:session_id", get(get_session))
            .route("/v1/sessions/:session_id", delete(cancel_session))
            .route("/v1/sessions/:session_id/status", get(get_session_status))
            // Approval endpoints
            .route("/v1/sessions/:session_id/approval", post(request_approval))
            .route("/v1/sessions/:session_id/approve", post(approve_session))
            .route("/v1/approvals/:approval_id", get(get_approval))
            .route("/v1/approvals/:approval_id/approve", post(process_approval))
            .route("/v1/approvals/pending", get(get_pending_approvals))
            // Message relay
            .route("/v1/sessions/:session_id/messages", post(post_message))
            .route("/v1/sessions/:session_id/messages", get(get_messages))
            // Signature collection
            .route(
                "/v1/sessions/:session_id/signatures",
                post(submit_partial_signature),
            )
            .route("/v1/sessions/:session_id/complete", post(complete_session))
            // WebSocket
            .route("/v1/ws", get(websocket_handler))
            .route("/v1/sessions/:session_id/stream", get(session_websocket))
            // Webhook management
            .route("/v1/webhooks", get(list_webhooks))
            .route("/v1/webhooks", post(add_webhook))
            .route("/v1/webhooks", delete(remove_webhook))
            .layer(
                ServiceBuilder::new()
                    .layer(TraceLayer::new_for_http())
                    .layer(TimeoutLayer::with_status_code(
                        StatusCode::REQUEST_TIMEOUT,
                        timeout,
                    )),
            )
            .with_state(state);

        if self.state.config.cors_enabled {
            router = router.layer(CorsLayer::permissive());
        }

        router
    }

    /// Start the relay service with graceful shutdown
    pub async fn serve(self, addr: impl Into<SocketAddr>) -> anyhow::Result<()> {
        let addr = addr.into();
        let state = Arc::clone(&self.state);
        let shutdown_timeout = Duration::from_secs(self.state.config.shutdown_timeout_secs);

        // Register default notification channels
        self.register_default_channels().await;

        // Start cleanup task
        let cleanup_state = Arc::clone(&state);
        let cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(
                cleanup_state.config.cleanup_interval_secs,
            ));
            loop {
                interval.tick().await;
                cleanup_state.sessions.cleanup();
            }
        });

        info!(address = %addr, "Starting wallet relay service");

        let router = self.router();
        let listener = tokio::net::TcpListener::bind(addr).await?;

        // Setup graceful shutdown
        let shutdown_signal = shutdown_signal();

        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal)
            .await?;

        info!("Shutdown signal received, cleaning up...");

        // Stop cleanup task
        cleanup_handle.abort();

        // Give time for in-flight requests to complete
        tokio::time::sleep(shutdown_timeout).await;

        info!("Relay service stopped");
        Ok(())
    }

    /// Start without graceful shutdown (for testing)
    pub async fn serve_until_stopped(self, addr: impl Into<SocketAddr>) -> anyhow::Result<()> {
        let addr = addr.into();
        let state = Arc::clone(&self.state);

        self.register_default_channels().await;

        let cleanup_state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(
                cleanup_state.config.cleanup_interval_secs,
            ));
            loop {
                interval.tick().await;
                cleanup_state.sessions.cleanup();
            }
        });

        info!(address = %addr, "Starting wallet relay service");

        let router = self.router();
        let listener = tokio::net::TcpListener::bind(addr).await?;

        axum::serve(listener, router).await?;

        Ok(())
    }
}

/// Graceful shutdown signal handler
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, initiating graceful shutdown");
        },
        _ = terminate => {
            info!("Received SIGTERM, initiating graceful shutdown");
        },
    }
}

// ============================================================================
// Error Handling
// ============================================================================

/// API error response that implements IntoResponse
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub fn from_relay_error(e: RelayError) -> Self {
        Self {
            status: StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            message: e.to_string(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ApiResponse::<()>::error(&self.message));
        (self.status, body).into_response()
    }
}

impl From<RelayError> for ApiError {
    fn from(e: RelayError) -> Self {
        Self::from_relay_error(e)
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Create session request
#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub wallet_address: String,
    pub transaction: TransactionRequest,
    #[serde(default)]
    pub policy_decision: Option<PolicyDecision>,
    #[serde(default)]
    pub requester_role: Option<PartyRole>,
    pub participants: Vec<PartyRole>,
}

/// Request approval request
#[derive(Debug, Deserialize)]
pub struct RequestApprovalRequest {
    pub approver_role: PartyRole,
    #[serde(default)]
    pub approval_method: Option<ApprovalMethod>,
    #[serde(default)]
    pub notification_target: Option<NotificationTarget>,
}

/// Process approval request
#[derive(Debug, Deserialize)]
pub struct ProcessApprovalRequest {
    pub approved: bool,
    #[serde(default)]
    pub rejection_reason: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
}

/// Post message request
#[derive(Debug, Deserialize)]
pub struct PostMessageRequest {
    pub round: u32,
    pub from: Option<usize>,
    pub to: Option<usize>,
    pub tag: String,
    pub payload: String, // base64 encoded
}

/// Get messages query
#[derive(Debug, Deserialize)]
pub struct GetMessagesQuery {
    pub round: u32,
    #[serde(default)]
    pub party_id: Option<usize>,
}

/// Submit signature request
#[derive(Debug, Deserialize)]
pub struct SubmitSignatureRequest {
    pub party_id: usize,
    pub role: PartyRole,
    pub signature_data: String, // base64 encoded
}

/// Complete session request
#[derive(Debug, Deserialize)]
pub struct CompleteSessionRequest {
    pub signature: String, // hex encoded
}

/// Add webhook request
#[derive(Debug, Deserialize)]
pub struct AddWebhookRequest {
    pub url: String,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub events: Option<Vec<String>>,
}

/// Remove webhook request
#[derive(Debug, Deserialize)]
pub struct RemoveWebhookRequest {
    pub url: String,
}

/// Pending approvals query
#[derive(Debug, Deserialize)]
pub struct PendingApprovalsQuery {
    pub role: PartyRole,
}

/// API response wrapper
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// Health check (for load balancers)
async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "mpc-wallet-relay",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Readiness check (for Kubernetes)
async fn ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let response = HealthResponse {
        status: "ready".to_string(),
        service: "mpc-wallet-relay".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: state.started_at.elapsed().as_secs(),
        active_sessions: state.sessions.active_session_count(),
        pending_approvals: state.sessions.get_pending_approvals(PartyRole::User).len()
            + state
                .sessions
                .get_pending_approvals(PartyRole::Recovery)
                .len(),
    };

    Json(ApiResponse::success(response))
}

/// Get statistics
async fn stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let session_stats = state.sessions.stats();
    let total_approvals =
        session_stats.total_completed + session_stats.total_rejected + session_stats.total_expired;
    let approval_rate = if total_approvals > 0 {
        session_stats.total_completed as f64 / total_approvals as f64
    } else {
        0.0
    };

    let webhooks = state.webhooks.list_webhooks().await;

    let response = StatsResponse {
        total_sessions: session_stats.total_created,
        total_approvals,
        approval_rate,
        avg_approval_time_secs: 0.0, // TODO: Track this in SessionStats
        active_webhooks: webhooks.len(),
    };

    Json(ApiResponse::success(response))
}

/// Create a new signing session
async fn create_session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let policy_decision = req.policy_decision.unwrap_or(PolicyDecision::Approve);
    let requester = req.requester_role.unwrap_or(PartyRole::Agent);

    let session = state
        .sessions
        .create_session(
            &req.wallet_address,
            req.transaction,
            policy_decision,
            requester,
            req.participants,
        )
        .map_err(ApiError::from)?;

    // Broadcast event
    let _ = state.event_tx.send(SessionEvent::SessionCreated {
        session_id: session.id.clone(),
        wallet_address: session.wallet_address.clone(),
    });

    Ok((StatusCode::CREATED, Json(ApiResponse::success(session))))
}

/// Get a session by ID
async fn get_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let session = state
        .sessions
        .get_session(&session_id)
        .map_err(ApiError::from)?;
    Ok(Json(ApiResponse::success(session)))
}

/// Get session status
async fn get_session_status(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let session = state
        .sessions
        .get_session(&session_id)
        .map_err(ApiError::from)?;

    let status_info = serde_json::json!({
        "session_id": session.id,
        "status": session.status,
        "approval_status": session.approval.as_ref().map(|a| a.status),
        "partial_signatures": session.partial_signatures.len(),
        "time_remaining_secs": session.time_remaining_secs(),
    });

    Ok(Json(ApiResponse::success(status_info)))
}

/// Cancel a session
async fn cancel_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .sessions
        .cancel_session(&session_id)
        .map_err(ApiError::from)?;

    let _ = state.event_tx.send(SessionEvent::SessionStatusChanged {
        session_id: session_id.clone(),
        status: SessionStatus::Cancelled,
    });

    Ok(Json(ApiResponse::success(serde_json::json!({
        "session_id": session_id,
        "status": "cancelled"
    }))))
}

/// Request approval for a session
async fn request_approval(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(req): Json<RequestApprovalRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let approval = state
        .sessions
        .create_approval(&session_id, req.approver_role)
        .map_err(ApiError::from)?;

    // Send notifications if target provided
    if let Some(target) = req.notification_target {
        let results = state.notifications.notify_approval(&approval, target).await;
        let failed: Vec<_> = results.iter().filter(|r| !r.success).collect();
        if !failed.is_empty() {
            warn!(
                failed_count = failed.len(),
                "Some approval notifications failed"
            );
        }
    }

    // Notify webhooks
    if let Ok(session) = state.sessions.get_session(&session_id) {
        state
            .webhooks
            .notify_approval_requested(&session, &approval)
            .await;
    }

    // Broadcast event
    let _ = state.event_tx.send(SessionEvent::ApprovalRequested {
        session_id: session_id.clone(),
        approval_id: approval.id.clone(),
        expires_at: approval.expires_at,
    });

    Ok((StatusCode::CREATED, Json(ApiResponse::success(approval))))
}

/// Approve session (shorthand for request + immediate approval)
async fn approve_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(req): Json<ProcessApprovalRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Get existing approval or error
    let session = state
        .sessions
        .get_session(&session_id)
        .map_err(ApiError::from)?;

    let approval_id = session
        .approval
        .as_ref()
        .ok_or_else(|| ApiError::bad_request("No approval request exists. Create one first."))?
        .id
        .clone();

    // Get approver role from the approval
    let approval = state
        .sessions
        .get_approval(&approval_id)
        .map_err(ApiError::from)?;
    let approver_role = approval.approver_role;

    // Build response
    let mut response = if req.approved {
        ApprovalResponse::approve(&approval_id, approver_role)
    } else {
        ApprovalResponse::reject(
            &approval_id,
            approver_role,
            req.rejection_reason
                .unwrap_or_else(|| "User rejected".to_string()),
        )
    };

    if let Some(device_id) = req.device_id {
        response = response.with_device_id(device_id);
    }

    let session = state
        .sessions
        .process_approval(response)
        .map_err(ApiError::from)?;

    // Notify webhooks
    state.webhooks.notify_approval_processed(&session).await;

    // Broadcast events
    if let Some(approval) = &session.approval {
        let _ = state.event_tx.send(SessionEvent::ApprovalProcessed {
            session_id: session_id.clone(),
            approval_id: approval.id.clone(),
            status: approval.status,
        });
    }

    let _ = state.event_tx.send(SessionEvent::SessionStatusChanged {
        session_id: session.id.clone(),
        status: session.status,
    });

    Ok(Json(ApiResponse::success(session)))
}

/// Get approval by ID
async fn get_approval(
    State(state): State<Arc<AppState>>,
    Path(approval_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let approval = state
        .sessions
        .get_approval(&approval_id)
        .map_err(ApiError::from)?;
    Ok(Json(ApiResponse::success(approval)))
}

/// Process approval response
async fn process_approval(
    State(state): State<Arc<AppState>>,
    Path(approval_id): Path<String>,
    Json(req): Json<ProcessApprovalRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Get approver role from the approval
    let approval = state
        .sessions
        .get_approval(&approval_id)
        .map_err(ApiError::from)?;
    let approver_role = approval.approver_role;

    let mut response = if req.approved {
        ApprovalResponse::approve(&approval_id, approver_role)
    } else {
        ApprovalResponse::reject(
            &approval_id,
            approver_role,
            req.rejection_reason
                .unwrap_or_else(|| "User rejected".to_string()),
        )
    };

    if let Some(device_id) = req.device_id {
        response = response.with_device_id(device_id);
    }

    let session = state
        .sessions
        .process_approval(response)
        .map_err(ApiError::from)?;

    state.webhooks.notify_approval_processed(&session).await;

    if let Some(approval) = &session.approval {
        let _ = state.event_tx.send(SessionEvent::ApprovalProcessed {
            session_id: session.id.clone(),
            approval_id: approval.id.clone(),
            status: approval.status,
        });
    }

    Ok(Json(ApiResponse::success(session)))
}

/// Get pending approvals for a role
async fn get_pending_approvals(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PendingApprovalsQuery>,
) -> impl IntoResponse {
    let approvals = state.sessions.get_pending_approvals(query.role);
    Json(ApiResponse::success(approvals))
}

/// Post MPC message
async fn post_message(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(req): Json<PostMessageRequest>,
) -> Result<impl IntoResponse, ApiError> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let payload = STANDARD
        .decode(&req.payload)
        .map_err(|e| ApiError::bad_request(format!("Invalid base64: {}", e)))?;

    let id = MessageId::new(&session_id, req.round, req.from, req.to, &req.tag);

    let hash = state
        .sessions
        .message_store()
        .put(id, payload)
        .map_err(ApiError::from)?;

    // Broadcast message available event
    if let Some(from) = req.from {
        let _ = state.event_tx.send(SessionEvent::MessageAvailable {
            session_id,
            round: req.round,
            from,
        });
    }

    Ok(Json(ApiResponse::success(hash)))
}

/// Get MPC messages
async fn get_messages(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Query(query): Query<GetMessagesQuery>,
) -> impl IntoResponse {
    let messages = if let Some(party_id) = query.party_id {
        state
            .sessions
            .message_store()
            .get_messages_for_party(&session_id, query.round, party_id)
    } else {
        state
            .sessions
            .message_store()
            .get_round_messages(&session_id, query.round)
    };

    // Convert payloads to base64
    use base64::{Engine, engine::general_purpose::STANDARD};
    let messages: Vec<_> = messages
        .into_iter()
        .map(|m| {
            serde_json::json!({
                "id": m.id,
                "payload": STANDARD.encode(&m.payload),
                "created_at": m.created_at,
            })
        })
        .collect();

    Json(ApiResponse::success(messages))
}

/// Submit partial signature
async fn submit_partial_signature(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(req): Json<SubmitSignatureRequest>,
) -> Result<impl IntoResponse, ApiError> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let signature_data = STANDARD
        .decode(&req.signature_data)
        .map_err(|e| ApiError::bad_request(format!("Invalid base64: {}", e)))?;

    let signature = PartialSignature {
        session_id: session_id.clone(),
        party_id: req.party_id,
        role: req.role,
        signature_data,
        created_at: Utc::now(),
    };

    let session = state
        .sessions
        .add_partial_signature(&session_id, signature)
        .map_err(ApiError::from)?;

    Ok(Json(ApiResponse::success(session)))
}

/// Complete signing session
async fn complete_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(req): Json<CompleteSessionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let signature = hex::decode(&req.signature)
        .map_err(|e| ApiError::bad_request(format!("Invalid hex: {}", e)))?;

    let session = state
        .sessions
        .complete_session(&session_id, signature)
        .map_err(ApiError::from)?;

    state.webhooks.notify_session_completed(&session).await;

    let _ = state.event_tx.send(SessionEvent::SessionStatusChanged {
        session_id: session.id.clone(),
        status: session.status,
    });

    Ok(Json(ApiResponse::success(session)))
}

/// List webhooks
async fn list_webhooks(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let webhooks = state.webhooks.list_webhooks().await;
    Json(ApiResponse::success(webhooks))
}

/// Add webhook
async fn add_webhook(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddWebhookRequest>,
) -> impl IntoResponse {
    let mut config = WebhookConfig::new(&req.url);

    if let Some(secret) = req.secret {
        config = config.with_secret(secret);
    }

    state.webhooks.add_webhook(config).await;

    (
        StatusCode::CREATED,
        Json(ApiResponse::success(serde_json::json!({
            "url": req.url,
            "status": "added"
        }))),
    )
}

/// Remove webhook
async fn remove_webhook(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RemoveWebhookRequest>,
) -> impl IntoResponse {
    state.webhooks.remove_webhook(&req.url).await;

    Json(ApiResponse::success(serde_json::json!({
        "url": req.url,
        "status": "removed"
    })))
}

/// WebSocket handler for global events
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_global_websocket(socket, state))
}

async fn handle_global_websocket(socket: axum::extract::ws::WebSocket, state: Arc<AppState>) {
    use axum::extract::ws::Message;

    let (mut sender, mut receiver) = socket.split();
    let mut event_rx = state.event_tx.subscribe();

    // Spawn task to send events
    let send_task = tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            if let Ok(json) = serde_json::to_string(&event) {
                if sender.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
        }
    });

    // Handle incoming messages (ping/pong, close)
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(_)) => {
                // Pong is handled automatically by axum
            }
            Err(e) => {
                warn!(error = %e, "WebSocket error");
                break;
            }
            _ => {}
        }
    }

    send_task.abort();
}

/// WebSocket handler for session-specific events
async fn session_websocket(
    ws: WebSocketUpgrade,
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_session_websocket(socket, session_id, state))
}

async fn handle_session_websocket(
    socket: axum::extract::ws::WebSocket,
    session_id: String,
    state: Arc<AppState>,
) {
    use axum::extract::ws::Message;

    let (mut sender, mut receiver) = socket.split();
    let mut event_rx = state.event_tx.subscribe();

    // Send current session state
    if let Ok(session) = state.sessions.get_session(&session_id)
        && let Ok(json) = serde_json::to_string(&session)
    {
        let _ = sender.send(Message::Text(json.into())).await;
    }

    let target_session_id = session_id.clone();

    // Spawn task to send filtered events
    let send_task = tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            let matches = match &event {
                SessionEvent::SessionCreated { session_id, .. } => *session_id == target_session_id,
                SessionEvent::ApprovalRequested { session_id, .. } => {
                    *session_id == target_session_id
                }
                SessionEvent::ApprovalProcessed { session_id, .. } => {
                    *session_id == target_session_id
                }
                SessionEvent::SessionStatusChanged { session_id, .. } => {
                    *session_id == target_session_id
                }
                SessionEvent::MessageAvailable { session_id, .. } => {
                    *session_id == target_session_id
                }
            };

            if matches
                && let Ok(json) = serde_json::to_string(&event)
                && sender.send(Message::Text(json.into())).await.is_err()
            {
                break;
            }
        }
    });

    // Handle incoming messages
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Close(_)) => break,
            Err(e) => {
                warn!(error = %e, "Session WebSocket error");
                break;
            }
            _ => {}
        }
    }

    send_task.abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_config() {
        let config = RelayConfig::default()
            .with_base_url("https://relay.example.com")
            .with_request_timeout(60)
            .without_cors();

        assert_eq!(config.base_url, "https://relay.example.com");
        assert_eq!(config.request_timeout_secs, 60);
        assert!(!config.cors_enabled);
    }

    #[tokio::test]
    async fn test_wallet_relay_service() {
        let service = WalletRelayService::new(RelayConfig::default());

        // Test that we can create sessions
        let session = service
            .sessions()
            .create_session(
                "0xWallet",
                TransactionRequest::new(mpc_wallet_core::ChainType::Evm, "0x1234", "1000"),
                PolicyDecision::Approve,
                PartyRole::Agent,
                vec![PartyRole::Agent, PartyRole::User],
            )
            .unwrap();

        assert_eq!(session.status, SessionStatus::Created);
    }

    #[test]
    fn test_api_error() {
        let error = ApiError::bad_request("test error");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);

        let error = ApiError::not_found("not found");
        assert_eq!(error.status, StatusCode::NOT_FOUND);
    }
}
