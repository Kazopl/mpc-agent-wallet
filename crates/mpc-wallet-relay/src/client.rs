//! Relay client for connecting to the wallet relay service
//!
//! Provides both HTTP and WebSocket client implementations.

use crate::{ApprovalRequest, ApprovalStatus, MessageId, RelayError, Result, SigningSession};
use futures_util::StreamExt;
use mpc_wallet_core::{PartyRole, TransactionRequest};
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, info};

/// Relay client configuration
#[derive(Debug, Clone)]
pub struct RelayClientConfig {
    /// Relay service URL (HTTP)
    pub url: String,
    /// WebSocket URL (optional, derived from url if not set)
    pub ws_url: Option<String>,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Retry configuration
    pub max_retries: u32,
    /// Retry delay in milliseconds
    pub retry_delay_ms: u64,
}

impl RelayClientConfig {
    /// Create a new config
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ws_url: None,
            timeout_secs: 30,
            max_retries: 3,
            retry_delay_ms: 1000,
        }
    }

    /// Set WebSocket URL
    pub fn with_ws_url(mut self, url: impl Into<String>) -> Self {
        self.ws_url = Some(url.into());
        self
    }

    /// Get WebSocket URL
    pub fn get_ws_url(&self) -> String {
        self.ws_url.clone().unwrap_or_else(|| {
            self.url
                .replace("http://", "ws://")
                .replace("https://", "wss://")
        })
    }
}

/// API response structure
#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn into_result(self) -> Result<T> {
        if self.success {
            self.data
                .ok_or_else(|| RelayError::Internal("No data in response".to_string()))
        } else {
            Err(RelayError::Internal(
                self.error.unwrap_or_else(|| "Unknown error".to_string()),
            ))
        }
    }
}

/// Relay client for HTTP communication
pub struct RelayClient {
    config: RelayClientConfig,
    client: Client,
    /// Event receiver for WebSocket events
    event_tx: broadcast::Sender<SessionEvent>,
    /// WebSocket connection state
    ws_connected: Arc<RwLock<bool>>,
}

/// Events received from WebSocket
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEvent {
    SessionCreated {
        session_id: String,
        wallet_address: String,
    },
    ApprovalRequested {
        session_id: String,
        approval_id: String,
        expires_at: String,
    },
    ApprovalProcessed {
        session_id: String,
        approval_id: String,
        status: ApprovalStatus,
    },
    SessionStatusChanged {
        session_id: String,
        status: String,
    },
    MessageAvailable {
        session_id: String,
        round: u32,
        from: usize,
    },
}

impl RelayClient {
    /// Create a new relay client
    pub fn new(config: RelayClientConfig) -> Self {
        let (event_tx, _) = broadcast::channel(100);

        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(config.timeout_secs))
                .build()
                .expect("Failed to create HTTP client"),
            config,
            event_tx,
            ws_connected: Arc::new(RwLock::new(false)),
        }
    }

    /// Create with default configuration
    pub fn with_url(url: impl Into<String>) -> Self {
        Self::new(RelayClientConfig::new(url))
    }

    /// Subscribe to events
    pub fn subscribe(&self) -> broadcast::Receiver<SessionEvent> {
        self.event_tx.subscribe()
    }

    /// Check if WebSocket is connected
    pub async fn is_connected(&self) -> bool {
        *self.ws_connected.read().await
    }

    // ========================================================================
    // Session Management
    // ========================================================================

    /// Create a new signing session
    pub async fn create_session(
        &self,
        wallet_address: &str,
        transaction: TransactionRequest,
        requester: PartyRole,
        participants: Vec<PartyRole>,
    ) -> Result<SigningSession> {
        let url = format!("{}/v1/sessions", self.config.url);

        let response: ApiResponse<SigningSession> = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "wallet_address": wallet_address,
                "transaction": transaction,
                "requester_role": requester,
                "participants": participants,
            }))
            .send()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?;

        response.into_result()
    }

    /// Get a session by ID
    pub async fn get_session(&self, session_id: &str) -> Result<SigningSession> {
        let url = format!("{}/v1/sessions/{}", self.config.url, session_id);

        let response: ApiResponse<SigningSession> = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?;

        response.into_result()
    }

    /// Cancel a session
    pub async fn cancel_session(&self, session_id: &str) -> Result<()> {
        let url = format!("{}/v1/sessions/{}", self.config.url, session_id);

        let response: ApiResponse<serde_json::Value> = self
            .client
            .delete(&url)
            .send()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?;

        response.into_result().map(|_| ())
    }

    // ========================================================================
    // Approval Flow
    // ========================================================================

    /// Request approval for a session
    pub async fn request_approval(
        &self,
        session_id: &str,
        approver_role: PartyRole,
    ) -> Result<ApprovalRequest> {
        let url = format!("{}/v1/sessions/{}/approval", self.config.url, session_id);

        let response: ApiResponse<ApprovalRequest> = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "approver_role": approver_role,
            }))
            .send()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?;

        response.into_result()
    }

    /// Get an approval by ID
    pub async fn get_approval(&self, approval_id: &str) -> Result<ApprovalRequest> {
        let url = format!("{}/v1/approvals/{}", self.config.url, approval_id);

        let response: ApiResponse<ApprovalRequest> = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?;

        response.into_result()
    }

    /// Approve a transaction
    pub async fn approve(
        &self,
        approval_id: &str,
        device_id: Option<&str>,
    ) -> Result<SigningSession> {
        let url = format!("{}/v1/approvals/{}/approve", self.config.url, approval_id);

        let mut body = serde_json::json!({
            "approved": true,
        });

        if let Some(id) = device_id {
            body["device_id"] = serde_json::json!(id);
        }

        let response: ApiResponse<SigningSession> = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?;

        response.into_result()
    }

    /// Reject a transaction
    pub async fn reject(&self, approval_id: &str, reason: &str) -> Result<SigningSession> {
        let url = format!("{}/v1/approvals/{}/approve", self.config.url, approval_id);

        let response: ApiResponse<SigningSession> = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "approved": false,
                "rejection_reason": reason,
            }))
            .send()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?;

        response.into_result()
    }

    /// Get pending approvals for a role
    pub async fn get_pending_approvals(&self, role: PartyRole) -> Result<Vec<ApprovalRequest>> {
        let url = format!("{}/v1/approvals/pending?role={:?}", self.config.url, role);

        let response: ApiResponse<Vec<ApprovalRequest>> = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?;

        response.into_result()
    }

    // ========================================================================
    // Message Relay
    // ========================================================================

    /// Post an MPC message
    pub async fn post_message(
        &self,
        session_id: &str,
        round: u32,
        from: Option<usize>,
        to: Option<usize>,
        tag: &str,
        payload: &[u8],
    ) -> Result<String> {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let url = format!("{}/v1/sessions/{}/messages", self.config.url, session_id);

        let response: ApiResponse<String> = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "round": round,
                "from": from,
                "to": to,
                "tag": tag,
                "payload": STANDARD.encode(payload),
            }))
            .send()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?;

        response.into_result()
    }

    /// Get messages for a round
    pub async fn get_messages(
        &self,
        session_id: &str,
        round: u32,
        party_id: Option<usize>,
    ) -> Result<Vec<RelayMessage>> {
        let mut url = format!(
            "{}/v1/sessions/{}/messages?round={}",
            self.config.url, session_id, round
        );

        if let Some(id) = party_id {
            url.push_str(&format!("&party_id={}", id));
        }

        let response: ApiResponse<Vec<RelayMessage>> = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?;

        response.into_result()
    }

    /// Wait for a specific message
    pub async fn wait_for_message(
        &self,
        session_id: &str,
        round: u32,
        from: Option<usize>,
        to: Option<usize>,
        tag: &str,
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>> {
        let start = std::time::Instant::now();
        let poll_interval = std::time::Duration::from_millis(100);

        loop {
            let messages = self.get_messages(session_id, round, to).await?;

            for msg in messages {
                if msg.id.round == round
                    && msg.id.from == from
                    && msg.id.to == to
                    && msg.id.tag == tag
                {
                    return msg.decode_payload();
                }
            }

            if start.elapsed() > timeout {
                return Err(RelayError::MessageNotFound(format!(
                    "Timeout waiting for message: round={}, from={:?}, to={:?}, tag={}",
                    round, from, to, tag
                )));
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    // ========================================================================
    // Signature Collection
    // ========================================================================

    /// Submit a partial signature
    pub async fn submit_signature(
        &self,
        session_id: &str,
        party_id: usize,
        role: PartyRole,
        signature_data: &[u8],
    ) -> Result<SigningSession> {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let url = format!("{}/v1/sessions/{}/signatures", self.config.url, session_id);

        let response: ApiResponse<SigningSession> = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "party_id": party_id,
                "role": role,
                "signature_data": STANDARD.encode(signature_data),
            }))
            .send()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?;

        response.into_result()
    }

    /// Complete a session with the final signature
    pub async fn complete_session(
        &self,
        session_id: &str,
        signature: &[u8],
    ) -> Result<SigningSession> {
        let url = format!("{}/v1/sessions/{}/complete", self.config.url, session_id);

        let response: ApiResponse<SigningSession> = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "signature": hex::encode(signature),
            }))
            .send()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?;

        response.into_result()
    }

    // ========================================================================
    // WebSocket
    // ========================================================================

    /// Connect to WebSocket for real-time updates
    pub async fn connect_websocket(&self) -> Result<()> {
        let ws_url = format!("{}/v1/ws", self.config.get_ws_url());

        let (ws_stream, _) = connect_async(&ws_url)
            .await
            .map_err(|e| RelayError::Network(format!("WebSocket connection failed: {}", e)))?;

        info!(url = %ws_url, "Connected to relay WebSocket");

        *self.ws_connected.write().await = true;

        let event_tx = self.event_tx.clone();
        let ws_connected = Arc::clone(&self.ws_connected);

        let (_write, mut read) = ws_stream.split();

        // Spawn read task
        tokio::spawn(async move {
            while let Some(msg) = read.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        if let Ok(event) = serde_json::from_str::<SessionEvent>(&text) {
                            let _ = event_tx.send(event);
                        }
                    }
                    Ok(Message::Close(_)) => {
                        info!("WebSocket closed by server");
                        break;
                    }
                    Ok(Message::Ping(_)) => {
                        debug!("Received ping");
                    }
                    Err(e) => {
                        error!(error = %e, "WebSocket error");
                        break;
                    }
                    _ => {}
                }
            }

            *ws_connected.write().await = false;
            info!("WebSocket disconnected");
        });

        Ok(())
    }

    /// Connect to session-specific WebSocket
    pub async fn connect_session_websocket(&self, session_id: &str) -> Result<()> {
        let ws_url = format!(
            "{}/v1/sessions/{}/stream",
            self.config.get_ws_url(),
            session_id
        );

        let (ws_stream, _) = connect_async(&ws_url)
            .await
            .map_err(|e| RelayError::Network(format!("WebSocket connection failed: {}", e)))?;

        info!(url = %ws_url, session_id, "Connected to session WebSocket");

        let event_tx = self.event_tx.clone();

        let (_write, mut read) = ws_stream.split();

        // Spawn read task
        tokio::spawn(async move {
            while let Some(msg) = read.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        // First message is the full session state
                        if let Ok(event) = serde_json::from_str::<SessionEvent>(&text) {
                            let _ = event_tx.send(event);
                        }
                    }
                    Ok(Message::Close(_)) => {
                        info!("Session WebSocket closed");
                        break;
                    }
                    Err(e) => {
                        error!(error = %e, "Session WebSocket error");
                        break;
                    }
                    _ => {}
                }
            }
        });

        Ok(())
    }

    // ========================================================================
    // Health & Stats
    // ========================================================================

    /// Check service health
    pub async fn health(&self) -> Result<HealthInfo> {
        let url = format!("{}/health", self.config.url);

        let response: ApiResponse<HealthInfo> = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| RelayError::Network(e.to_string()))?;

        response.into_result()
    }
}

/// Relay message structure
#[derive(Debug, Clone, Deserialize)]
pub struct RelayMessage {
    pub id: MessageId,
    pub payload: String, // base64 encoded
    pub created_at: String,
}

impl RelayMessage {
    /// Decode the payload from base64
    pub fn decode_payload(&self) -> Result<Vec<u8>> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        STANDARD
            .decode(&self.payload)
            .map_err(|e| RelayError::InvalidMessageFormat(e.to_string()))
    }
}

/// Health information
#[derive(Debug, Clone, Deserialize)]
pub struct HealthInfo {
    pub status: String,
    pub service: String,
    pub version: String,
    pub uptime_secs: u64,
    pub active_sessions: usize,
    pub pending_approvals: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config() {
        let config =
            RelayClientConfig::new("http://localhost:8080").with_ws_url("ws://localhost:8080");

        assert_eq!(config.url, "http://localhost:8080");
        assert_eq!(config.get_ws_url(), "ws://localhost:8080");
    }

    #[test]
    fn test_ws_url_derivation() {
        let config = RelayClientConfig::new("https://relay.example.com");
        assert_eq!(config.get_ws_url(), "wss://relay.example.com");

        let config = RelayClientConfig::new("http://localhost:8080");
        assert_eq!(config.get_ws_url(), "ws://localhost:8080");
    }
}
