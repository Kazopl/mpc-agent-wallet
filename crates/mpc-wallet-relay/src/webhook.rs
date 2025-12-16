//! Webhook notification service
//!
//! Sends webhook notifications to external services for approval events.

use crate::{ApprovalRequest, ApprovalStatus, SessionId, SigningSession};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
#[cfg(feature = "client")]
use tracing::{debug, error, warn};

#[cfg(not(feature = "client"))]
use tracing::info;

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL
    pub url: String,
    /// Optional secret for HMAC signature
    pub secret: Option<String>,
    /// Events to subscribe to
    pub events: Vec<WebhookEvent>,
    /// Headers to include
    pub headers: HashMap<String, String>,
    /// Retry configuration
    pub retry_config: RetryConfig,
    /// Whether the webhook is enabled
    pub enabled: bool,
}

impl WebhookConfig {
    /// Create a new webhook config
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            secret: None,
            events: vec![
                WebhookEvent::ApprovalRequested,
                WebhookEvent::ApprovalProcessed,
                WebhookEvent::SessionCompleted,
            ],
            headers: HashMap::new(),
            retry_config: RetryConfig::default(),
            enabled: true,
        }
    }

    /// Set webhook secret for HMAC signing
    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.secret = Some(secret.into());
        self
    }

    /// Set events to subscribe to
    pub fn with_events(mut self, events: Vec<WebhookEvent>) -> Self {
        self.events = events;
        self
    }

    /// Add a header
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Set retry configuration
    pub fn with_retry_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    /// Check if subscribed to event
    pub fn is_subscribed(&self, event: &WebhookEvent) -> bool {
        self.enabled && self.events.contains(event)
    }
}

/// Webhook events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEvent {
    /// New session created
    SessionCreated,
    /// Approval requested
    ApprovalRequested,
    /// Approval processed (approved/rejected)
    ApprovalProcessed,
    /// Approval expired
    ApprovalExpired,
    /// Session signing started
    SessionSigning,
    /// Session completed
    SessionCompleted,
    /// Session failed
    SessionFailed,
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    pub max_attempts: u32,
    /// Initial delay in milliseconds
    pub initial_delay_ms: u64,
    /// Maximum delay in milliseconds
    pub max_delay_ms: u64,
    /// Backoff multiplier
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
        }
    }
}

/// Webhook payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// Event type
    pub event: WebhookEvent,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Session ID
    pub session_id: SessionId,
    /// Wallet address
    pub wallet_address: String,
    /// Event-specific data
    pub data: WebhookData,
}

/// Webhook event data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WebhookData {
    /// Approval request data
    ApprovalRequest {
        approval_id: String,
        approver_role: String,
        transaction_to: String,
        transaction_value: String,
        chain: String,
        expires_at: DateTime<Utc>,
    },
    /// Approval response data
    ApprovalResponse {
        approval_id: String,
        status: ApprovalStatus,
        approver_role: String,
        rejection_reason: Option<String>,
    },
    /// Session status data
    SessionStatus {
        status: String,
        error: Option<String>,
        signature: Option<String>,
    },
}

/// Delivery status for a webhook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryStatus {
    /// Webhook URL
    pub url: String,
    /// Whether delivery succeeded
    pub success: bool,
    /// HTTP status code (if available)
    pub status_code: Option<u16>,
    /// Number of attempts
    pub attempts: u32,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Delivery timestamp
    pub delivered_at: DateTime<Utc>,
}

/// Webhook service for sending notifications
pub struct WebhookService {
    /// Configured webhooks
    webhooks: Arc<RwLock<Vec<WebhookConfig>>>,
    /// HTTP client
    #[cfg(feature = "client")]
    client: reqwest::Client,
    /// Delivery history (for debugging)
    delivery_history: Arc<RwLock<Vec<DeliveryStatus>>>,
    /// Maximum history entries
    max_history: usize,
}

impl WebhookService {
    /// Create a new webhook service
    pub fn new() -> Self {
        Self {
            webhooks: Arc::new(RwLock::new(Vec::new())),
            #[cfg(feature = "client")]
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
            delivery_history: Arc::new(RwLock::new(Vec::new())),
            max_history: 1000,
        }
    }

    /// Add a webhook configuration
    pub async fn add_webhook(&self, config: WebhookConfig) {
        self.webhooks.write().await.push(config);
    }

    /// Remove a webhook by URL
    pub async fn remove_webhook(&self, url: &str) {
        self.webhooks.write().await.retain(|w| w.url != url);
    }

    /// Get all configured webhooks
    pub async fn list_webhooks(&self) -> Vec<WebhookConfig> {
        self.webhooks.read().await.clone()
    }

    /// Notify approval requested
    pub async fn notify_approval_requested(
        &self,
        session: &SigningSession,
        approval: &ApprovalRequest,
    ) {
        let payload = WebhookPayload {
            event: WebhookEvent::ApprovalRequested,
            timestamp: Utc::now(),
            session_id: session.id.clone(),
            wallet_address: session.wallet_address.clone(),
            data: WebhookData::ApprovalRequest {
                approval_id: approval.id.clone(),
                approver_role: format!("{:?}", approval.approver_role),
                transaction_to: approval.transaction.to.clone(),
                transaction_value: approval.transaction.value.clone(),
                chain: format!("{:?}", approval.transaction.chain),
                expires_at: approval.expires_at,
            },
        };

        self.send_event(WebhookEvent::ApprovalRequested, payload)
            .await;
    }

    /// Notify approval processed
    pub async fn notify_approval_processed(&self, session: &SigningSession) {
        if let Some(approval) = &session.approval {
            let payload = WebhookPayload {
                event: WebhookEvent::ApprovalProcessed,
                timestamp: Utc::now(),
                session_id: session.id.clone(),
                wallet_address: session.wallet_address.clone(),
                data: WebhookData::ApprovalResponse {
                    approval_id: approval.id.clone(),
                    status: approval.status,
                    approver_role: format!("{:?}", approval.approver_role),
                    rejection_reason: approval
                        .response
                        .as_ref()
                        .and_then(|r| r.rejection_reason.clone()),
                },
            };

            self.send_event(WebhookEvent::ApprovalProcessed, payload)
                .await;
        }
    }

    /// Notify session completed
    pub async fn notify_session_completed(&self, session: &SigningSession) {
        let payload = WebhookPayload {
            event: WebhookEvent::SessionCompleted,
            timestamp: Utc::now(),
            session_id: session.id.clone(),
            wallet_address: session.wallet_address.clone(),
            data: WebhookData::SessionStatus {
                status: format!("{:?}", session.status),
                error: session.error.clone(),
                signature: session.final_signature.as_ref().map(hex::encode),
            },
        };

        self.send_event(WebhookEvent::SessionCompleted, payload)
            .await;
    }

    /// Notify session failed
    pub async fn notify_session_failed(&self, session: &SigningSession) {
        let payload = WebhookPayload {
            event: WebhookEvent::SessionFailed,
            timestamp: Utc::now(),
            session_id: session.id.clone(),
            wallet_address: session.wallet_address.clone(),
            data: WebhookData::SessionStatus {
                status: format!("{:?}", session.status),
                error: session.error.clone(),
                signature: None,
            },
        };

        self.send_event(WebhookEvent::SessionFailed, payload).await;
    }

    /// Send event to all subscribed webhooks
    async fn send_event(&self, event: WebhookEvent, payload: WebhookPayload) {
        let webhooks = self.webhooks.read().await;
        let subscribed: Vec<_> = webhooks
            .iter()
            .filter(|w| w.is_subscribed(&event))
            .cloned()
            .collect();
        drop(webhooks);

        for webhook in subscribed {
            let payload_clone = payload.clone();
            let service = self.clone();

            // Spawn delivery task
            tokio::spawn(async move {
                service.deliver(&webhook, payload_clone).await;
            });
        }
    }

    /// Deliver payload to a webhook with retries
    #[cfg(feature = "client")]
    async fn deliver(&self, webhook: &WebhookConfig, payload: WebhookPayload) {
        let payload_json = match serde_json::to_string(&payload) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize webhook payload: {}", e);
                return;
            }
        };

        let mut attempt = 0;
        let mut delay_ms = webhook.retry_config.initial_delay_ms;

        loop {
            attempt += 1;

            let mut request = self
                .client
                .post(&webhook.url)
                .header("Content-Type", "application/json")
                .header("X-Webhook-Event", format!("{:?}", payload.event))
                .header("X-Delivery-Attempt", attempt.to_string());

            // Add custom headers
            for (key, value) in &webhook.headers {
                request = request.header(key, value);
            }

            // Add HMAC signature if secret is configured
            if let Some(secret) = &webhook.secret {
                let signature = compute_hmac_signature(secret, &payload_json);
                request = request.header("X-Webhook-Signature", signature);
            }

            let result = request.body(payload_json.clone()).send().await;

            match result {
                Ok(response) => {
                    let status_code = response.status().as_u16();
                    let success = response.status().is_success();

                    self.record_delivery(DeliveryStatus {
                        url: webhook.url.clone(),
                        success,
                        status_code: Some(status_code),
                        attempts: attempt,
                        error: if success {
                            None
                        } else {
                            Some(format!("HTTP {}", status_code))
                        },
                        delivered_at: Utc::now(),
                    })
                    .await;

                    if success {
                        debug!(
                            url = %webhook.url,
                            event = ?payload.event,
                            "Webhook delivered successfully"
                        );
                        return;
                    }

                    warn!(
                        url = %webhook.url,
                        status = status_code,
                        attempt,
                        "Webhook delivery failed"
                    );
                }
                Err(e) => {
                    warn!(
                        url = %webhook.url,
                        error = %e,
                        attempt,
                        "Webhook request failed"
                    );
                }
            }

            // Check if we should retry
            if attempt >= webhook.retry_config.max_attempts {
                error!(
                    url = %webhook.url,
                    event = ?payload.event,
                    attempts = attempt,
                    "Webhook delivery failed after max retries"
                );

                self.record_delivery(DeliveryStatus {
                    url: webhook.url.clone(),
                    success: false,
                    status_code: None,
                    attempts: attempt,
                    error: Some("Max retries exceeded".to_string()),
                    delivered_at: Utc::now(),
                })
                .await;

                return;
            }

            // Wait before retry
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;

            // Exponential backoff
            delay_ms = ((delay_ms as f64 * webhook.retry_config.backoff_multiplier) as u64)
                .min(webhook.retry_config.max_delay_ms);
        }
    }

    /// Deliver (stub for non-client builds)
    #[cfg(not(feature = "client"))]
    async fn deliver(&self, webhook: &WebhookConfig, payload: WebhookPayload) {
        info!(
            url = %webhook.url,
            event = ?payload.event,
            "Webhook delivery (client feature disabled)"
        );
    }

    /// Record delivery status
    #[cfg(feature = "client")]
    async fn record_delivery(&self, status: DeliveryStatus) {
        let mut history = self.delivery_history.write().await;
        history.push(status);

        // Trim history if too long
        if history.len() > self.max_history {
            let excess = history.len() - self.max_history;
            history.drain(0..excess);
        }
    }

    /// Get recent delivery history
    pub async fn get_delivery_history(&self, limit: usize) -> Vec<DeliveryStatus> {
        let history = self.delivery_history.read().await;
        history.iter().rev().take(limit).cloned().collect()
    }

    /// Get delivery statistics
    pub async fn get_stats(&self) -> WebhookStats {
        let history = self.delivery_history.read().await;
        let total = history.len() as u64;
        let successful = history.iter().filter(|d| d.success).count() as u64;

        WebhookStats {
            total_deliveries: total,
            successful_deliveries: successful,
            failed_deliveries: total - successful,
            success_rate: if total > 0 {
                successful as f64 / total as f64
            } else {
                0.0
            },
            webhooks_configured: 0, // Will be set by caller
        }
    }
}

impl Default for WebhookService {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for WebhookService {
    fn clone(&self) -> Self {
        Self {
            webhooks: Arc::clone(&self.webhooks),
            #[cfg(feature = "client")]
            client: self.client.clone(),
            delivery_history: Arc::clone(&self.delivery_history),
            max_history: self.max_history,
        }
    }
}

/// Webhook statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookStats {
    /// Total deliveries attempted
    pub total_deliveries: u64,
    /// Successful deliveries
    pub successful_deliveries: u64,
    /// Failed deliveries
    pub failed_deliveries: u64,
    /// Success rate (0.0 - 1.0)
    pub success_rate: f64,
    /// Number of webhooks configured
    pub webhooks_configured: usize,
}

/// Compute HMAC-SHA256 signature
#[cfg(feature = "client")]
fn compute_hmac_signature(secret: &str, payload: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());
    let result = mac.finalize();

    format!("sha256={}", hex::encode(result.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only HMAC computation
    fn test_compute_hmac_signature(secret: &str, payload: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(payload.as_bytes());
        let result = mac.finalize();

        format!("sha256={}", hex::encode(result.into_bytes()))
    }

    #[test]
    fn test_webhook_config() {
        let config = WebhookConfig::new("https://example.com/webhook")
            .with_secret("my-secret")
            .with_events(vec![WebhookEvent::ApprovalRequested])
            .with_header("X-Custom", "value");

        assert!(config.is_subscribed(&WebhookEvent::ApprovalRequested));
        assert!(!config.is_subscribed(&WebhookEvent::SessionCompleted));
    }

    #[test]
    fn test_hmac_signature() {
        let signature = test_compute_hmac_signature("secret", "payload");
        assert!(signature.starts_with("sha256="));
    }

    #[tokio::test]
    async fn test_webhook_service() {
        let service = WebhookService::new();

        service
            .add_webhook(WebhookConfig::new("https://example.com/hook"))
            .await;

        let webhooks = service.list_webhooks().await;
        assert_eq!(webhooks.len(), 1);

        service.remove_webhook("https://example.com/hook").await;
        let webhooks = service.list_webhooks().await;
        assert!(webhooks.is_empty());
    }
}
