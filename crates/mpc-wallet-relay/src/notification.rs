//! Notification service for approval flows
//!
//! Supports multiple notification channels: push notifications, Telegram,
//! Discord, email, and QR code generation.

use crate::{ApprovalMethod, ApprovalRequest, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[cfg(feature = "client")]
use crate::RelayError;

/// Notification channel trait
#[async_trait]
pub trait NotificationChannel: Send + Sync {
    /// Get channel type
    fn channel_type(&self) -> ApprovalMethod;

    /// Send a notification
    async fn send(&self, notification: &Notification) -> Result<NotificationResult>;

    /// Check if channel is available for a target
    fn is_available_for(&self, target: &NotificationTarget) -> bool;
}

/// Notification to send
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    /// Notification ID
    pub id: String,
    /// Target recipient
    pub target: NotificationTarget,
    /// Notification title
    pub title: String,
    /// Notification body
    pub body: String,
    /// Approval request reference
    pub approval_id: String,
    /// Session ID
    pub session_id: String,
    /// Deep link URL for approval
    pub approval_url: Option<String>,
    /// QR code data (for QR channel)
    pub qr_data: Option<String>,
    /// Priority level
    pub priority: NotificationPriority,
    /// Expiration time
    pub expires_at: DateTime<Utc>,
    /// Additional data
    pub data: HashMap<String, String>,
}

impl Notification {
    /// Create a notification for an approval request
    pub fn from_approval(approval: &ApprovalRequest, target: NotificationTarget) -> Self {
        let title = format!(
            "Transaction Approval Required ({})",
            approval.summary.chain_name
        );

        let body = format!(
            "Approve transfer of {} to {}?\nRequest expires in {} seconds.",
            approval.summary.value,
            shorten_address(&approval.summary.to),
            approval.time_remaining_secs()
        );

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            target,
            title,
            body,
            approval_id: approval.id.clone(),
            session_id: approval.session_id.clone(),
            approval_url: None,
            qr_data: None,
            priority: match approval.summary.risk_level {
                crate::RiskLevel::Critical | crate::RiskLevel::High => NotificationPriority::High,
                _ => NotificationPriority::Normal,
            },
            expires_at: approval.expires_at,
            data: HashMap::new(),
        }
    }

    /// Set approval URL
    pub fn with_approval_url(mut self, url: impl Into<String>) -> Self {
        self.approval_url = Some(url.into());
        self
    }

    /// Set QR data
    pub fn with_qr_data(mut self, data: impl Into<String>) -> Self {
        self.qr_data = Some(data.into());
        self
    }

    /// Add custom data
    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }
}

/// Notification target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationTarget {
    /// User identifier (wallet address or user ID)
    pub user_id: String,
    /// Push notification token
    pub push_token: Option<String>,
    /// Telegram chat ID
    pub telegram_chat_id: Option<String>,
    /// Discord user ID
    pub discord_user_id: Option<String>,
    /// Email address
    pub email: Option<String>,
    /// Preferred channels (in order of preference)
    pub preferred_channels: Vec<ApprovalMethod>,
}

impl NotificationTarget {
    /// Create a new target
    pub fn new(user_id: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            push_token: None,
            telegram_chat_id: None,
            discord_user_id: None,
            email: None,
            preferred_channels: vec![ApprovalMethod::PushNotification, ApprovalMethod::Polling],
        }
    }

    /// Set push token
    pub fn with_push_token(mut self, token: impl Into<String>) -> Self {
        self.push_token = Some(token.into());
        if !self
            .preferred_channels
            .contains(&ApprovalMethod::PushNotification)
        {
            self.preferred_channels
                .insert(0, ApprovalMethod::PushNotification);
        }
        self
    }

    /// Set Telegram chat ID
    pub fn with_telegram(mut self, chat_id: impl Into<String>) -> Self {
        self.telegram_chat_id = Some(chat_id.into());
        if !self.preferred_channels.contains(&ApprovalMethod::Telegram) {
            self.preferred_channels.push(ApprovalMethod::Telegram);
        }
        self
    }

    /// Set Discord user ID
    pub fn with_discord(mut self, user_id: impl Into<String>) -> Self {
        self.discord_user_id = Some(user_id.into());
        if !self.preferred_channels.contains(&ApprovalMethod::Discord) {
            self.preferred_channels.push(ApprovalMethod::Discord);
        }
        self
    }

    /// Set email
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        if !self.preferred_channels.contains(&ApprovalMethod::Email) {
            self.preferred_channels.push(ApprovalMethod::Email);
        }
        self
    }

    /// Get available channels
    pub fn available_channels(&self) -> Vec<ApprovalMethod> {
        let mut channels = Vec::new();

        if self.push_token.is_some() {
            channels.push(ApprovalMethod::PushNotification);
        }
        if self.telegram_chat_id.is_some() {
            channels.push(ApprovalMethod::Telegram);
        }
        if self.discord_user_id.is_some() {
            channels.push(ApprovalMethod::Discord);
        }
        if self.email.is_some() {
            channels.push(ApprovalMethod::Email);
        }

        // Polling and WebSocket are always available
        channels.push(ApprovalMethod::Polling);
        channels.push(ApprovalMethod::WebSocket);
        channels.push(ApprovalMethod::QrCode);

        channels
    }
}

/// Notification priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotificationPriority {
    /// Low priority
    Low,
    /// Normal priority
    Normal,
    /// High priority (critical transactions)
    High,
}

/// Result of sending a notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationResult {
    /// Notification ID
    pub notification_id: String,
    /// Channel used
    pub channel: ApprovalMethod,
    /// Whether sending succeeded
    pub success: bool,
    /// External ID (from push service, etc.)
    pub external_id: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl NotificationResult {
    /// Create a success result
    pub fn success(notification_id: &str, channel: ApprovalMethod) -> Self {
        Self {
            notification_id: notification_id.to_string(),
            channel,
            success: true,
            external_id: None,
            error: None,
            timestamp: Utc::now(),
        }
    }

    /// Create a failure result
    pub fn failure(
        notification_id: &str,
        channel: ApprovalMethod,
        error: impl Into<String>,
    ) -> Self {
        Self {
            notification_id: notification_id.to_string(),
            channel,
            success: false,
            external_id: None,
            error: Some(error.into()),
            timestamp: Utc::now(),
        }
    }

    /// Set external ID
    pub fn with_external_id(mut self, id: impl Into<String>) -> Self {
        self.external_id = Some(id.into());
        self
    }
}

/// Notification service managing multiple channels
pub struct NotificationService {
    /// Registered channels
    channels: Arc<RwLock<HashMap<ApprovalMethod, Arc<dyn NotificationChannel>>>>,
    /// Notification history
    history: Arc<RwLock<Vec<NotificationResult>>>,
    /// Max history size
    max_history: usize,
    /// Base URL for approval links
    base_url: String,
}

impl NotificationService {
    /// Create a new notification service
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(Vec::new())),
            max_history: 1000,
            base_url: base_url.into(),
        }
    }

    /// Register a notification channel
    pub async fn register_channel(&self, channel: Arc<dyn NotificationChannel>) {
        let channel_type = channel.channel_type();
        self.channels.write().await.insert(channel_type, channel);
        info!(channel = ?channel_type, "Registered notification channel");
    }

    /// Send notification for an approval request
    pub async fn notify_approval(
        &self,
        approval: &ApprovalRequest,
        target: NotificationTarget,
    ) -> Vec<NotificationResult> {
        let approval_url = format!("{}/approve/{}", self.base_url, approval.id);

        let qr_data = serde_json::json!({
            "type": "mpc_wallet_approval",
            "approval_id": approval.id,
            "session_id": approval.session_id,
            "expires_at": approval.expires_at.timestamp(),
        })
        .to_string();

        let notification = Notification::from_approval(approval, target.clone())
            .with_approval_url(&approval_url)
            .with_qr_data(&qr_data);

        self.send(&notification, &target).await
    }

    /// Send a notification through available channels
    pub async fn send(
        &self,
        notification: &Notification,
        target: &NotificationTarget,
    ) -> Vec<NotificationResult> {
        let channels = self.channels.read().await;
        let mut results = Vec::new();

        // Try channels in order of preference
        for method in &target.preferred_channels {
            if let Some(channel) = channels.get(method) {
                if channel.is_available_for(target) {
                    match channel.send(notification).await {
                        Ok(result) => {
                            let success = result.success;
                            results.push(result.clone());
                            self.record_result(result).await;

                            if success {
                                debug!(
                                    channel = ?method,
                                    notification_id = %notification.id,
                                    "Notification sent successfully"
                                );
                                // Stop after first successful delivery
                                break;
                            }
                        }
                        Err(e) => {
                            let result = NotificationResult::failure(
                                &notification.id,
                                *method,
                                e.to_string(),
                            );
                            results.push(result.clone());
                            self.record_result(result).await;

                            warn!(
                                channel = ?method,
                                error = %e,
                                "Notification delivery failed"
                            );
                        }
                    }
                }
            }
        }

        if results.iter().all(|r| !r.success) {
            error!(
                notification_id = %notification.id,
                "All notification channels failed"
            );
        }

        results
    }

    /// Record notification result
    async fn record_result(&self, result: NotificationResult) {
        let mut history = self.history.write().await;
        history.push(result);

        if history.len() > self.max_history {
            let excess = history.len() - self.max_history;
            history.drain(0..excess);
        }
    }

    /// Get recent notification history
    pub async fn get_history(&self, limit: usize) -> Vec<NotificationResult> {
        let history = self.history.read().await;
        history.iter().rev().take(limit).cloned().collect()
    }

    /// Get statistics
    pub async fn get_stats(&self) -> NotificationStats {
        let history = self.history.read().await;
        let total = history.len() as u64;
        let successful = history.iter().filter(|r| r.success).count() as u64;

        let mut by_channel: HashMap<ApprovalMethod, (u64, u64)> = HashMap::new();
        for result in history.iter() {
            let entry = by_channel.entry(result.channel).or_insert((0, 0));
            entry.0 += 1;
            if result.success {
                entry.1 += 1;
            }
        }

        NotificationStats {
            total_sent: total,
            successful: successful,
            failed: total - successful,
            success_rate: if total > 0 {
                successful as f64 / total as f64
            } else {
                0.0
            },
            by_channel,
        }
    }
}

/// Notification statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationStats {
    /// Total notifications sent
    pub total_sent: u64,
    /// Successful deliveries
    pub successful: u64,
    /// Failed deliveries
    pub failed: u64,
    /// Success rate
    pub success_rate: f64,
    /// Stats by channel (total, successful)
    pub by_channel: HashMap<ApprovalMethod, (u64, u64)>,
}

// ============================================================================
// Built-in Notification Channels
// ============================================================================

/// Polling notification channel (no-op, user polls for updates)
pub struct PollingChannel;

#[async_trait]
impl NotificationChannel for PollingChannel {
    fn channel_type(&self) -> ApprovalMethod {
        ApprovalMethod::Polling
    }

    async fn send(&self, notification: &Notification) -> Result<NotificationResult> {
        // Polling doesn't actually send anything
        debug!(notification_id = %notification.id, "Polling notification recorded");
        Ok(NotificationResult::success(
            &notification.id,
            ApprovalMethod::Polling,
        ))
    }

    fn is_available_for(&self, _target: &NotificationTarget) -> bool {
        true // Always available
    }
}

/// QR Code notification channel
pub struct QrCodeChannel;

#[async_trait]
impl NotificationChannel for QrCodeChannel {
    fn channel_type(&self) -> ApprovalMethod {
        ApprovalMethod::QrCode
    }

    async fn send(&self, notification: &Notification) -> Result<NotificationResult> {
        // QR code is generated on-demand, just record the notification
        debug!(notification_id = %notification.id, "QR code notification recorded");
        Ok(NotificationResult::success(
            &notification.id,
            ApprovalMethod::QrCode,
        ))
    }

    fn is_available_for(&self, _target: &NotificationTarget) -> bool {
        true // Always available
    }
}

/// Telegram notification channel
#[cfg(feature = "client")]
pub struct TelegramChannel {
    bot_token: String,
    client: reqwest::Client,
}

#[cfg(feature = "client")]
impl TelegramChannel {
    /// Create a new Telegram channel
    pub fn new(bot_token: impl Into<String>) -> Self {
        Self {
            bot_token: bot_token.into(),
            client: reqwest::Client::new(),
        }
    }
}

#[cfg(feature = "client")]
#[async_trait]
impl NotificationChannel for TelegramChannel {
    fn channel_type(&self) -> ApprovalMethod {
        ApprovalMethod::Telegram
    }

    async fn send(&self, notification: &Notification) -> Result<NotificationResult> {
        let chat_id = notification
            .target
            .telegram_chat_id
            .as_ref()
            .ok_or_else(|| RelayError::NotificationError("No Telegram chat ID".to_string()))?;

        let message = format!(
            "*{}*\n\n{}\n\n[Approve]({}) | [Reject]({})",
            notification.title,
            notification.body,
            notification.approval_url.as_deref().unwrap_or("#"),
            notification.approval_url.as_deref().unwrap_or("#"),
        );

        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);

        let response = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "Markdown",
                "disable_web_page_preview": true,
            }))
            .send()
            .await
            .map_err(|e| RelayError::NotificationError(e.to_string()))?;

        if response.status().is_success() {
            let body: serde_json::Value = response
                .json()
                .await
                .map_err(|e| RelayError::NotificationError(e.to_string()))?;

            let message_id = body["result"]["message_id"]
                .as_i64()
                .map(|id| id.to_string());

            Ok(
                NotificationResult::success(&notification.id, ApprovalMethod::Telegram)
                    .with_external_id(message_id.unwrap_or_default()),
            )
        } else {
            Err(RelayError::NotificationError(format!(
                "Telegram API error: {}",
                response.status()
            )))
        }
    }

    fn is_available_for(&self, target: &NotificationTarget) -> bool {
        target.telegram_chat_id.is_some()
    }
}

/// Discord notification channel
#[cfg(feature = "client")]
pub struct DiscordChannel {
    bot_token: String,
    client: reqwest::Client,
}

#[cfg(feature = "client")]
impl DiscordChannel {
    /// Create a new Discord channel
    pub fn new(bot_token: impl Into<String>) -> Self {
        Self {
            bot_token: bot_token.into(),
            client: reqwest::Client::new(),
        }
    }
}

#[cfg(feature = "client")]
#[async_trait]
impl NotificationChannel for DiscordChannel {
    fn channel_type(&self) -> ApprovalMethod {
        ApprovalMethod::Discord
    }

    async fn send(&self, notification: &Notification) -> Result<NotificationResult> {
        let user_id = notification
            .target
            .discord_user_id
            .as_ref()
            .ok_or_else(|| RelayError::NotificationError("No Discord user ID".to_string()))?;

        // First, create a DM channel
        let create_dm_url = "https://discord.com/api/v10/users/@me/channels";
        let dm_response = self
            .client
            .post(create_dm_url)
            .header("Authorization", format!("Bot {}", self.bot_token))
            .json(&serde_json::json!({
                "recipient_id": user_id,
            }))
            .send()
            .await
            .map_err(|e| RelayError::NotificationError(e.to_string()))?;

        if !dm_response.status().is_success() {
            return Err(RelayError::NotificationError(format!(
                "Failed to create DM channel: {}",
                dm_response.status()
            )));
        }

        let dm_channel: serde_json::Value = dm_response
            .json()
            .await
            .map_err(|e| RelayError::NotificationError(e.to_string()))?;

        let channel_id = dm_channel["id"].as_str().ok_or_else(|| {
            RelayError::NotificationError("No channel ID in response".to_string())
        })?;

        // Send message to DM channel
        let send_url = format!(
            "https://discord.com/api/v10/channels/{}/messages",
            channel_id
        );

        let embed = serde_json::json!({
            "title": notification.title,
            "description": notification.body,
            "color": match notification.priority {
                NotificationPriority::High => 0xFF0000,
                NotificationPriority::Normal => 0x0099FF,
                NotificationPriority::Low => 0x00FF00,
            },
            "fields": [
                {
                    "name": "Approval ID",
                    "value": notification.approval_id,
                    "inline": true
                }
            ],
            "timestamp": notification.expires_at.to_rfc3339(),
        });

        let response = self
            .client
            .post(&send_url)
            .header("Authorization", format!("Bot {}", self.bot_token))
            .json(&serde_json::json!({
                "embeds": [embed],
            }))
            .send()
            .await
            .map_err(|e| RelayError::NotificationError(e.to_string()))?;

        if response.status().is_success() {
            let body: serde_json::Value = response
                .json()
                .await
                .map_err(|e| RelayError::NotificationError(e.to_string()))?;

            let message_id = body["id"].as_str().map(|s| s.to_string());

            Ok(
                NotificationResult::success(&notification.id, ApprovalMethod::Discord)
                    .with_external_id(message_id.unwrap_or_default()),
            )
        } else {
            Err(RelayError::NotificationError(format!(
                "Discord API error: {}",
                response.status()
            )))
        }
    }

    fn is_available_for(&self, target: &NotificationTarget) -> bool {
        target.discord_user_id.is_some()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Shorten an address for display
fn shorten_address(address: &str) -> String {
    if address.len() > 12 {
        format!("{}...{}", &address[..6], &address[address.len() - 4..])
    } else {
        address.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_target() {
        let target = NotificationTarget::new("0x1234")
            .with_telegram("12345678")
            .with_discord("discord_user");

        let channels = target.available_channels();
        assert!(channels.contains(&ApprovalMethod::Telegram));
        assert!(channels.contains(&ApprovalMethod::Discord));
        assert!(channels.contains(&ApprovalMethod::Polling));
    }

    #[test]
    fn test_shorten_address() {
        assert_eq!(
            shorten_address("0x1234567890abcdef1234567890abcdef12345678"),
            "0x1234...5678"
        );
        assert_eq!(shorten_address("0x1234"), "0x1234");
    }

    #[tokio::test]
    async fn test_polling_channel() {
        let channel = PollingChannel;
        let notification = Notification {
            id: "test".to_string(),
            target: NotificationTarget::new("user"),
            title: "Test".to_string(),
            body: "Test body".to_string(),
            approval_id: "approval".to_string(),
            session_id: "session".to_string(),
            approval_url: None,
            qr_data: None,
            priority: NotificationPriority::Normal,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            data: HashMap::new(),
        };

        let result = channel.send(&notification).await.unwrap();
        assert!(result.success);
    }
}
