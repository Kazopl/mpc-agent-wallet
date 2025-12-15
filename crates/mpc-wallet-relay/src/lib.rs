//! # MPC Wallet Relay Service
//!
//! Message relay service for coordinating MPC protocol execution and transaction
//! approval flows between AI agents, users, and recovery guardians.
//!
//! ## Features
//!
//! - **Session Management**: Create and track signing sessions
//! - **Approval Flows**: Handle transaction approval requests with multiple UX patterns
//! - **Webhook Notifications**: Push notifications to external services
//! - **WebSocket Streaming**: Real-time updates for approval status
//! - **Message Relay**: Route MPC protocol messages between parties
//!
//! ## Approval Flow
//!
//! ```text
//! AI Agent ──► Relay ──► User Device
//!    │           │           │
//!    │           │           ▼
//!    │           │       Approve/Reject
//!    │           │           │
//!    │           ◄───────────┘
//!    │           │
//!    ◄───────────┘
//!    │
//!    ▼
//! Sign & Broadcast
//! ```
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use mpc_wallet_relay::{WalletRelayService, RelayConfig, WebhookConfig};
//!
//! // Create relay service with configuration
//! let config = RelayConfig::default()
//!     .with_base_url("https://relay.example.com")
//!     .with_request_timeout(60);
//!
//! let relay = WalletRelayService::new(config);
//!
//! // Add webhook for notifications
//! relay.add_webhook(WebhookConfig::new("https://notify.example.com/webhook")).await;
//!
//! // Start server with graceful shutdown support
//! relay.serve("0.0.0.0:8080".parse()?).await?;
//! ```

pub mod approval;
pub mod error;
pub mod message;
pub mod notification;
pub mod session;
pub mod types;
pub mod webhook;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub mod client;

pub use approval::{ApprovalRequest, ApprovalResponse, ApprovalStatus};
pub use error::{RelayError, Result};
pub use message::{MessageId, MessageStore, StoredMessage};
pub use notification::{
    Notification, NotificationChannel, NotificationPriority, NotificationResult,
    NotificationService, NotificationTarget, PollingChannel, QrCodeChannel,
};
pub use session::{SessionManager, SessionStatus, SigningSession};
pub use types::*;
pub use webhook::{WebhookConfig, WebhookService};

#[cfg(feature = "server")]
pub use server::{RelayConfig, WalletRelayService};

#[cfg(feature = "client")]
pub use client::RelayClient;

/// Re-export core types for convenience
pub use mpc_wallet_core::{ChainType, PartyRole, PolicyDecision, TransactionRequest};
