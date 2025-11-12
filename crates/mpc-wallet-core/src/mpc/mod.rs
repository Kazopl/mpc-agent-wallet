//! MPC coordination utilities
//!
//! This module provides the communication infrastructure for MPC protocol execution.
//! The `Relay` trait abstracts message passing between parties, enabling different
//! transport mechanisms (in-memory, WebSocket, REST API).

use crate::{PartyId, Result, SessionId};
use serde::{Serialize, de::DeserializeOwned};

pub use async_trait::async_trait;

pub mod memory;

pub use memory::MemoryRelay;

/// Message relay trait for MPC communication
///
/// Implementations of this trait handle the transport of messages between
/// MPC protocol participants. The relay is responsible for:
/// - Broadcasting messages to all parties
/// - Sending direct (point-to-point) messages
/// - Collecting and delivering messages by round
#[async_trait]
pub trait Relay: Send + Sync {
    /// Broadcast a message to all parties in the session
    ///
    /// # Arguments
    /// * `session_id` - Unique session identifier
    /// * `round` - Protocol round number
    /// * `message` - Message to broadcast (will be serialized)
    async fn broadcast<T: Serialize + Send + Sync>(
        &self,
        session_id: &SessionId,
        round: u32,
        message: &T,
    ) -> Result<()>;

    /// Send a direct message to a specific party
    ///
    /// # Arguments
    /// * `session_id` - Unique session identifier
    /// * `round` - Protocol round number
    /// * `to` - Target party ID
    /// * `message` - Message to send (will be serialized)
    async fn send_direct<T: Serialize + Send + Sync>(
        &self,
        session_id: &SessionId,
        round: u32,
        to: PartyId,
        message: &T,
    ) -> Result<()>;

    /// Collect broadcast messages from all parties for a round
    ///
    /// This method blocks until `count` messages have been received.
    ///
    /// # Arguments
    /// * `session_id` - Unique session identifier
    /// * `round` - Protocol round number
    /// * `count` - Number of messages to collect
    async fn collect_broadcasts<T: DeserializeOwned + Send>(
        &self,
        session_id: &SessionId,
        round: u32,
        count: usize,
    ) -> Result<Vec<T>>;

    /// Collect direct messages sent to this party
    ///
    /// This method blocks until `count` messages have been received.
    ///
    /// # Arguments
    /// * `session_id` - Unique session identifier
    /// * `round` - Protocol round number
    /// * `my_id` - This party's ID
    /// * `count` - Number of messages to collect
    async fn collect_direct<T: DeserializeOwned + Send>(
        &self,
        session_id: &SessionId,
        round: u32,
        my_id: PartyId,
        count: usize,
    ) -> Result<Vec<T>>;
}

/// Extension trait for relay with timeout support
#[async_trait]
pub trait RelayExt: Relay {
    /// Broadcast with timeout
    async fn broadcast_with_timeout<T: Serialize + Send + Sync>(
        &self,
        session_id: &SessionId,
        round: u32,
        message: &T,
        timeout: std::time::Duration,
    ) -> Result<()>;

    /// Collect broadcasts with timeout
    async fn collect_broadcasts_with_timeout<T: DeserializeOwned + Send>(
        &self,
        session_id: &SessionId,
        round: u32,
        count: usize,
        timeout: std::time::Duration,
    ) -> Result<Vec<T>>;
}

#[async_trait]
impl<R: Relay + ?Sized> RelayExt for R {
    async fn broadcast_with_timeout<T: Serialize + Send + Sync>(
        &self,
        session_id: &SessionId,
        round: u32,
        message: &T,
        timeout: std::time::Duration,
    ) -> Result<()> {
        tokio::time::timeout(timeout, self.broadcast(session_id, round, message))
            .await
            .map_err(|_| crate::Error::Timeout("broadcast".to_string()))?
    }

    async fn collect_broadcasts_with_timeout<T: DeserializeOwned + Send>(
        &self,
        session_id: &SessionId,
        round: u32,
        count: usize,
        timeout: std::time::Duration,
    ) -> Result<Vec<T>> {
        tokio::time::timeout(timeout, self.collect_broadcasts(session_id, round, count))
            .await
            .map_err(|_| crate::Error::Timeout("collect_broadcasts".to_string()))?
    }
}
