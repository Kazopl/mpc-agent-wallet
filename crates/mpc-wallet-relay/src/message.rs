//! Message relay functionality for MPC communication
//!
//! Provides message storage and routing for MPC protocol execution.

use crate::{RelayError, Result, SessionId};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Message identifier
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct MessageId {
    /// Session identifier
    pub session_id: SessionId,
    /// Round number
    pub round: u32,
    /// Sender party ID (None for broadcasts)
    pub from: Option<usize>,
    /// Receiver party ID (None for broadcasts)
    pub to: Option<usize>,
    /// Message tag
    pub tag: String,
}

impl MessageId {
    /// Create a new message ID
    pub fn new(
        session_id: impl Into<SessionId>,
        round: u32,
        from: Option<usize>,
        to: Option<usize>,
        tag: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            round,
            from,
            to,
            tag: tag.into(),
        }
    }

    /// Create a broadcast message ID
    pub fn broadcast(
        session_id: impl Into<SessionId>,
        round: u32,
        from: usize,
        tag: impl Into<String>,
    ) -> Self {
        Self::new(session_id, round, Some(from), None, tag)
    }

    /// Create a point-to-point message ID
    pub fn p2p(
        session_id: impl Into<SessionId>,
        round: u32,
        from: usize,
        to: usize,
        tag: impl Into<String>,
    ) -> Self {
        Self::new(session_id, round, Some(from), Some(to), tag)
    }

    /// Compute hash for lookup
    pub fn hash(&self) -> String {
        let data = format!(
            "{}:{}:{}:{}:{}",
            self.session_id,
            self.round,
            self.from.map(|v| v.to_string()).unwrap_or_default(),
            self.to.map(|v| v.to_string()).unwrap_or_default(),
            self.tag
        );
        hex::encode(blake3::hash(data.as_bytes()).as_bytes())
    }

    /// Check if this is a broadcast message
    pub fn is_broadcast(&self) -> bool {
        self.to.is_none()
    }
}

/// Stored message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    /// Message ID
    pub id: MessageId,
    /// Message payload (binary)
    pub payload: Vec<u8>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
}

impl StoredMessage {
    /// Check if the message has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Get payload as base64
    pub fn payload_base64(&self) -> String {
        use base64::{Engine, engine::general_purpose::STANDARD};
        STANDARD.encode(&self.payload)
    }
}

/// Message store configuration
#[derive(Debug, Clone)]
pub struct MessageStoreConfig {
    /// Default TTL in seconds
    pub ttl_secs: i64,
    /// Maximum messages per session
    pub max_messages_per_session: usize,
    /// Cleanup interval in seconds
    pub cleanup_interval_secs: u64,
}

impl Default for MessageStoreConfig {
    fn default() -> Self {
        Self {
            ttl_secs: 3600, // 1 hour
            max_messages_per_session: 1000,
            cleanup_interval_secs: 60,
        }
    }
}

/// Message relay store
#[derive(Clone)]
pub struct MessageStore {
    /// Messages indexed by hash
    messages: Arc<DashMap<String, StoredMessage>>,
    /// Session message counts
    session_counts: Arc<DashMap<SessionId, usize>>,
    /// Configuration
    config: MessageStoreConfig,
}

impl MessageStore {
    /// Create a new message store with default configuration
    pub fn new() -> Self {
        Self::with_config(MessageStoreConfig::default())
    }

    /// Create a new message store with TTL
    pub fn with_ttl(ttl_secs: i64) -> Self {
        Self::with_config(MessageStoreConfig {
            ttl_secs,
            ..Default::default()
        })
    }

    /// Create a new message store with configuration
    pub fn with_config(config: MessageStoreConfig) -> Self {
        Self {
            messages: Arc::new(DashMap::new()),
            session_counts: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Store a message
    pub fn put(&self, id: MessageId, payload: Vec<u8>) -> Result<String> {
        // Check session message limit
        {
            let count = self
                .session_counts
                .entry(id.session_id.clone())
                .or_insert(0);

            if *count >= self.config.max_messages_per_session {
                return Err(RelayError::RateLimited(format!(
                    "Session {} has reached maximum message count",
                    id.session_id
                )));
            }
        }

        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(self.config.ttl_secs);

        let hash = id.hash();
        let message = StoredMessage {
            id: id.clone(),
            payload,
            created_at: now,
            expires_at,
        };

        self.messages.insert(hash.clone(), message);

        // Increment count
        *self.session_counts.entry(id.session_id).or_insert(0) += 1;

        Ok(hash)
    }

    /// Get a message by ID
    pub fn get(&self, id: &MessageId) -> Result<StoredMessage> {
        let hash = id.hash();
        self.get_by_hash(&hash)
    }

    /// Get a message by hash
    pub fn get_by_hash(&self, hash: &str) -> Result<StoredMessage> {
        self.messages
            .get(hash)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| RelayError::MessageNotFound(hash.to_string()))
    }

    /// Check if a message exists
    pub fn exists(&self, id: &MessageId) -> bool {
        self.messages.contains_key(&id.hash())
    }

    /// Wait for a message with timeout
    pub async fn wait_for(
        &self,
        id: &MessageId,
        timeout: std::time::Duration,
    ) -> Result<StoredMessage> {
        let start = std::time::Instant::now();
        let poll_interval = std::time::Duration::from_millis(50);

        loop {
            if let Ok(msg) = self.get(id) {
                return Ok(msg);
            }

            if start.elapsed() > timeout {
                return Err(RelayError::MessageNotFound(format!(
                    "Timeout waiting for message: {:?}",
                    id
                )));
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Get all messages for a session and round
    pub fn get_round_messages(&self, session_id: &str, round: u32) -> Vec<StoredMessage> {
        self.messages
            .iter()
            .filter(|entry| {
                entry.id.session_id == session_id && entry.id.round == round && !entry.is_expired()
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get all messages for a recipient in a round
    pub fn get_messages_for_party(
        &self,
        session_id: &str,
        round: u32,
        party_id: usize,
    ) -> Vec<StoredMessage> {
        self.messages
            .iter()
            .filter(|entry| {
                entry.id.session_id == session_id
                    && entry.id.round == round
                    && !entry.is_expired()
                    && (entry.id.to.is_none() || entry.id.to == Some(party_id))
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Remove expired messages
    pub fn cleanup(&self) {
        let now = Utc::now();
        let mut removed_by_session: std::collections::HashMap<SessionId, usize> =
            std::collections::HashMap::new();

        self.messages.retain(|_, msg| {
            let keep = msg.expires_at > now;
            if !keep {
                *removed_by_session
                    .entry(msg.id.session_id.clone())
                    .or_insert(0) += 1;
            }
            keep
        });

        // Update session counts
        for (session_id, removed) in removed_by_session {
            if let Some(mut count) = self.session_counts.get_mut(&session_id) {
                *count = count.saturating_sub(removed);
            }
        }

        // Remove empty session counters
        self.session_counts.retain(|_, count| *count > 0);
    }

    /// Delete all messages for a session
    pub fn delete_session(&self, session_id: &str) {
        self.messages
            .retain(|_, msg| msg.id.session_id != session_id);
        self.session_counts.remove(session_id);
    }

    /// Get message count
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Check if store is empty
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.session_counts.len()
    }
}

impl Default for MessageStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_id_hash() {
        let id1 = MessageId::new("session1", 1, Some(0), Some(1), "keygen");
        let id2 = MessageId::new("session1", 1, Some(0), Some(1), "keygen");
        let id3 = MessageId::new("session1", 2, Some(0), Some(1), "keygen");

        assert_eq!(id1.hash(), id2.hash());
        assert_ne!(id1.hash(), id3.hash());
    }

    #[test]
    fn test_message_store_basic() {
        let store = MessageStore::new();
        let id = MessageId::broadcast("session1", 1, 0, "commit");

        let hash = store.put(id.clone(), vec![1, 2, 3]).unwrap();

        assert!(store.exists(&id));
        let msg = store.get(&id).unwrap();
        assert_eq!(msg.payload, vec![1, 2, 3]);
        assert_eq!(store.get_by_hash(&hash).unwrap().payload, vec![1, 2, 3]);
    }

    #[test]
    fn test_broadcast_vs_p2p() {
        let broadcast = MessageId::broadcast("s1", 1, 0, "data");
        let p2p = MessageId::p2p("s1", 1, 0, 1, "data");

        assert!(broadcast.is_broadcast());
        assert!(!p2p.is_broadcast());
    }

    #[test]
    fn test_get_messages_for_party() {
        let store = MessageStore::new();

        // Broadcast from party 0
        store
            .put(MessageId::broadcast("s1", 1, 0, "bc"), vec![1])
            .unwrap();

        // P2P from party 0 to party 1
        store
            .put(MessageId::p2p("s1", 1, 0, 1, "p2p"), vec![2])
            .unwrap();

        // P2P from party 0 to party 2
        store
            .put(MessageId::p2p("s1", 1, 0, 2, "p2p"), vec![3])
            .unwrap();

        // Party 1 should see broadcast + p2p to self
        let msgs_for_1 = store.get_messages_for_party("s1", 1, 1);
        assert_eq!(msgs_for_1.len(), 2);

        // Party 2 should see broadcast + p2p to self
        let msgs_for_2 = store.get_messages_for_party("s1", 1, 2);
        assert_eq!(msgs_for_2.len(), 2);
    }

    #[test]
    fn test_cleanup() {
        let config = MessageStoreConfig {
            ttl_secs: -1, // Already expired
            ..Default::default()
        };
        let store = MessageStore::with_config(config);

        let id = MessageId::broadcast("s1", 1, 0, "data");
        store.put(id.clone(), vec![1]).unwrap();

        assert_eq!(store.len(), 1);
        store.cleanup();
        assert_eq!(store.len(), 0);
    }
}
