//! In-memory relay implementation for testing and local development

use super::{Relay, async_trait};
use crate::{Error, PartyId, Result, SessionId};
use dashmap::DashMap;
use serde::{Serialize, de::DeserializeOwned};
use std::sync::Arc;
use tokio::sync::broadcast;

/// In-memory message relay for local testing
///
/// This relay stores all messages in memory and uses channels for notification.
/// It's useful for:
/// - Unit and integration testing
/// - Local development
/// - Single-process multi-party simulation
#[derive(Debug)]
pub struct MemoryRelay {
    /// Broadcast messages: (session_id, round) -> Vec<message_bytes>
    broadcasts: Arc<DashMap<(SessionId, u32), Vec<Vec<u8>>>>,
    /// Direct messages: (session_id, round, to) -> Vec<message_bytes>
    directs: Arc<DashMap<(SessionId, u32, PartyId), Vec<Vec<u8>>>>,
    /// Notification channel for new messages
    notify: broadcast::Sender<()>,
    /// Timeout for waiting on messages (milliseconds)
    timeout_ms: u64,
}

impl MemoryRelay {
    /// Create a new in-memory relay with default timeout
    pub fn new() -> Self {
        Self::with_timeout(30_000) // 30 seconds default
    }

    /// Create a new in-memory relay with custom timeout
    pub fn with_timeout(timeout_ms: u64) -> Self {
        let (notify, _) = broadcast::channel(1000);
        Self {
            broadcasts: Arc::new(DashMap::new()),
            directs: Arc::new(DashMap::new()),
            notify,
            timeout_ms,
        }
    }

    /// Clear all messages (useful for test cleanup)
    pub fn clear(&self) {
        self.broadcasts.clear();
        self.directs.clear();
    }

    /// Get the number of broadcast messages for a session/round
    pub fn broadcast_count(&self, session_id: &SessionId, round: u32) -> usize {
        self.broadcasts
            .get(&(*session_id, round))
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Get the number of direct messages for a party
    pub fn direct_count(&self, session_id: &SessionId, round: u32, to: PartyId) -> usize {
        self.directs
            .get(&(*session_id, round, to))
            .map(|v| v.len())
            .unwrap_or(0)
    }
}

impl Default for MemoryRelay {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MemoryRelay {
    fn clone(&self) -> Self {
        Self {
            broadcasts: Arc::clone(&self.broadcasts),
            directs: Arc::clone(&self.directs),
            notify: self.notify.clone(),
            timeout_ms: self.timeout_ms,
        }
    }
}

fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| Error::Serialization(e.to_string()))
}

fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|e| Error::Deserialization(e.to_string()))
}

#[async_trait]
impl Relay for MemoryRelay {
    async fn broadcast<T: Serialize + Send + Sync>(
        &self,
        session_id: &SessionId,
        round: u32,
        message: &T,
    ) -> Result<()> {
        let bytes = serialize(message)?;

        self.broadcasts
            .entry((*session_id, round))
            .or_default()
            .push(bytes);

        // Notify waiting collectors
        let _ = self.notify.send(());
        Ok(())
    }

    async fn send_direct<T: Serialize + Send + Sync>(
        &self,
        session_id: &SessionId,
        round: u32,
        to: PartyId,
        message: &T,
    ) -> Result<()> {
        let bytes = serialize(message)?;

        self.directs
            .entry((*session_id, round, to))
            .or_default()
            .push(bytes);

        // Notify waiting collectors
        let _ = self.notify.send(());
        Ok(())
    }

    async fn collect_broadcasts<T: DeserializeOwned + Send>(
        &self,
        session_id: &SessionId,
        round: u32,
        count: usize,
    ) -> Result<Vec<T>> {
        let mut rx = self.notify.subscribe();
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(self.timeout_ms);

        loop {
            // Check if we have enough messages
            if let Some(messages) = self.broadcasts.get(&(*session_id, round)) {
                if messages.len() >= count {
                    let result: Result<Vec<T>> = messages
                        .iter()
                        .take(count)
                        .map(|bytes| deserialize(bytes))
                        .collect();
                    return result;
                }
            }

            // Check timeout
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(Error::Timeout(format!(
                    "Waiting for {} broadcast messages in round {}",
                    count, round
                )));
            }

            // Wait for notification or timeout
            tokio::select! {
                _ = rx.recv() => continue,
                _ = tokio::time::sleep(std::time::Duration::from_millis(100).min(remaining)) => continue,
            }
        }
    }

    async fn collect_direct<T: DeserializeOwned + Send>(
        &self,
        session_id: &SessionId,
        round: u32,
        my_id: PartyId,
        count: usize,
    ) -> Result<Vec<T>> {
        let mut rx = self.notify.subscribe();
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(self.timeout_ms);

        loop {
            // Check if we have enough messages
            if let Some(messages) = self.directs.get(&(*session_id, round, my_id)) {
                if messages.len() >= count {
                    let result: Result<Vec<T>> = messages
                        .iter()
                        .take(count)
                        .map(|bytes| deserialize(bytes))
                        .collect();
                    return result;
                }
            }

            // Check timeout
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(Error::Timeout(format!(
                    "Waiting for {} direct messages to party {} in round {}",
                    count, my_id, round
                )));
            }

            // Wait for notification or timeout
            tokio::select! {
                _ = rx.recv() => continue,
                _ = tokio::time::sleep(std::time::Duration::from_millis(100).min(remaining)) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestMessage {
        value: u32,
        data: String,
    }

    #[tokio::test]
    async fn test_broadcast() {
        let relay = MemoryRelay::new();
        let session_id = [0u8; 32];

        relay
            .broadcast(
                &session_id,
                1,
                &TestMessage {
                    value: 42,
                    data: "hello".to_string(),
                },
            )
            .await
            .unwrap();

        relay
            .broadcast(
                &session_id,
                1,
                &TestMessage {
                    value: 43,
                    data: "world".to_string(),
                },
            )
            .await
            .unwrap();

        let messages: Vec<TestMessage> = relay.collect_broadcasts(&session_id, 1, 2).await.unwrap();

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].value, 42);
        assert_eq!(messages[1].value, 43);
    }

    #[tokio::test]
    async fn test_direct() {
        let relay = MemoryRelay::new();
        let session_id = [0u8; 32];

        relay
            .send_direct(
                &session_id,
                1,
                0,
                &TestMessage {
                    value: 100,
                    data: "direct".to_string(),
                },
            )
            .await
            .unwrap();

        let messages: Vec<TestMessage> = relay.collect_direct(&session_id, 1, 0, 1).await.unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].value, 100);
    }

    #[tokio::test]
    async fn test_concurrent_broadcast() {
        let relay = MemoryRelay::new();
        let session_id = [0u8; 32];

        // Spawn multiple broadcasters
        let handles: Vec<_> = (0..3)
            .map(|i| {
                let r = relay.clone();
                let sid = session_id;
                tokio::spawn(async move {
                    r.broadcast(
                        &sid,
                        1,
                        &TestMessage {
                            value: i,
                            data: format!("msg-{}", i),
                        },
                    )
                    .await
                })
            })
            .collect();

        // Wait for all broadcasts
        for h in handles {
            h.await.unwrap().unwrap();
        }

        // Collect all messages
        let messages: Vec<TestMessage> = relay.collect_broadcasts(&session_id, 1, 3).await.unwrap();
        assert_eq!(messages.len(), 3);
    }

    #[tokio::test]
    async fn test_timeout() {
        let relay = MemoryRelay::with_timeout(100); // 100ms timeout
        let session_id = [0u8; 32];

        // Only send 1 message but request 2
        relay
            .broadcast(
                &session_id,
                1,
                &TestMessage {
                    value: 1,
                    data: "only one".to_string(),
                },
            )
            .await
            .unwrap();

        let result: Result<Vec<TestMessage>> = relay.collect_broadcasts(&session_id, 1, 2).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Timeout(_)));
    }

    #[tokio::test]
    async fn test_separate_sessions() {
        let relay = MemoryRelay::new();
        let session1 = [1u8; 32];
        let session2 = [2u8; 32];

        relay
            .broadcast(
                &session1,
                1,
                &TestMessage {
                    value: 1,
                    data: "s1".to_string(),
                },
            )
            .await
            .unwrap();

        relay
            .broadcast(
                &session2,
                1,
                &TestMessage {
                    value: 2,
                    data: "s2".to_string(),
                },
            )
            .await
            .unwrap();

        let msgs1: Vec<TestMessage> = relay.collect_broadcasts(&session1, 1, 1).await.unwrap();
        let msgs2: Vec<TestMessage> = relay.collect_broadcasts(&session2, 1, 1).await.unwrap();

        assert_eq!(msgs1[0].value, 1);
        assert_eq!(msgs2[0].value, 2);
    }

    #[tokio::test]
    async fn test_separate_rounds() {
        let relay = MemoryRelay::new();
        let session_id = [0u8; 32];

        relay
            .broadcast(
                &session_id,
                1,
                &TestMessage {
                    value: 1,
                    data: "r1".to_string(),
                },
            )
            .await
            .unwrap();

        relay
            .broadcast(
                &session_id,
                2,
                &TestMessage {
                    value: 2,
                    data: "r2".to_string(),
                },
            )
            .await
            .unwrap();

        let msgs1: Vec<TestMessage> = relay.collect_broadcasts(&session_id, 1, 1).await.unwrap();
        let msgs2: Vec<TestMessage> = relay.collect_broadcasts(&session_id, 2, 1).await.unwrap();

        assert_eq!(msgs1[0].value, 1);
        assert_eq!(msgs2[0].value, 2);
    }

    #[test]
    fn test_clear() {
        let relay = MemoryRelay::new();
        let session_id = [0u8; 32];

        // Add some messages synchronously using the underlying maps
        relay.broadcasts.insert(
            (session_id, 1),
            vec![
                serde_json::to_vec(&TestMessage {
                    value: 1,
                    data: "test".to_string(),
                })
                .unwrap(),
            ],
        );

        assert_eq!(relay.broadcast_count(&session_id, 1), 1);

        relay.clear();

        assert_eq!(relay.broadcast_count(&session_id, 1), 0);
    }
}
