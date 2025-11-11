//! Key Share Storage Interface
//!
//! This module provides abstractions for secure storage of MPC key shares.
//! Key shares are always stored encrypted, with multiple backend options:
//!
//! - **FileSystemStore**: Local encrypted files (development/testing)
//! - **EncryptedMemoryStore**: In-memory with encryption (testing)
//!
//! ## Security Considerations
//!
//! - Key shares are encrypted using ChaCha20-Poly1305 before storage
//! - Encryption keys should be derived from user passwords or hardware security modules
//! - The storage interface is async to support remote backends (cloud, TEE)
//!
//! ## Example
//!
//! ```rust,ignore
//! use mpc_wallet_core::storage::{FileSystemStore, KeyShareStore};
//!
//! // Create a file system store
//! let store = FileSystemStore::new("/path/to/shares", encryption_key)?;
//!
//! // Store a key share
//! store.store("my-wallet", &encrypted_share).await?;
//!
//! // Load a key share
//! let share = store.load("my-wallet").await?;
//! ```

use crate::{AgentKeyShare, Error, PartyRole, Result};
use async_trait::async_trait;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Encrypted key share with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeyShare {
    /// Encrypted share data
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption (12 bytes)
    pub nonce: [u8; 12],
    /// Key derivation salt (32 bytes)
    pub salt: [u8; 32],
    /// Role of the party
    pub role: PartyRole,
    /// Public key (not encrypted)
    pub public_key: Vec<u8>,
    /// Ethereum address
    pub eth_address: String,
    /// Creation timestamp
    pub created_at: i64,
    /// Version for future compatibility
    pub version: u32,
}

impl EncryptedKeyShare {
    /// Current version of the encrypted share format
    pub const CURRENT_VERSION: u32 = 1;

    /// Encrypt a key share using the provided key
    pub fn encrypt(share: &AgentKeyShare, encryption_key: &[u8; 32]) -> Result<Self> {
        let cipher = ChaCha20Poly1305::new(encryption_key.into());

        // Generate random nonce and salt
        let nonce_bytes: [u8; 12] = rand::random();
        let salt: [u8; 32] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Serialize and encrypt the share
        let plaintext =
            serde_json::to_vec(share).map_err(|e| Error::Serialization(e.to_string()))?;

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| Error::Encryption(e.to_string()))?;

        let eth_address = share.eth_address().unwrap_or_default();

        Ok(Self {
            ciphertext,
            nonce: nonce_bytes,
            salt,
            role: share.role,
            public_key: share.public_key.clone(),
            eth_address,
            created_at: chrono::Utc::now().timestamp(),
            version: Self::CURRENT_VERSION,
        })
    }

    /// Decrypt the key share using the provided key
    pub fn decrypt(&self, encryption_key: &[u8; 32]) -> Result<AgentKeyShare> {
        let cipher = ChaCha20Poly1305::new(encryption_key.into());
        let nonce = Nonce::from_slice(&self.nonce);

        let plaintext = cipher
            .decrypt(nonce, self.ciphertext.as_ref())
            .map_err(|_| {
                Error::Encryption("Decryption failed - invalid key or corrupted data".into())
            })?;

        let share: AgentKeyShare = serde_json::from_slice(&plaintext)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        Ok(share)
    }
}

/// Trait for key share storage backends
#[async_trait]
pub trait KeyShareStore: Send + Sync {
    /// Store an encrypted key share
    async fn store(&self, id: &str, share: &EncryptedKeyShare) -> Result<()>;

    /// Load an encrypted key share
    async fn load(&self, id: &str) -> Result<EncryptedKeyShare>;

    /// Delete a key share
    async fn delete(&self, id: &str) -> Result<()>;

    /// Check if a key share exists
    async fn exists(&self, id: &str) -> Result<bool>;

    /// List all stored share IDs
    async fn list(&self) -> Result<Vec<String>>;

    /// Get metadata for a share without decrypting
    async fn get_metadata(&self, id: &str) -> Result<ShareMetadata>;
}

/// Metadata about a stored share (without sensitive data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareMetadata {
    /// Share identifier
    pub id: String,
    /// Role of the party
    pub role: PartyRole,
    /// Public key
    pub public_key: Vec<u8>,
    /// Ethereum address
    pub eth_address: String,
    /// Creation timestamp
    pub created_at: i64,
    /// Storage version
    pub version: u32,
}

/// In-memory store for testing
#[derive(Debug)]
pub struct EncryptedMemoryStore {
    shares: Arc<RwLock<HashMap<String, EncryptedKeyShare>>>,
}

impl EncryptedMemoryStore {
    /// Create a new in-memory store
    pub fn new() -> Self {
        Self {
            shares: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for EncryptedMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyShareStore for EncryptedMemoryStore {
    async fn store(&self, id: &str, share: &EncryptedKeyShare) -> Result<()> {
        let mut shares = self.shares.write().await;
        shares.insert(id.to_string(), share.clone());
        Ok(())
    }

    async fn load(&self, id: &str) -> Result<EncryptedKeyShare> {
        let shares = self.shares.read().await;
        shares
            .get(id)
            .cloned()
            .ok_or_else(|| Error::KeyShareNotFound(id.to_string()))
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let mut shares = self.shares.write().await;
        shares.remove(id);
        Ok(())
    }

    async fn exists(&self, id: &str) -> Result<bool> {
        let shares = self.shares.read().await;
        Ok(shares.contains_key(id))
    }

    async fn list(&self) -> Result<Vec<String>> {
        let shares = self.shares.read().await;
        Ok(shares.keys().cloned().collect())
    }

    async fn get_metadata(&self, id: &str) -> Result<ShareMetadata> {
        let shares = self.shares.read().await;
        let share = shares
            .get(id)
            .ok_or_else(|| Error::KeyShareNotFound(id.to_string()))?;

        Ok(ShareMetadata {
            id: id.to_string(),
            role: share.role,
            public_key: share.public_key.clone(),
            eth_address: share.eth_address.clone(),
            created_at: share.created_at,
            version: share.version,
        })
    }
}

/// File system store for local storage
#[derive(Debug)]
pub struct FileSystemStore {
    /// Base directory for storing shares
    base_path: PathBuf,
}

impl FileSystemStore {
    /// Create a new file system store
    pub fn new(base_path: impl Into<PathBuf>) -> Result<Self> {
        let base_path = base_path.into();

        // Create directory if it doesn't exist
        if !base_path.exists() {
            std::fs::create_dir_all(&base_path)?;
        }

        Ok(Self { base_path })
    }

    /// Get the file path for a share ID
    fn share_path(&self, id: &str) -> PathBuf {
        // Sanitize ID to prevent path traversal
        let safe_id = id.replace(['/', '\\', '.', '~'], "_");
        self.base_path.join(format!("{}.share", safe_id))
    }
}

#[async_trait]
impl KeyShareStore for FileSystemStore {
    async fn store(&self, id: &str, share: &EncryptedKeyShare) -> Result<()> {
        let path = self.share_path(id);
        let data = serde_json::to_vec_pretty(share)?;

        tokio::fs::write(&path, data).await?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms)?;
        }

        Ok(())
    }

    async fn load(&self, id: &str) -> Result<EncryptedKeyShare> {
        let path = self.share_path(id);

        if !path.exists() {
            return Err(Error::KeyShareNotFound(id.to_string()));
        }

        let data = tokio::fs::read(&path).await?;
        let share: EncryptedKeyShare =
            serde_json::from_slice(&data).map_err(|e| Error::Deserialization(e.to_string()))?;

        Ok(share)
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let path = self.share_path(id);

        if path.exists() {
            // Overwrite with zeros before deleting for security
            let size = tokio::fs::metadata(&path).await?.len() as usize;
            let zeros = vec![0u8; size];
            tokio::fs::write(&path, zeros).await?;
            tokio::fs::remove_file(&path).await?;
        }

        Ok(())
    }

    async fn exists(&self, id: &str) -> Result<bool> {
        let path = self.share_path(id);
        Ok(path.exists())
    }

    async fn list(&self) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.base_path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("share") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    ids.push(stem.to_string());
                }
            }
        }

        Ok(ids)
    }

    async fn get_metadata(&self, id: &str) -> Result<ShareMetadata> {
        let share = self.load(id).await?;

        Ok(ShareMetadata {
            id: id.to_string(),
            role: share.role,
            public_key: share.public_key,
            eth_address: share.eth_address,
            created_at: share.created_at,
            version: share.version,
        })
    }
}

/// Derive an encryption key from a password using Argon2
pub fn derive_key_from_password(password: &str, salt: &[u8; 32]) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};

    // Simple key derivation (in production, use Argon2 or similar)
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);

    // Multiple rounds for basic stretching
    let mut result = hasher.finalize();
    for _ in 0..10000 {
        let mut hasher = Sha256::new();
        hasher.update(&result);
        hasher.update(salt);
        result = hasher.finalize();
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Ok(key)
}

/// Generate a random encryption key
pub fn generate_encryption_key() -> [u8; 32] {
    rand::random()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::KeyShareMetadata;
    use k256::Scalar;
    use std::collections::HashMap;

    fn create_test_share() -> AgentKeyShare {
        AgentKeyShare {
            party_id: 0,
            role: PartyRole::Agent,
            secret_share: Scalar::ONE,
            public_key: vec![0x02; 33],
            public_shares: vec![vec![0x02; 33]; 3],
            chain_code: [0u8; 32],
            metadata: KeyShareMetadata {
                share_id: "test".to_string(),
                role: PartyRole::Agent,
                created_at: 0,
                last_refreshed_at: None,
                addresses: HashMap::new(),
                label: None,
            },
        }
    }

    #[test]
    fn test_encrypt_decrypt() {
        let share = create_test_share();
        let key = generate_encryption_key();

        let encrypted = EncryptedKeyShare::encrypt(&share, &key).unwrap();
        assert!(!encrypted.ciphertext.is_empty());
        assert_eq!(encrypted.role, PartyRole::Agent);

        let decrypted = encrypted.decrypt(&key).unwrap();
        assert_eq!(decrypted.party_id, share.party_id);
        assert_eq!(decrypted.role, share.role);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let share = create_test_share();
        let key1 = generate_encryption_key();
        let key2 = generate_encryption_key();

        let encrypted = EncryptedKeyShare::encrypt(&share, &key1).unwrap();
        let result = encrypted.decrypt(&key2);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_memory_store() {
        let store = EncryptedMemoryStore::new();
        let share = create_test_share();
        let key = generate_encryption_key();

        let encrypted = EncryptedKeyShare::encrypt(&share, &key).unwrap();

        // Store
        store.store("test-id", &encrypted).await.unwrap();

        // Exists
        assert!(store.exists("test-id").await.unwrap());
        assert!(!store.exists("nonexistent").await.unwrap());

        // Load
        let loaded = store.load("test-id").await.unwrap();
        assert_eq!(loaded.role, encrypted.role);

        // List
        let list = store.list().await.unwrap();
        assert_eq!(list, vec!["test-id"]);

        // Metadata
        let metadata = store.get_metadata("test-id").await.unwrap();
        assert_eq!(metadata.role, PartyRole::Agent);

        // Delete
        store.delete("test-id").await.unwrap();
        assert!(!store.exists("test-id").await.unwrap());
    }

    #[test]
    fn test_derive_key_from_password() {
        let password = "test-password";
        let salt: [u8; 32] = rand::random();

        let key1 = derive_key_from_password(password, &salt).unwrap();
        let key2 = derive_key_from_password(password, &salt).unwrap();

        // Same password + salt should produce same key
        assert_eq!(key1, key2);

        // Different password should produce different key
        let key3 = derive_key_from_password("different", &salt).unwrap();
        assert_ne!(key1, key3);
    }

    #[tokio::test]
    async fn test_file_system_store() {
        let temp_dir = std::env::temp_dir().join(format!("mpc-test-{}", rand::random::<u64>()));
        let store = FileSystemStore::new(&temp_dir).unwrap();
        let share = create_test_share();
        let key = generate_encryption_key();

        let encrypted = EncryptedKeyShare::encrypt(&share, &key).unwrap();

        // Store
        store.store("test-file", &encrypted).await.unwrap();

        // Load
        let loaded = store.load("test-file").await.unwrap();
        assert_eq!(loaded.role, encrypted.role);

        // List
        let list = store.list().await.unwrap();
        assert!(list.contains(&"test-file".to_string()));

        // Cleanup
        store.delete("test-file").await.unwrap();
        std::fs::remove_dir_all(&temp_dir).ok();
    }
}
