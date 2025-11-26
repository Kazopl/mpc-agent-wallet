//! WASM bindings for key share storage
//!
//! Provides interfaces for storing encrypted key shares in browser storage
//! (IndexedDB, localStorage) or Node.js environments.

use crate::keygen::KeyShare;
use crate::types::PartyRole;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Current backup format version
pub const BACKUP_VERSION: u32 = 1;

/// Storage interface for key shares
///
/// This provides a common interface for different storage backends.
/// In browsers, this would typically use IndexedDB or localStorage.
/// In Node.js, this would use the file system.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredShare {
    /// Share identifier
    pub id: String,
    /// Party role
    pub role: PartyRole,
    /// Public key (hex)
    #[wasm_bindgen(js_name = publicKey)]
    pub public_key: String,
    /// Ethereum address
    #[wasm_bindgen(js_name = ethAddress)]
    pub eth_address: String,
    /// Encrypted share data (JSON)
    #[wasm_bindgen(js_name = encryptedData)]
    pub encrypted_data: String,
    /// Creation timestamp
    #[wasm_bindgen(js_name = createdAt)]
    pub created_at: i64,
    /// Last accessed timestamp
    #[wasm_bindgen(js_name = lastAccessedAt)]
    pub last_accessed_at: i64,
    /// Optional label
    pub label: Option<String>,
}

#[wasm_bindgen]
impl StoredShare {
    /// Create from a KeyShare
    #[wasm_bindgen(js_name = fromKeyShare)]
    pub fn from_key_share(share: &KeyShare, id: String) -> Result<StoredShare, JsValue> {
        let now = chrono::Utc::now().timestamp();
        let encrypted_data = share.to_json()?;

        Ok(StoredShare {
            id,
            role: share.role(),
            public_key: share.public_key(),
            eth_address: share.eth_address(),
            encrypted_data,
            created_at: now,
            last_accessed_at: now,
            label: None,
        })
    }

    /// Set label
    #[wasm_bindgen(js_name = withLabel)]
    pub fn with_label(mut self, label: String) -> Self {
        self.label = Some(label);
        self
    }

    /// Get the KeyShare (decrypted version stored in encrypted_data)
    #[wasm_bindgen(js_name = getKeyShare)]
    pub fn get_key_share(&self) -> Result<KeyShare, JsValue> {
        KeyShare::from_json(&self.encrypted_data)
    }

    /// Update last accessed timestamp
    #[wasm_bindgen(js_name = touch)]
    pub fn touch(&mut self) {
        self.last_accessed_at = chrono::Utc::now().timestamp();
    }

    /// Convert to JSON for storage
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Create from JSON
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(json: &str) -> Result<StoredShare, JsValue> {
        serde_json::from_str(json).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

/// In-memory storage for key shares (for testing or temporary use)
#[wasm_bindgen]
pub struct MemoryStore {
    shares: std::collections::HashMap<String, StoredShare>,
}

#[wasm_bindgen]
impl MemoryStore {
    /// Create a new memory store
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            shares: std::collections::HashMap::new(),
        }
    }

    /// Store a share
    #[wasm_bindgen]
    pub fn store(&mut self, share: &StoredShare) -> Result<(), JsValue> {
        self.shares.insert(share.id.clone(), share.clone());
        Ok(())
    }

    /// Load a share by ID
    #[wasm_bindgen]
    pub fn load(&self, id: &str) -> Result<StoredShare, JsValue> {
        self.shares
            .get(id)
            .cloned()
            .ok_or_else(|| JsValue::from_str(&format!("Share not found: {}", id)))
    }

    /// Delete a share
    #[wasm_bindgen]
    pub fn delete(&mut self, id: &str) -> bool {
        self.shares.remove(id).is_some()
    }

    /// Check if a share exists
    #[wasm_bindgen]
    pub fn exists(&self, id: &str) -> bool {
        self.shares.contains_key(id)
    }

    /// List all share IDs
    #[wasm_bindgen]
    pub fn list(&self) -> Vec<String> {
        self.shares.keys().cloned().collect()
    }

    /// Get count of stored shares
    #[wasm_bindgen]
    pub fn count(&self) -> usize {
        self.shares.len()
    }

    /// Clear all shares
    #[wasm_bindgen]
    pub fn clear(&mut self) {
        self.shares.clear();
    }

    /// Export all shares as JSON
    #[wasm_bindgen(js_name = exportAll)]
    pub fn export_all(&self) -> Result<String, JsValue> {
        let shares: Vec<&StoredShare> = self.shares.values().collect();
        serde_json::to_string(&shares).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Import shares from JSON
    #[wasm_bindgen(js_name = importAll)]
    pub fn import_all(&mut self, json: &str) -> Result<usize, JsValue> {
        let shares: Vec<StoredShare> =
            serde_json::from_str(json).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let count = shares.len();
        for share in shares {
            self.shares.insert(share.id.clone(), share);
        }

        Ok(count)
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Storage key helper for browser localStorage
#[wasm_bindgen]
pub struct StorageKey;

#[wasm_bindgen]
impl StorageKey {
    /// Get the storage key for a share ID
    #[wasm_bindgen(js_name = forShare)]
    pub fn for_share(id: &str) -> String {
        format!("mpc-wallet:share:{}", id)
    }

    /// Get the storage key for share index
    #[wasm_bindgen(js_name = forIndex)]
    pub fn for_index() -> String {
        "mpc-wallet:index".to_string()
    }

    /// Get the storage key for policy config
    #[wasm_bindgen(js_name = forPolicy)]
    pub fn for_policy() -> String {
        "mpc-wallet:policy".to_string()
    }

    /// Get the storage key for active share
    #[wasm_bindgen(js_name = forActiveShare)]
    pub fn for_active_share() -> String {
        "mpc-wallet:active-share".to_string()
    }

    /// Parse a share ID from a storage key
    #[wasm_bindgen(js_name = parseShareId)]
    pub fn parse_share_id(key: &str) -> Option<String> {
        key.strip_prefix("mpc-wallet:share:").map(String::from)
    }
}

/// Backup format for exporting shares
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupData {
    /// Version of the backup format
    pub version: u32,
    /// Timestamp of backup creation
    #[wasm_bindgen(js_name = createdAt)]
    pub created_at: i64,
    /// Number of shares
    #[wasm_bindgen(js_name = shareCount)]
    pub share_count: usize,
    /// Encrypted backup data (contains all shares)
    #[wasm_bindgen(js_name = encryptedData)]
    pub encrypted_data: String,
    /// Checksum for integrity verification
    pub checksum: String,
}

#[wasm_bindgen]
impl BackupData {
    /// Create a backup from shares
    #[wasm_bindgen]
    pub fn create(shares_json: &str, password: &str) -> Result<BackupData, JsValue> {
        use base64::Engine;
        use chacha20poly1305::{
            ChaCha20Poly1305, Nonce,
            aead::{Aead, KeyInit},
        };
        use sha2::{Digest, Sha256};

        // Derive key from password
        let salt: [u8; 32] = rand::random();
        let mut key = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(&salt);
        let hash = hasher.finalize();
        key.copy_from_slice(&hash);

        // Encrypt the shares
        let cipher = ChaCha20Poly1305::new(&key.into());
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, shares_json.as_bytes())
            .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;

        // Combine salt + nonce + ciphertext
        let mut encrypted = Vec::new();
        encrypted.extend_from_slice(&salt);
        encrypted.extend_from_slice(&nonce_bytes);
        encrypted.extend_from_slice(&ciphertext);

        // Compute checksum
        let mut checksum_hasher = Sha256::new();
        checksum_hasher.update(&encrypted);
        let checksum = hex::encode(checksum_hasher.finalize());

        // Count shares
        let shares: Vec<serde_json::Value> =
            serde_json::from_str(shares_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(BackupData {
            version: BACKUP_VERSION,
            created_at: chrono::Utc::now().timestamp(),
            share_count: shares.len(),
            encrypted_data: base64::engine::general_purpose::STANDARD.encode(&encrypted),
            checksum,
        })
    }

    /// Restore shares from backup
    #[wasm_bindgen]
    pub fn restore(&self, password: &str) -> Result<String, JsValue> {
        use base64::Engine;
        use chacha20poly1305::{
            ChaCha20Poly1305, Nonce,
            aead::{Aead, KeyInit},
        };
        use sha2::{Digest, Sha256};

        // Decode encrypted data
        let encrypted = base64::engine::general_purpose::STANDARD
            .decode(&self.encrypted_data)
            .map_err(|e| JsValue::from_str(&format!("Invalid backup data: {}", e)))?;

        // Verify checksum
        let mut checksum_hasher = Sha256::new();
        checksum_hasher.update(&encrypted);
        let computed_checksum = hex::encode(checksum_hasher.finalize());
        if computed_checksum != self.checksum {
            return Err(JsValue::from_str("Backup checksum mismatch"));
        }

        if encrypted.len() < 44 {
            return Err(JsValue::from_str("Invalid backup data length"));
        }

        // Extract salt, nonce, and ciphertext
        let salt: [u8; 32] = encrypted[..32].try_into().unwrap();
        let nonce_bytes: [u8; 12] = encrypted[32..44].try_into().unwrap();
        let ciphertext = &encrypted[44..];

        // Derive key from password
        let mut key = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(&salt);
        let hash = hasher.finalize();
        key.copy_from_slice(&hash);

        // Decrypt
        let cipher = ChaCha20Poly1305::new(&key.into());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| JsValue::from_str("Decryption failed - wrong password?"))?;

        String::from_utf8(plaintext)
            .map_err(|e| JsValue::from_str(&format!("Invalid backup content: {}", e)))
    }

    /// Convert to JSON
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Create from JSON
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(json: &str) -> Result<BackupData, JsValue> {
        serde_json::from_str(json).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Verify the backup checksum without decrypting
    #[wasm_bindgen(js_name = verifyChecksum)]
    pub fn verify_checksum(&self) -> Result<bool, JsValue> {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let encrypted = base64::engine::general_purpose::STANDARD
            .decode(&self.encrypted_data)
            .map_err(|e| JsValue::from_str(&format!("Invalid backup data: {}", e)))?;

        let mut hasher = Sha256::new();
        hasher.update(&encrypted);
        let computed_checksum = hex::encode(hasher.finalize());

        Ok(computed_checksum == self.checksum)
    }

    /// Get the backup version
    #[wasm_bindgen(js_name = getVersion)]
    pub fn get_version() -> u32 {
        BACKUP_VERSION
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_memory_store() {
        let mut store = MemoryStore::new();

        // Create a mock stored share
        let share = StoredShare {
            id: "test-share".to_string(),
            role: PartyRole::Agent,
            public_key: "0x02".to_string() + &"ab".repeat(32),
            eth_address: "0x".to_string() + &"12".repeat(20),
            encrypted_data: "{}".to_string(),
            created_at: 0,
            last_accessed_at: 0,
            label: None,
        };

        // Store
        store.store(&share).unwrap();
        assert!(store.exists("test-share"));
        assert_eq!(store.count(), 1);

        // Load
        let loaded = store.load("test-share").unwrap();
        assert_eq!(loaded.id, "test-share");

        // List
        let list = store.list();
        assert_eq!(list, vec!["test-share"]);

        // Delete
        assert!(store.delete("test-share"));
        assert!(!store.exists("test-share"));
    }

    #[wasm_bindgen_test]
    fn test_storage_keys() {
        let share_key = StorageKey::for_share("my-share");
        assert_eq!(share_key, "mpc-wallet:share:my-share");

        let parsed = StorageKey::parse_share_id(&share_key);
        assert_eq!(parsed, Some("my-share".to_string()));

        let index_key = StorageKey::for_index();
        assert_eq!(index_key, "mpc-wallet:index");
    }

    #[wasm_bindgen_test]
    fn test_backup_round_trip() {
        let shares_json = r#"[{"id": "test", "data": "secret"}]"#;
        let password = "test-password";

        let backup = BackupData::create(shares_json, password).unwrap();

        assert_eq!(backup.version, BACKUP_VERSION);
        assert_eq!(backup.share_count, 1);
        assert!(backup.verify_checksum().unwrap());

        let restored = backup.restore(password).unwrap();
        assert_eq!(restored, shares_json);
    }

    #[wasm_bindgen_test]
    fn test_backup_wrong_password() {
        let shares_json = r#"[{"id": "test"}]"#;
        let password = "correct-password";

        let backup = BackupData::create(shares_json, password).unwrap();

        let result = backup.restore("wrong-password");
        assert!(result.is_err());
    }
}
