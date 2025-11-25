//! WASM bindings for key generation

use crate::types::{KeyShareInfo, PartyRole};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Key share for local storage and use
///
/// This is the encrypted representation that can be safely stored.
/// The actual secret share is never exposed to JavaScript.
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    /// Party ID (0=Agent, 1=User, 2=Recovery)
    party_id: u8,
    /// Encrypted share data (base64)
    encrypted_data: String,
    /// Public key (hex)
    public_key: String,
    /// Ethereum address
    eth_address: String,
    /// Chain code for derivation (hex)
    chain_code: String,
    /// Nonce used for encryption (hex)
    nonce: String,
    /// Salt used for key derivation (hex)
    salt: String,
}

#[wasm_bindgen]
impl KeyShare {
    /// Get the party ID
    #[wasm_bindgen(getter, js_name = partyId)]
    pub fn party_id(&self) -> u8 {
        self.party_id
    }

    /// Get the party role
    #[wasm_bindgen(getter)]
    pub fn role(&self) -> PartyRole {
        match self.party_id {
            0 => PartyRole::Agent,
            1 => PartyRole::User,
            _ => PartyRole::Recovery,
        }
    }

    /// Get the public key (hex)
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> String {
        self.public_key.clone()
    }

    /// Get the Ethereum address
    #[wasm_bindgen(getter, js_name = ethAddress)]
    pub fn eth_address(&self) -> String {
        self.eth_address.clone()
    }

    /// Get non-sensitive metadata
    #[wasm_bindgen(js_name = getInfo)]
    pub fn get_info(&self) -> KeyShareInfo {
        KeyShareInfo {
            share_id: format!("share-{}", self.party_id),
            role: self.role(),
            public_key: self.public_key.clone(),
            eth_address: self.eth_address.clone(),
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Export to JSON for storage
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Import from JSON
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(json: &str) -> Result<KeyShare, JsValue> {
        serde_json::from_str(json).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Derive a child key share (non-hardened BIP32)
    #[wasm_bindgen(js_name = deriveChild)]
    pub fn derive_child(&self, _path: &str, _password: &str) -> Result<KeyShare, JsValue> {
        // This would decrypt, derive, and re-encrypt
        // For now, return an error as full implementation requires MPC coordination
        Err(JsValue::from_str(
            "Child derivation requires coordination with other parties",
        ))
    }
}

/// Result of key generation ceremony
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone)]
pub struct KeygenResult {
    /// The generated key share (encrypted)
    share: KeyShare,
    /// Aggregated public key (hex)
    #[wasm_bindgen(js_name = publicKey)]
    pub public_key: String,
    /// Ethereum address
    #[wasm_bindgen(js_name = ethAddress)]
    pub eth_address: String,
}

#[wasm_bindgen]
impl KeygenResult {
    /// Get the key share
    #[wasm_bindgen(getter)]
    pub fn share(&self) -> KeyShare {
        self.share.clone()
    }

    /// Export to JSON
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        #[derive(Serialize)]
        struct Export {
            public_key: String,
            eth_address: String,
            share: String,
        }

        let export = Export {
            public_key: self.public_key.clone(),
            eth_address: self.eth_address.clone(),
            share: self.share.to_json()?,
        };

        serde_json::to_string(&export).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

/// Configuration for key generation
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenConfig {
    /// This party's role
    pub role: PartyRole,
    /// Session ID (32 bytes, hex)
    #[wasm_bindgen(js_name = sessionId)]
    pub session_id: String,
    /// Timeout in seconds
    #[wasm_bindgen(js_name = timeoutSecs)]
    pub timeout_secs: u32,
}

#[wasm_bindgen]
impl KeygenConfig {
    /// Create a new keygen config
    #[wasm_bindgen(constructor)]
    pub fn new(role: PartyRole) -> Self {
        let session_id = hex::encode(rand::random::<[u8; 32]>());
        Self {
            role,
            session_id,
            timeout_secs: 300, // 5 minutes default
        }
    }

    /// Set session ID
    #[wasm_bindgen(js_name = withSessionId)]
    pub fn with_session_id(mut self, session_id: String) -> Self {
        self.session_id = session_id;
        self
    }

    /// Set timeout
    #[wasm_bindgen(js_name = withTimeout)]
    pub fn with_timeout(mut self, timeout_secs: u32) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }
}

/// Message handler for DKG rounds
///
/// This handles the state machine for distributed key generation.
#[wasm_bindgen]
pub struct KeygenSession {
    party_id: u8,
    session_id: Vec<u8>,
    round: u32,
    state: KeygenState,
    // Store intermediate values (in real implementation, these would be MPC state)
    local_secret: Vec<u8>,
    public_shares: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
enum KeygenState {
    Initialized,
    Round1Complete,
    #[allow(dead_code)]
    Round2Complete,
    Complete,
    #[allow(dead_code)]
    Failed(String),
}

#[wasm_bindgen]
impl KeygenSession {
    /// Create a new keygen session
    #[wasm_bindgen(constructor)]
    pub fn new(config: &KeygenConfig) -> Result<KeygenSession, JsValue> {
        let session_id = hex::decode(&config.session_id)
            .map_err(|e| JsValue::from_str(&format!("Invalid session ID: {}", e)))?;

        if session_id.len() != 32 {
            return Err(JsValue::from_str("Session ID must be 32 bytes"));
        }

        Ok(KeygenSession {
            party_id: config.role as u8,
            session_id,
            round: 0,
            state: KeygenState::Initialized,
            local_secret: Vec::new(),
            public_shares: Vec::new(),
        })
    }

    /// Get current round number
    #[wasm_bindgen(getter)]
    pub fn round(&self) -> u32 {
        self.round
    }

    /// Check if keygen is complete
    #[wasm_bindgen(js_name = isComplete)]
    pub fn is_complete(&self) -> bool {
        matches!(self.state, KeygenState::Complete)
    }

    /// Check if keygen failed
    #[wasm_bindgen(js_name = isFailed)]
    pub fn is_failed(&self) -> bool {
        matches!(self.state, KeygenState::Failed(_))
    }

    /// Get failure reason (if any)
    #[wasm_bindgen(js_name = getFailureReason)]
    pub fn get_failure_reason(&self) -> Option<String> {
        match &self.state {
            KeygenState::Failed(reason) => Some(reason.clone()),
            _ => None,
        }
    }

    /// Generate round 1 message
    ///
    /// This creates the commitment message for the first round of DKG.
    #[wasm_bindgen(js_name = generateRound1)]
    pub fn generate_round1(&mut self) -> Result<String, JsValue> {
        if !matches!(self.state, KeygenState::Initialized) {
            return Err(JsValue::from_str("Invalid state for round 1"));
        }

        // Generate local secret (in real implementation, this would be polynomial coefficients)
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        self.local_secret = secret.to_vec();

        // Create commitment (hash of public share)
        let commitment = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&secret);
            hasher.update(&self.session_id);
            hasher.update(&[self.party_id]);
            hasher.finalize().to_vec()
        };

        self.round = 1;

        // Create round 1 message
        let msg = Round1Message {
            party_id: self.party_id,
            session_id: hex::encode(&self.session_id),
            commitment: hex::encode(&commitment),
        };

        serde_json::to_string(&msg).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Process round 1 messages from other parties
    #[wasm_bindgen(js_name = processRound1)]
    pub fn process_round1(&mut self, messages_json: &str) -> Result<(), JsValue> {
        if self.round != 1 {
            return Err(JsValue::from_str("Must be in round 1"));
        }

        let messages: Vec<Round1Message> =
            serde_json::from_str(messages_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

        // Verify we have messages from all other parties
        if messages.len() != 2 {
            return Err(JsValue::from_str("Expected 2 messages from other parties"));
        }

        // Store commitments (in real implementation, these would be verified in round 3)
        self.state = KeygenState::Round1Complete;
        Ok(())
    }

    /// Generate round 2 message
    #[wasm_bindgen(js_name = generateRound2)]
    pub fn generate_round2(&mut self) -> Result<String, JsValue> {
        if !matches!(self.state, KeygenState::Round1Complete) {
            return Err(JsValue::from_str("Invalid state for round 2"));
        }

        // Generate public share from secret
        // In real implementation, this would be EC point multiplication
        let public_share = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"public:");
            hasher.update(&self.local_secret);
            hasher.finalize().to_vec()
        };

        self.round = 2;

        let msg = Round2Message {
            party_id: self.party_id,
            session_id: hex::encode(&self.session_id),
            public_share: hex::encode(&public_share),
        };

        serde_json::to_string(&msg).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Process round 2 messages and complete keygen
    #[wasm_bindgen(js_name = processRound2)]
    pub fn process_round2(
        &mut self,
        messages_json: &str,
        password: &str,
    ) -> Result<KeygenResult, JsValue> {
        if self.round != 2 {
            return Err(JsValue::from_str("Must be in round 2"));
        }

        let messages: Vec<Round2Message> =
            serde_json::from_str(messages_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

        if messages.len() != 2 {
            return Err(JsValue::from_str("Expected 2 messages from other parties"));
        }

        // Collect public shares
        for msg in &messages {
            self.public_shares.push(
                hex::decode(&msg.public_share)
                    .map_err(|e: hex::FromHexError| JsValue::from_str(&e.to_string()))?,
            );
        }

        // Generate aggregated public key (in real implementation, this would combine EC points)
        let aggregated_pk = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"aggregate:");
            hasher.update(&self.local_secret);
            for share in &self.public_shares {
                hasher.update(share);
            }
            let hash = hasher.finalize();

            // Create compressed public key format (33 bytes)
            let mut pk = vec![0x02]; // Even y-coordinate prefix
            pk.extend_from_slice(&hash[..32]);
            pk
        };

        // Derive Ethereum address from public key
        let eth_address = {
            use sha3::{Digest, Keccak256};

            // For real implementation, we would use the uncompressed public key
            let mut hasher = Keccak256::new();
            hasher.update(&aggregated_pk[1..]); // Skip prefix
            let hash = hasher.finalize();
            format!("0x{}", hex::encode(&hash[12..]))
        };

        // Encrypt the secret share
        let (encrypted_data, nonce, salt) = encrypt_secret(&self.local_secret, password)?;

        // Generate chain code for BIP32
        let chain_code = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"chaincode:");
            hasher.update(&self.session_id);
            hasher.update(&aggregated_pk);
            hex::encode(hasher.finalize())
        };

        let share = KeyShare {
            party_id: self.party_id,
            encrypted_data,
            public_key: hex::encode(&aggregated_pk),
            eth_address: eth_address.clone(),
            chain_code,
            nonce,
            salt,
        };

        self.state = KeygenState::Complete;

        Ok(KeygenResult {
            share,
            public_key: hex::encode(&aggregated_pk),
            eth_address,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct Round1Message {
    party_id: u8,
    session_id: String,
    commitment: String,
}

#[derive(Serialize, Deserialize)]
struct Round2Message {
    party_id: u8,
    session_id: String,
    public_share: String,
}

/// Encrypt a secret using a password
fn encrypt_secret(secret: &[u8], password: &str) -> Result<(String, String, String), JsValue> {
    use base64::Engine;
    use chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{Aead, KeyInit},
    };
    use sha2::{Digest, Sha256};

    // Generate salt
    let salt: [u8; 32] = rand::random();

    // Derive key from password
    let mut key = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(&salt);
    let hash = hasher.finalize();
    key.copy_from_slice(&hash);

    // Encrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new(&key.into());
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, secret)
        .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;

    Ok((
        base64::engine::general_purpose::STANDARD.encode(&ciphertext),
        hex::encode(nonce_bytes),
        hex::encode(salt),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_keygen_config() {
        let config = KeygenConfig::new(PartyRole::Agent).with_timeout(60);

        assert_eq!(config.timeout_secs, 60);
        assert_eq!(config.session_id.len(), 64); // 32 bytes hex
    }

    #[wasm_bindgen_test]
    fn test_key_share_export() {
        let share = KeyShare {
            party_id: 0,
            encrypted_data: "test".to_string(),
            public_key: "0x02".to_string() + &"ab".repeat(32),
            eth_address: "0x".to_string() + &"12".repeat(20),
            chain_code: "cc".repeat(32),
            nonce: "aa".repeat(12),
            salt: "bb".repeat(32),
        };

        let json = share.to_json().unwrap();
        let restored = KeyShare::from_json(&json).unwrap();

        assert_eq!(restored.party_id, share.party_id);
        assert_eq!(restored.eth_address, share.eth_address);
    }
}
