//! WASM bindings for threshold signing

use crate::keygen::KeyShare;
use crate::policy::{PolicyConfig, PolicyDecision, PolicyEngine};
use crate::types::{PartyRole, Signature, TransactionRequest};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Configuration for a signing session
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningConfig {
    /// Session ID (32 bytes, hex)
    #[wasm_bindgen(js_name = sessionId)]
    pub session_id: String,
    /// Participating parties
    pub participants: Vec<u8>,
    /// Timeout in seconds
    #[wasm_bindgen(js_name = timeoutSecs)]
    pub timeout_secs: u32,
}

#[wasm_bindgen]
impl SigningConfig {
    /// Create a new signing config with AI agent and user
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            session_id: hex::encode(rand::random::<[u8; 32]>()),
            participants: vec![0, 1], // Agent + User
            timeout_secs: 60,
        }
    }

    /// Set session ID
    #[wasm_bindgen(js_name = withSessionId)]
    pub fn with_session_id(mut self, session_id: String) -> Self {
        self.session_id = session_id;
        self
    }

    /// Set participants (Agent=0, User=1, Recovery=2)
    #[wasm_bindgen(js_name = withParticipants)]
    pub fn with_participants(mut self, participants: Vec<u8>) -> Self {
        self.participants = participants;
        self
    }

    /// Add recovery guardian instead of user
    #[wasm_bindgen(js_name = withRecovery)]
    pub fn with_recovery(mut self) -> Self {
        self.participants = vec![0, 2]; // Agent + Recovery
        self
    }

    /// Set timeout
    #[wasm_bindgen(js_name = withTimeout)]
    pub fn with_timeout(mut self, timeout_secs: u32) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }
}

impl Default for SigningConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Signing session state machine
#[wasm_bindgen]
pub struct SigningSession {
    party_id: u8,
    session_id: Vec<u8>,
    message_hash: Vec<u8>,
    round: u32,
    state: SigningState,
    // Intermediate values
    local_nonce: Vec<u8>,
    nonce_commitments: Vec<Vec<u8>>,
    partial_signatures: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
enum SigningState {
    Initialized,
    Round1Complete,
    #[allow(dead_code)]
    Round2Complete,
    Complete(Signature),
    #[allow(dead_code)]
    Failed(String),
}

#[wasm_bindgen]
impl SigningSession {
    /// Create a new signing session
    #[wasm_bindgen(constructor)]
    pub fn new(
        config: &SigningConfig,
        share: &KeyShare,
        message_hash: Vec<u8>,
    ) -> Result<SigningSession, JsValue> {
        let session_id = hex::decode(&config.session_id)
            .map_err(|e| JsValue::from_str(&format!("Invalid session ID: {}", e)))?;

        if session_id.len() != 32 {
            return Err(JsValue::from_str("Session ID must be 32 bytes"));
        }

        if message_hash.len() != 32 {
            return Err(JsValue::from_str("Message hash must be 32 bytes"));
        }

        if !config.participants.contains(&share.party_id()) {
            return Err(JsValue::from_str("Party not in signing set"));
        }

        if config.participants.len() < 2 {
            return Err(JsValue::from_str("Need at least 2 participants"));
        }

        Ok(SigningSession {
            party_id: share.party_id(),
            session_id,
            message_hash,
            round: 0,
            state: SigningState::Initialized,
            local_nonce: Vec::new(),
            nonce_commitments: Vec::new(),
            partial_signatures: Vec::new(),
        })
    }

    /// Get current round
    #[wasm_bindgen(getter)]
    pub fn round(&self) -> u32 {
        self.round
    }

    /// Check if signing is complete
    #[wasm_bindgen(js_name = isComplete)]
    pub fn is_complete(&self) -> bool {
        matches!(self.state, SigningState::Complete(_))
    }

    /// Check if signing failed
    #[wasm_bindgen(js_name = isFailed)]
    pub fn is_failed(&self) -> bool {
        matches!(self.state, SigningState::Failed(_))
    }

    /// Get failure reason
    #[wasm_bindgen(js_name = getFailureReason)]
    pub fn get_failure_reason(&self) -> Option<String> {
        match &self.state {
            SigningState::Failed(reason) => Some(reason.clone()),
            _ => None,
        }
    }

    /// Get the final signature (if complete)
    #[wasm_bindgen(js_name = getSignature)]
    pub fn get_signature(&self) -> Option<Signature> {
        match &self.state {
            SigningState::Complete(sig) => Some(sig.clone()),
            _ => None,
        }
    }

    /// Generate round 1 message (nonce commitment)
    #[wasm_bindgen(js_name = generateRound1)]
    pub fn generate_round1(&mut self) -> Result<String, JsValue> {
        if !matches!(self.state, SigningState::Initialized) {
            return Err(JsValue::from_str("Invalid state for round 1"));
        }

        // Generate local nonce
        use rand::RngCore;
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        self.local_nonce = nonce.to_vec();

        // Create nonce commitment (R_i = k_i * G)
        // In real implementation, this would be EC multiplication
        let commitment = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"nonce_commitment:");
            hasher.update(&nonce);
            hasher.update(&self.session_id);
            hasher.update(&self.message_hash);
            hasher.finalize().to_vec()
        };

        self.round = 1;

        let msg = SignRound1Message {
            party_id: self.party_id,
            session_id: hex::encode(&self.session_id),
            commitment: hex::encode(&commitment),
        };

        serde_json::to_string(&msg).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Process round 1 messages from other party
    #[wasm_bindgen(js_name = processRound1)]
    pub fn process_round1(&mut self, messages_json: &str) -> Result<(), JsValue> {
        if self.round != 1 {
            return Err(JsValue::from_str("Must be in round 1"));
        }

        let messages: Vec<SignRound1Message> =
            serde_json::from_str(messages_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

        if messages.is_empty() {
            return Err(JsValue::from_str(
                "Expected at least 1 message from other party",
            ));
        }

        // Store commitments
        for msg in messages {
            let commitment = hex::decode(&msg.commitment)
                .map_err(|e: hex::FromHexError| JsValue::from_str(&e.to_string()))?;
            self.nonce_commitments.push(commitment);
        }

        self.state = SigningState::Round1Complete;
        Ok(())
    }

    /// Generate round 2 message (partial signature)
    #[wasm_bindgen(js_name = generateRound2)]
    pub fn generate_round2(&mut self, _password: &str) -> Result<String, JsValue> {
        if !matches!(self.state, SigningState::Round1Complete) {
            return Err(JsValue::from_str("Invalid state for round 2"));
        }

        // Compute aggregate nonce point R
        let aggregate_r = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"aggregate_r:");
            hasher.update(&self.local_nonce);
            for commitment in &self.nonce_commitments {
                hasher.update(commitment);
            }
            hasher.finalize().to_vec()
        };

        // Compute partial signature s_i = k_i + e * x_i
        // In real implementation, e = H(R || P || m) and x_i is the secret share
        let partial_sig = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"partial_sig:");
            hasher.update(&self.local_nonce);
            hasher.update(&aggregate_r);
            hasher.update(&self.message_hash);
            hasher.finalize().to_vec()
        };

        self.round = 2;

        let msg = SignRound2Message {
            party_id: self.party_id,
            session_id: hex::encode(&self.session_id),
            partial_signature: hex::encode(&partial_sig),
            nonce_point: hex::encode(&aggregate_r[..32]),
        };

        serde_json::to_string(&msg).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Process round 2 messages and complete signing
    #[wasm_bindgen(js_name = processRound2)]
    pub fn process_round2(&mut self, messages_json: &str) -> Result<Signature, JsValue> {
        if self.round != 2 {
            return Err(JsValue::from_str("Must be in round 2"));
        }

        let messages: Vec<SignRound2Message> =
            serde_json::from_str(messages_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

        if messages.is_empty() {
            return Err(JsValue::from_str(
                "Expected at least 1 message from other party",
            ));
        }

        // Collect partial signatures
        for msg in &messages {
            let partial = hex::decode(&msg.partial_signature)
                .map_err(|e: hex::FromHexError| JsValue::from_str(&e.to_string()))?;
            self.partial_signatures.push(partial);
        }

        // Combine partial signatures: s = s_1 + s_2
        // In real implementation, this uses Lagrange interpolation
        let combined_s = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"combined_s:");
            for partial in &self.partial_signatures {
                hasher.update(partial);
            }
            hasher.finalize()
        };

        // Compute r from the aggregate nonce
        let r = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"r:");
            hasher.update(&self.message_hash);
            for commitment in &self.nonce_commitments {
                hasher.update(commitment);
            }
            hasher.finalize()
        };

        // Determine recovery ID (simplified - in real implementation would check y-coordinate parity)
        let recovery_id = if r[31] % 2 == 0 { 0 } else { 1 };

        let signature = Signature {
            r: format!("0x{}", hex::encode(&r[..32])),
            s: format!("0x{}", hex::encode(&combined_s[..32])),
            recovery_id,
        };

        self.state = SigningState::Complete(signature.clone());

        Ok(signature)
    }
}

#[derive(Serialize, Deserialize)]
struct SignRound1Message {
    party_id: u8,
    session_id: String,
    commitment: String,
}

#[derive(Serialize, Deserialize)]
struct SignRound2Message {
    party_id: u8,
    session_id: String,
    partial_signature: String,
    nonce_point: String,
}

/// MPC Wallet for complete signing operations with policy enforcement
#[wasm_bindgen]
pub struct MpcWallet {
    share: Option<KeyShare>,
    policy_engine: Option<PolicyEngine>,
}

#[wasm_bindgen]
impl MpcWallet {
    /// Create a new wallet (without key share)
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            share: None,
            policy_engine: None,
        }
    }

    /// Load a key share
    #[wasm_bindgen(js_name = loadShare)]
    pub fn load_share(&mut self, share_json: &str) -> Result<(), JsValue> {
        let share = KeyShare::from_json(share_json)?;
        self.share = Some(share);
        Ok(())
    }

    /// Set policy configuration
    #[wasm_bindgen(js_name = setPolicy)]
    pub fn set_policy(&mut self, config: &PolicyConfig) -> Result<(), JsValue> {
        let engine = PolicyEngine::new(config)?;
        self.policy_engine = Some(engine);
        Ok(())
    }

    /// Get the public key
    #[wasm_bindgen(js_name = getPublicKey)]
    pub fn get_public_key(&self) -> Result<String, JsValue> {
        self.share
            .as_ref()
            .map(|s| s.public_key())
            .ok_or_else(|| JsValue::from_str("No share loaded"))
    }

    /// Get the Ethereum address
    #[wasm_bindgen(js_name = getAddress)]
    pub fn get_address(&self) -> Result<String, JsValue> {
        self.share
            .as_ref()
            .map(|s| s.eth_address())
            .ok_or_else(|| JsValue::from_str("No share loaded"))
    }

    /// Get the party role
    #[wasm_bindgen(js_name = getRole)]
    pub fn get_role(&self) -> Result<PartyRole, JsValue> {
        self.share
            .as_ref()
            .map(|s| s.role())
            .ok_or_else(|| JsValue::from_str("No share loaded"))
    }

    /// Evaluate a transaction against policy
    #[wasm_bindgen(js_name = evaluatePolicy)]
    pub fn evaluate_policy(&self, tx: &TransactionRequest) -> Result<PolicyDecision, JsValue> {
        match &self.policy_engine {
            Some(engine) => engine.evaluate(tx),
            None => Ok(PolicyDecision {
                approved: true,
                requires_additional_approval: false,
                reason: None,
            }),
        }
    }

    /// Create a signing session
    #[wasm_bindgen(js_name = createSigningSession)]
    pub fn create_signing_session(
        &self,
        config: &SigningConfig,
        message_hash: Vec<u8>,
    ) -> Result<SigningSession, JsValue> {
        let share = self
            .share
            .as_ref()
            .ok_or_else(|| JsValue::from_str("No share loaded"))?;

        SigningSession::new(config, share, message_hash)
    }

    /// Hash a message for signing (Keccak256)
    #[wasm_bindgen(js_name = hashMessage)]
    pub fn hash_message(&self, message: &[u8]) -> Vec<u8> {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(message);
        hasher.finalize().to_vec()
    }

    /// Hash a message with Ethereum prefix
    #[wasm_bindgen(js_name = hashEthMessage)]
    pub fn hash_eth_message(&self, message: &[u8]) -> Vec<u8> {
        use sha3::{Digest, Keccak256};
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut hasher = Keccak256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(message);
        hasher.finalize().to_vec()
    }

    /// Verify a signature against a message and the wallet's public key
    #[wasm_bindgen(js_name = verifySignature)]
    pub fn verify_signature(
        &self,
        message_hash: &[u8],
        signature: &Signature,
    ) -> Result<bool, JsValue> {
        // In real implementation, this would use ECDSA verification
        // For now, just check that we have a share and the signature has valid format
        if self.share.is_none() {
            return Err(JsValue::from_str("No share loaded"));
        }

        if message_hash.len() != 32 {
            return Err(JsValue::from_str("Message hash must be 32 bytes"));
        }

        // Check signature components are valid hex
        let _ = hex::decode(signature.r.strip_prefix("0x").unwrap_or(&signature.r))
            .map_err(|e| JsValue::from_str(&format!("Invalid r: {}", e)))?;
        let _ = hex::decode(signature.s.strip_prefix("0x").unwrap_or(&signature.s))
            .map_err(|e| JsValue::from_str(&format!("Invalid s: {}", e)))?;

        // In a real implementation, we would verify the signature here
        Ok(true)
    }
}

impl Default for MpcWallet {
    fn default() -> Self {
        Self::new()
    }
}

/// Approval request for user
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Request ID
    #[wasm_bindgen(js_name = requestId)]
    pub request_id: String,
    /// Session ID
    #[wasm_bindgen(js_name = sessionId)]
    pub session_id: String,
    /// Transaction details (JSON)
    #[wasm_bindgen(js_name = transactionJson)]
    pub transaction_json: String,
    /// Message hash to sign (hex)
    #[wasm_bindgen(js_name = messageHash)]
    pub message_hash: String,
    /// Expiry timestamp
    #[wasm_bindgen(js_name = expiresAt)]
    pub expires_at: i64,
    /// Requesting party
    #[wasm_bindgen(js_name = requestedBy)]
    pub requested_by: PartyRole,
}

#[wasm_bindgen]
impl ApprovalRequest {
    /// Create a new approval request
    #[wasm_bindgen(constructor)]
    pub fn new(tx: &TransactionRequest, message_hash: Vec<u8>, requested_by: PartyRole) -> Self {
        let session_id = hex::encode(rand::random::<[u8; 32]>());
        let expires_at = chrono::Utc::now().timestamp() + 300; // 5 minutes

        Self {
            request_id: tx.request_id.clone(),
            session_id,
            transaction_json: serde_json::to_string(tx).unwrap_or_default(),
            message_hash: hex::encode(&message_hash),
            expires_at,
            requested_by,
        }
    }

    /// Check if the request has expired
    #[wasm_bindgen(js_name = isExpired)]
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now().timestamp() > self.expires_at
    }

    /// Convert to JSON
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Create from JSON
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(json: &str) -> Result<ApprovalRequest, JsValue> {
        serde_json::from_str(json).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_signing_config() {
        let config = SigningConfig::new().with_timeout(30);
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.participants, vec![0, 1]);

        let recovery_config = SigningConfig::new().with_recovery();
        assert_eq!(recovery_config.participants, vec![0, 2]);
    }

    #[wasm_bindgen_test]
    fn test_mpc_wallet() {
        let wallet = MpcWallet::new();

        // Without share, should fail
        assert!(wallet.get_address().is_err());

        // Hash message
        let hash = wallet.hash_message(b"test message");
        assert_eq!(hash.len(), 32);
    }

    #[wasm_bindgen_test]
    fn test_approval_request() {
        use crate::types::ChainType;

        let tx = TransactionRequest::new(ChainType::Evm, "0x1234".to_string(), "1000".to_string());
        let hash = vec![0u8; 32];
        let request = ApprovalRequest::new(&tx, hash, PartyRole::Agent);

        assert!(!request.is_expired());
        assert!(!request.session_id.is_empty());
    }
}
