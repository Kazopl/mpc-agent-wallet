//! DSG protocol messages

use crate::PartyId;
use serde::{Deserialize, Serialize};

/// Round 1 DSG message: commitments to nonces
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsgRound1Message {
    /// Sender's party ID
    pub party_id: PartyId,
    /// Commitment to k_i (compressed EC point)
    pub k_commitment: Vec<u8>,
    /// Commitment to gamma_i (compressed EC point)
    pub gamma_commitment: Vec<u8>,
}

/// Round 2 DSG message: MtA protocol shares
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsgRound2Message {
    /// Sender's party ID
    pub party_id: PartyId,
    /// Delta share for signature computation
    pub delta_share: Vec<u8>,
}

/// Partial signature message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsgPartialMessage {
    /// Sender's party ID
    pub party_id: PartyId,
    /// Partial signature component
    pub sigma_share: Vec<u8>,
}

/// Pre-signature data (can be generated before message is known)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreSignature {
    /// Session ID
    pub session_id: [u8; 32],
    /// Participating parties
    pub parties: Vec<PartyId>,
    /// R point (compressed, 33 bytes stored as Vec for serde compatibility)
    pub r_point: Vec<u8>,
    /// This party's k^{-1} share
    pub k_inv_share: Vec<u8>,
    /// This party's chi share (k * x)
    pub chi_share: Vec<u8>,
}

/// Partial signature from one party
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSignature {
    /// Party ID that created this partial
    pub party_id: PartyId,
    /// Sigma share for combining
    pub sigma_share: Vec<u8>,
}
