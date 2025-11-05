//! DKG protocol messages

use serde::{Deserialize, Serialize};

use crate::PartyId;

/// Round 1 DKG message: commitments to secret polynomial
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgRound1Message {
    /// Sender's party ID
    pub party_id: PartyId,
    /// Commitments to polynomial coefficients (each commitment is a compressed EC point)
    pub commitments: Vec<Vec<u8>>,
}

/// Round 2 DKG message: secret share for a specific party
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgRound2Message {
    /// Sender's party ID
    pub from: PartyId,
    /// Recipient's party ID
    pub to: PartyId,
    /// The secret share (32 bytes)
    pub share: Vec<u8>,
}
