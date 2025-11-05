//! Distributed Key Generation (DKG) for 2-of-3 Agent Wallet
//!
//! This module implements threshold key generation specifically designed for
//! the AI agent wallet use case with three parties:
//! - Agent (party 0)
//! - User (party 1)
//! - Recovery (party 2)
//!
//! The DKG protocol generates secret shares such that any 2-of-3 parties
//! can collaborate to sign transactions.

#[cfg(feature = "runtime")]
mod dkg;
mod messages;
#[cfg(feature = "runtime")]
mod refresh;

#[cfg(feature = "runtime")]
pub use dkg::run_dkg;
pub use messages::{DkgRound1Message, DkgRound2Message};
#[cfg(feature = "runtime")]
pub use refresh::refresh_shares;

use crate::{AgentKeyShare, Result};

/// Result of distributed key generation
#[derive(Debug)]
pub struct KeygenResult {
    /// The generated key share for this party
    pub share: AgentKeyShare,
    /// The aggregated public key (same for all parties)
    pub public_key: Vec<u8>,
    /// Ethereum address derived from the public key
    pub eth_address: String,
}

impl KeygenResult {
    /// Create a new keygen result
    pub fn new(share: AgentKeyShare) -> Result<Self> {
        let eth_address = share.eth_address()?;
        let public_key = share.public_key.clone();

        Ok(Self {
            share,
            public_key,
            eth_address,
        })
    }
}
