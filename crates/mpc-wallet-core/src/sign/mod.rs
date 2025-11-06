//! Distributed Signature Generation (DSG) with Policy Enforcement
//!
//! This module implements threshold ECDSA signing for the 2-of-3 agent wallet.
//! All signing operations pass through the policy engine before MPC execution.
//!
//! ## Signing Flow
//!
//! 1. Transaction request is created
//! 2. Policy engine evaluates the request
//! 3. If approved, MPC signing protocol is executed
//! 4. Signature is returned
//!
//! ## Participants
//!
//! Any 2-of-3 parties can sign:
//! - Agent + User (standard flow)
//! - Agent + Recovery (user unavailable)
//! - User + Recovery (agent revocation)

#[cfg(feature = "runtime")]
mod dsg;
mod messages;

#[cfg(feature = "runtime")]
pub use dsg::{run_dsg, sign_with_policy};
pub use messages::{
    DsgPartialMessage, DsgRound1Message, DsgRound2Message, PartialSignature, PreSignature,
};
