//! Instructions for the MPC Spending Limit program

pub mod initialize;
pub mod record_spending;
pub mod update_limits;
pub mod validate_transfer;
pub mod whitelist;

pub use initialize::*;
pub use record_spending::*;
pub use update_limits::*;
pub use validate_transfer::*;
pub use whitelist::*;
