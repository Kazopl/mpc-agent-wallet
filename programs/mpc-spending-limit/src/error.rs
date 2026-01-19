//! Custom error types for the MPC Spending Limit program

use anchor_lang::prelude::*;

/// Errors that can occur in the MPC Spending Limit program
#[error_code]
pub enum SpendingLimitError {
    /// Transfer amount exceeds per-transaction limit
    #[msg("Transfer amount exceeds per-transaction limit")]
    PerTxLimitExceeded,

    /// Transfer would exceed daily spending limit
    #[msg("Transfer would exceed daily spending limit")]
    DailyLimitExceeded,

    /// Transfer would exceed weekly spending limit
    #[msg("Transfer would exceed weekly spending limit")]
    WeeklyLimitExceeded,

    /// Transfer would exceed monthly spending limit
    #[msg("Transfer would exceed monthly spending limit")]
    MonthlyLimitExceeded,

    /// Target address is not in the whitelist
    #[msg("Target address is not in the whitelist")]
    NotWhitelisted,

    /// Whitelist mode requires target to be whitelisted
    #[msg("Whitelist mode is enabled and target is not whitelisted")]
    WhitelistRequired,

    /// Target address is blacklisted
    #[msg("Target address is blacklisted")]
    TargetBlacklisted,

    /// Unauthorized - caller is not the authority
    #[msg("Unauthorized - caller is not the authority")]
    Unauthorized,

    /// Invalid limit configuration
    #[msg("Invalid limit configuration - limits must be non-zero and consistent")]
    InvalidLimitConfig,

    /// Config is paused
    #[msg("Spending config is currently paused")]
    ConfigPaused,

    /// Math overflow occurred
    #[msg("Math overflow occurred during calculation")]
    MathOverflow,

    /// Invalid slot window
    #[msg("Invalid slot window for period reset")]
    InvalidSlotWindow,

    /// Whitelist is full
    #[msg("Whitelist has reached maximum capacity")]
    WhitelistFull,

    /// Entry already exists
    #[msg("Whitelist entry already exists")]
    EntryAlreadyExists,

    /// Entry not found
    #[msg("Whitelist entry not found")]
    EntryNotFound,

    /// Invalid authority transfer
    #[msg("Invalid authority transfer - new authority cannot be zero")]
    InvalidAuthorityTransfer,

    /// Guardian already set
    #[msg("Guardian is already set")]
    GuardianAlreadySet,

    /// Guardian not set
    #[msg("Guardian is not set for this config")]
    GuardianNotSet,

    /// Cooldown period has not elapsed
    #[msg("Cooldown period has not elapsed for limit update")]
    CooldownNotElapsed,
}
