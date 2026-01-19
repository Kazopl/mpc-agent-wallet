//! State definitions for the MPC Spending Limit program
//!
//! This module defines the PDA account structures for:
//! - SpendingConfig: Main configuration with limits and authority
//! - WhitelistEntry: Individual whitelist/blacklist entries
//! - SpendingRecord: Per-period spending tracking

use anchor_lang::prelude::*;

// ============================================================================
// Constants
// ============================================================================

/// Seed for SpendingConfig PDA
pub const SPENDING_CONFIG_SEED: &[u8] = b"spending_config";

/// Seed for WhitelistEntry PDA
pub const WHITELIST_SEED: &[u8] = b"whitelist";

/// Seed for SpendingRecord PDA
pub const SPENDING_RECORD_SEED: &[u8] = b"spending_record";

/// Approximate slots per day (assuming 400ms slot time)
pub const SLOTS_PER_DAY: u64 = 216_000;

/// Approximate slots per week
pub const SLOTS_PER_WEEK: u64 = SLOTS_PER_DAY * 7;

/// Approximate slots per month (30 days)
pub const SLOTS_PER_MONTH: u64 = SLOTS_PER_DAY * 30;

/// Maximum whitelist entries per config
pub const MAX_WHITELIST_ENTRIES: u16 = 256;

// ============================================================================
// SpendingConfig Account
// ============================================================================

/// Main spending configuration account
///
/// This PDA stores the spending limits and authority for an MPC wallet.
/// It tracks per-transaction, daily, weekly, and monthly limits.
#[account]
#[derive(Debug)]
pub struct SpendingConfig {
    /// Authority that controls this config (MPC wallet address)
    pub authority: Pubkey,

    /// Optional guardian for emergency actions
    pub guardian: Option<Pubkey>,

    /// Maximum amount per single transaction (in lamports)
    pub per_tx_limit: u64,

    /// Maximum daily spending (in lamports)
    pub daily_limit: u64,

    /// Maximum weekly spending (in lamports)
    pub weekly_limit: u64,

    /// Maximum monthly spending (in lamports)
    pub monthly_limit: u64,

    /// Current daily spending (in lamports)
    pub daily_spent: u64,

    /// Current weekly spending (in lamports)
    pub weekly_spent: u64,

    /// Current monthly spending (in lamports)
    pub monthly_spent: u64,

    /// Slot when daily counter resets
    pub daily_reset_slot: u64,

    /// Slot when weekly counter resets
    pub weekly_reset_slot: u64,

    /// Slot when monthly counter resets
    pub monthly_reset_slot: u64,

    /// Whether whitelist mode is enabled (only allow whitelisted targets)
    pub whitelist_only: bool,

    /// Whether the config is paused
    pub is_paused: bool,

    /// Number of whitelist entries
    pub whitelist_count: u16,

    /// Cooldown slots before limit updates take effect
    pub update_cooldown_slots: u64,

    /// Slot when pending update was submitted
    pub pending_update_slot: u64,

    /// Bump seed for PDA derivation
    pub bump: u8,

    /// Reserved for future use
    pub _reserved: [u8; 64],
}

impl SpendingConfig {
    /// Size of the account in bytes
    pub const SIZE: usize = 8 + // discriminator
        32 + // authority
        33 + // guardian (Option<Pubkey>)
        8 + // per_tx_limit
        8 + // daily_limit
        8 + // weekly_limit
        8 + // monthly_limit
        8 + // daily_spent
        8 + // weekly_spent
        8 + // monthly_spent
        8 + // daily_reset_slot
        8 + // weekly_reset_slot
        8 + // monthly_reset_slot
        1 + // whitelist_only
        1 + // is_paused
        2 + // whitelist_count
        8 + // update_cooldown_slots
        8 + // pending_update_slot
        1 + // bump
        64; // _reserved

    /// Check if daily period has reset
    pub fn should_reset_daily(&self, current_slot: u64) -> bool {
        current_slot >= self.daily_reset_slot
    }

    /// Check if weekly period has reset
    pub fn should_reset_weekly(&self, current_slot: u64) -> bool {
        current_slot >= self.weekly_reset_slot
    }

    /// Check if monthly period has reset
    pub fn should_reset_monthly(&self, current_slot: u64) -> bool {
        current_slot >= self.monthly_reset_slot
    }

    /// Reset daily counter
    pub fn reset_daily(&mut self, current_slot: u64) {
        self.daily_spent = 0;
        self.daily_reset_slot = current_slot + SLOTS_PER_DAY;
    }

    /// Reset weekly counter
    pub fn reset_weekly(&mut self, current_slot: u64) {
        self.weekly_spent = 0;
        self.weekly_reset_slot = current_slot + SLOTS_PER_WEEK;
    }

    /// Reset monthly counter
    pub fn reset_monthly(&mut self, current_slot: u64) {
        self.monthly_spent = 0;
        self.monthly_reset_slot = current_slot + SLOTS_PER_MONTH;
    }

    /// Calculate remaining daily allowance
    pub fn remaining_daily(&self) -> u64 {
        self.daily_limit.saturating_sub(self.daily_spent)
    }

    /// Calculate remaining weekly allowance
    pub fn remaining_weekly(&self) -> u64 {
        self.weekly_limit.saturating_sub(self.weekly_spent)
    }

    /// Calculate remaining monthly allowance
    pub fn remaining_monthly(&self) -> u64 {
        self.monthly_limit.saturating_sub(self.monthly_spent)
    }

    /// Get the minimum remaining across all periods
    pub fn remaining_minimum(&self) -> u64 {
        self.remaining_daily()
            .min(self.remaining_weekly())
            .min(self.remaining_monthly())
            .min(self.per_tx_limit)
    }
}

// ============================================================================
// WhitelistEntry Account
// ============================================================================

/// Whitelist/blacklist entry for a target address
///
/// Each entry is stored as a separate PDA derived from the config and target.
#[account]
#[derive(Default, Debug)]
pub struct WhitelistEntry {
    /// The spending config this entry belongs to
    pub config: Pubkey,

    /// The target address (recipient)
    pub target: Pubkey,

    /// Whether this target is allowed (whitelist) or blocked (blacklist)
    pub is_allowed: bool,

    /// Whether this is a blacklist entry (overrides whitelist_only mode)
    pub is_blacklisted: bool,

    /// Optional label for the entry
    pub label: [u8; 32],

    /// When this entry was created (slot)
    pub created_at: u64,

    /// When this entry was last updated (slot)
    pub updated_at: u64,

    /// Bump seed for PDA derivation
    pub bump: u8,

    /// Reserved for future use
    pub _reserved: [u8; 16],
}

impl WhitelistEntry {
    /// Size of the account in bytes
    pub const SIZE: usize = 8 + // discriminator
        32 + // config
        32 + // target
        1 + // is_allowed
        1 + // is_blacklisted
        32 + // label
        8 + // created_at
        8 + // updated_at
        1 + // bump
        16; // _reserved
}

// ============================================================================
// SpendingRecord Account (Optional - for detailed tracking)
// ============================================================================

/// Record of a spending transaction
///
/// Used for audit trails and detailed spending history.
#[account]
#[derive(Default, Debug)]
pub struct SpendingRecord {
    /// The spending config this record belongs to
    pub config: Pubkey,

    /// Transaction signature (first 32 bytes)
    pub tx_signature: [u8; 32],

    /// Target address
    pub target: Pubkey,

    /// Amount spent (in lamports)
    pub amount: u64,

    /// Slot when the transaction occurred
    pub slot: u64,

    /// Unix timestamp (approximate)
    pub timestamp: i64,

    /// Bump seed for PDA derivation
    pub bump: u8,
}

impl SpendingRecord {
    /// Size of the account in bytes
    pub const SIZE: usize = 8 + // discriminator
        32 + // config
        32 + // tx_signature
        32 + // target
        8 + // amount
        8 + // slot
        8 + // timestamp
        1; // bump
}

// ============================================================================
// Input Types
// ============================================================================

/// Input parameters for initializing a spending config
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct SpendingConfigInput {
    /// Maximum amount per single transaction (in lamports)
    pub per_tx_limit: u64,

    /// Maximum daily spending (in lamports)
    pub daily_limit: u64,

    /// Maximum weekly spending (in lamports)
    pub weekly_limit: u64,

    /// Maximum monthly spending (in lamports)
    pub monthly_limit: u64,

    /// Whether whitelist mode is enabled
    pub whitelist_only: bool,

    /// Cooldown slots before limit updates take effect (0 for no cooldown)
    pub update_cooldown_slots: u64,
}

impl SpendingConfigInput {
    /// Validate the input parameters
    pub fn validate(&self) -> bool {
        // All limits must be positive
        self.per_tx_limit > 0
            && self.daily_limit > 0
            && self.weekly_limit > 0
            && self.monthly_limit > 0
            // Limits should be consistent (daily <= weekly <= monthly)
            && self.daily_limit <= self.weekly_limit
            && self.weekly_limit <= self.monthly_limit
            // Per-tx should not exceed daily
            && self.per_tx_limit <= self.daily_limit
    }
}

/// Input parameters for updating spending limits
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, Default)]
pub struct LimitsInput {
    /// New per-transaction limit (None to keep current)
    pub per_tx_limit: Option<u64>,

    /// New daily limit (None to keep current)
    pub daily_limit: Option<u64>,

    /// New weekly limit (None to keep current)
    pub weekly_limit: Option<u64>,

    /// New monthly limit (None to keep current)
    pub monthly_limit: Option<u64>,

    /// New whitelist mode (None to keep current)
    pub whitelist_only: Option<bool>,
}

// ============================================================================
// Events
// ============================================================================

/// Event emitted when a spending config is initialized
#[event]
pub struct ConfigInitialized {
    pub config: Pubkey,
    pub authority: Pubkey,
    pub per_tx_limit: u64,
    pub daily_limit: u64,
    pub weekly_limit: u64,
    pub monthly_limit: u64,
}

/// Event emitted when spending limits are updated
#[event]
pub struct LimitsUpdated {
    pub config: Pubkey,
    pub per_tx_limit: u64,
    pub daily_limit: u64,
    pub weekly_limit: u64,
    pub monthly_limit: u64,
}

/// Event emitted when a transfer is validated
#[event]
pub struct TransferValidated {
    pub config: Pubkey,
    pub target: Pubkey,
    pub amount: u64,
    pub daily_remaining: u64,
    pub weekly_remaining: u64,
    pub monthly_remaining: u64,
}

/// Event emitted when spending is recorded
#[event]
pub struct SpendingRecorded {
    pub config: Pubkey,
    pub target: Pubkey,
    pub amount: u64,
    pub daily_spent: u64,
    pub weekly_spent: u64,
    pub monthly_spent: u64,
}

/// Event emitted when a whitelist entry is added
#[event]
pub struct WhitelistAdded {
    pub config: Pubkey,
    pub target: Pubkey,
    pub is_blacklisted: bool,
}

/// Event emitted when a whitelist entry is removed
#[event]
pub struct WhitelistRemoved {
    pub config: Pubkey,
    pub target: Pubkey,
}

/// Event emitted when config is paused/unpaused
#[event]
pub struct ConfigPauseToggled {
    pub config: Pubkey,
    pub is_paused: bool,
}

/// Event emitted when authority is transferred
#[event]
pub struct AuthorityTransferred {
    pub config: Pubkey,
    pub old_authority: Pubkey,
    pub new_authority: Pubkey,
}
