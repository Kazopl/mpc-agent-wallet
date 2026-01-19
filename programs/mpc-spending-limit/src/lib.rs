//! # MPC Spending Limit Program
//!
//! A Solana program that enforces spending limits for MPC wallets.
//!
//! ## Features
//!
//! - **Per-transaction limits**: Maximum amount per single transfer
//! - **Period-based limits**: Daily, weekly, and monthly spending caps
//! - **Whitelist/Blacklist**: Control which addresses can receive funds
//! - **Guardian support**: Optional guardian for emergency pause
//! - **Cooldown periods**: Optional delay for limit updates
//!
//! ## Architecture
//!
//! The program uses PDAs (Program Derived Addresses) for state:
//!
//! - `SpendingConfig`: Main configuration PDA derived from `[spending_config, authority]`
//! - `WhitelistEntry`: Per-target whitelist entries derived from `[whitelist, config, target]`
//!
//! ## Usage
//!
//! 1. Initialize a spending config for your MPC wallet
//! 2. Optionally add whitelist entries for allowed recipients
//! 3. Before each transfer, call `validate_transfer` to check limits
//! 4. After successful transfer, call `record_spending` to update counters
//! 5. Or use `validate_and_record` for atomic validation + recording
//!
//! ## Example
//!
//! ```ignore
//! // Initialize config
//! let config = SpendingConfigInput {
//!     per_tx_limit: 1_000_000_000,      // 1 SOL per tx
//!     daily_limit: 10_000_000_000,       // 10 SOL daily
//!     weekly_limit: 50_000_000_000,      // 50 SOL weekly
//!     monthly_limit: 100_000_000_000,    // 100 SOL monthly
//!     whitelist_only: false,
//!     update_cooldown_slots: 0,
//! };
//!
//! // Validate before transfer
//! validate_transfer(amount, target)?;
//!
//! // Execute transfer...
//!
//! // Record after transfer
//! record_spending(amount)?;
//! ```

use anchor_lang::prelude::*;

pub mod error;
pub mod instructions;
pub mod state;

use instructions::*;
use state::*;

declare_id!("MpcSLim1t1111111111111111111111111111111111");

/// MPC Spending Limit Program
#[program]
pub mod mpc_spending_limit {
    use super::*;

    // ========================================================================
    // Initialization
    // ========================================================================

    /// Initialize a new spending configuration
    ///
    /// Creates a PDA that stores spending limits for an MPC wallet.
    /// The caller becomes the authority.
    pub fn initialize(ctx: Context<Initialize>, config_input: SpendingConfigInput) -> Result<()> {
        instructions::initialize::handler(ctx, config_input)
    }

    /// Initialize a spending config for a specific authority
    ///
    /// Allows creating a config where the payer is different from the authority.
    pub fn initialize_for(
        ctx: Context<InitializeFor>,
        authority: Pubkey,
        config_input: SpendingConfigInput,
    ) -> Result<()> {
        instructions::initialize::handler_for(ctx, authority, config_input)
    }

    // ========================================================================
    // Limit Management
    // ========================================================================

    /// Update spending limits
    ///
    /// Modifies the spending limits. Subject to cooldown if configured.
    pub fn update_limits(ctx: Context<UpdateLimits>, new_limits: LimitsInput) -> Result<()> {
        instructions::update_limits::handler(ctx, new_limits)
    }

    /// Toggle pause state
    ///
    /// Can be called by authority or guardian to pause/unpause transfers.
    pub fn toggle_pause(ctx: Context<TogglePause>) -> Result<()> {
        instructions::update_limits::handler_toggle_pause(ctx)
    }

    /// Set or remove guardian
    ///
    /// The guardian can pause the config but cannot modify limits.
    pub fn set_guardian(ctx: Context<SetGuardian>, guardian: Option<Pubkey>) -> Result<()> {
        instructions::update_limits::handler_set_guardian(ctx, guardian)
    }

    /// Transfer authority to a new address
    pub fn transfer_authority(
        ctx: Context<TransferAuthority>,
        new_authority: Pubkey,
    ) -> Result<()> {
        instructions::update_limits::handler_transfer_authority(ctx, new_authority)
    }

    // ========================================================================
    // Whitelist Management
    // ========================================================================

    /// Add an address to the whitelist
    ///
    /// Creates a whitelist entry PDA for the target address.
    pub fn add_to_whitelist(
        ctx: Context<AddToWhitelist>,
        target: Pubkey,
        is_blacklisted: bool,
        label: Option<[u8; 32]>,
    ) -> Result<()> {
        instructions::whitelist::handler_add_to_whitelist(ctx, target, is_blacklisted, label)
    }

    /// Remove an address from the whitelist
    ///
    /// Closes the whitelist entry PDA.
    pub fn remove_from_whitelist(ctx: Context<RemoveFromWhitelist>, target: Pubkey) -> Result<()> {
        instructions::whitelist::handler_remove_from_whitelist(ctx, target)
    }

    /// Update a whitelist entry
    pub fn update_whitelist_entry(
        ctx: Context<UpdateWhitelistEntry>,
        target: Pubkey,
        is_allowed: Option<bool>,
        is_blacklisted: Option<bool>,
        label: Option<[u8; 32]>,
    ) -> Result<()> {
        instructions::whitelist::handler_update_whitelist_entry(
            ctx,
            target,
            is_allowed,
            is_blacklisted,
            label,
        )
    }

    // ========================================================================
    // Transfer Validation
    // ========================================================================

    /// Validate a transfer against spending limits
    ///
    /// Checks if a transfer is allowed. Does NOT record the spending.
    pub fn validate_transfer(
        ctx: Context<ValidateTransfer>,
        amount: u64,
        target: Pubkey,
    ) -> Result<()> {
        instructions::validate_transfer::handler(ctx, amount, target)
    }

    /// Check if a transfer would be allowed (read-only)
    ///
    /// View-like function that doesn't require authority signature.
    pub fn check_transfer(ctx: Context<CheckTransfer>, amount: u64, target: Pubkey) -> Result<()> {
        instructions::validate_transfer::handler_check(ctx, amount, target)
    }

    /// Get remaining spending allowance
    pub fn get_remaining(ctx: Context<GetRemaining>) -> Result<RemainingAllowance> {
        instructions::validate_transfer::handler_get_remaining(ctx)
    }

    // ========================================================================
    // Spending Recording
    // ========================================================================

    /// Record a completed transfer
    ///
    /// Updates the spending counters after a transfer has been executed.
    pub fn record_spending(ctx: Context<RecordSpending>, amount: u64) -> Result<()> {
        instructions::record_spending::handler(ctx, amount)
    }

    /// Record a completed transfer with target information
    pub fn record_spending_with_target(
        ctx: Context<RecordSpendingWithTarget>,
        amount: u64,
        target: Pubkey,
    ) -> Result<()> {
        instructions::record_spending::handler_with_target(ctx, amount, target)
    }

    /// Validate and record a transfer atomically
    ///
    /// Combines validation and recording in a single instruction.
    pub fn validate_and_record(
        ctx: Context<ValidateAndRecord>,
        amount: u64,
        target: Pubkey,
    ) -> Result<()> {
        instructions::record_spending::handler_validate_and_record(ctx, amount, target)
    }

    /// Reset spending counters
    ///
    /// Can be used by authority or guardian for emergency resets.
    pub fn reset_counters(
        ctx: Context<ResetCounters>,
        reset_daily: bool,
        reset_weekly: bool,
        reset_monthly: bool,
    ) -> Result<()> {
        instructions::record_spending::handler_reset_counters(
            ctx,
            reset_daily,
            reset_weekly,
            reset_monthly,
        )
    }
}
