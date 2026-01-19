//! Validate transfer instruction for checking spending limits

use anchor_lang::prelude::*;

use crate::error::SpendingLimitError;
use crate::state::*;

/// Accounts for the validate_transfer instruction
#[derive(Accounts)]
#[instruction(amount: u64, target: Pubkey)]
pub struct ValidateTransfer<'info> {
    /// The authority validating the transfer
    pub authority: Signer<'info>,

    /// The spending config PDA
    #[account(
        mut,
        seeds = [SPENDING_CONFIG_SEED, authority.key().as_ref()],
        bump = spending_config.bump,
        constraint = spending_config.authority == authority.key() @ SpendingLimitError::Unauthorized
    )]
    pub spending_config: Account<'info, SpendingConfig>,

    /// Optional whitelist entry for the target (if whitelist mode is enabled)
    /// CHECK: This account is optional and validated in the handler
    pub whitelist_entry: Option<UncheckedAccount<'info>>,
}

/// Validate a transfer against spending limits
///
/// Checks if a transfer of the given amount to the target address is allowed
/// based on the spending limits and whitelist configuration. This instruction
/// does NOT record the spending - use `record_spending` after the actual transfer.
///
/// # Arguments
/// * `ctx` - The instruction context
/// * `amount` - The transfer amount in lamports
/// * `target` - The target address
///
/// # Returns
/// * `Ok(())` if the transfer is allowed
///
/// # Errors
/// * `ConfigPaused` - If the config is paused
/// * `PerTxLimitExceeded` - If amount exceeds per-transaction limit
/// * `DailyLimitExceeded` - If amount would exceed daily limit
/// * `WeeklyLimitExceeded` - If amount would exceed weekly limit
/// * `MonthlyLimitExceeded` - If amount would exceed monthly limit
/// * `WhitelistRequired` - If whitelist mode is on and target is not whitelisted
/// * `TargetBlacklisted` - If target is on the blacklist
pub fn handler(ctx: Context<ValidateTransfer>, amount: u64, target: Pubkey) -> Result<()> {
    let config_key = ctx.accounts.spending_config.key();
    let spending_config = &mut ctx.accounts.spending_config;
    let clock = Clock::get()?;
    let current_slot = clock.slot;

    // Check if paused
    require!(!spending_config.is_paused, SpendingLimitError::ConfigPaused);

    // Reset counters if periods have elapsed
    if spending_config.should_reset_daily(current_slot) {
        spending_config.reset_daily(current_slot);
    }
    if spending_config.should_reset_weekly(current_slot) {
        spending_config.reset_weekly(current_slot);
    }
    if spending_config.should_reset_monthly(current_slot) {
        spending_config.reset_monthly(current_slot);
    }

    // Check per-transaction limit
    require!(
        amount <= spending_config.per_tx_limit,
        SpendingLimitError::PerTxLimitExceeded
    );

    // Check daily limit
    let new_daily = spending_config
        .daily_spent
        .checked_add(amount)
        .ok_or(SpendingLimitError::MathOverflow)?;
    require!(
        new_daily <= spending_config.daily_limit,
        SpendingLimitError::DailyLimitExceeded
    );

    // Check weekly limit
    let new_weekly = spending_config
        .weekly_spent
        .checked_add(amount)
        .ok_or(SpendingLimitError::MathOverflow)?;
    require!(
        new_weekly <= spending_config.weekly_limit,
        SpendingLimitError::WeeklyLimitExceeded
    );

    // Check monthly limit
    let new_monthly = spending_config
        .monthly_spent
        .checked_add(amount)
        .ok_or(SpendingLimitError::MathOverflow)?;
    require!(
        new_monthly <= spending_config.monthly_limit,
        SpendingLimitError::MonthlyLimitExceeded
    );

    // Check whitelist if applicable
    if spending_config.whitelist_only || ctx.accounts.whitelist_entry.is_some() {
        validate_whitelist_entry(
            &ctx.accounts.whitelist_entry,
            &config_key,
            spending_config,
            &target,
        )?;
    }

    // Emit event with remaining amounts
    emit!(TransferValidated {
        config: config_key,
        target,
        amount,
        daily_remaining: spending_config.daily_limit.saturating_sub(new_daily),
        weekly_remaining: spending_config.weekly_limit.saturating_sub(new_weekly),
        monthly_remaining: spending_config.monthly_limit.saturating_sub(new_monthly),
    });

    msg!(
        "Transfer validated: {} lamports to {}, remaining: daily={}, weekly={}, monthly={}",
        amount,
        target,
        spending_config.daily_limit.saturating_sub(new_daily),
        spending_config.weekly_limit.saturating_sub(new_weekly),
        spending_config.monthly_limit.saturating_sub(new_monthly)
    );

    Ok(())
}

/// Validate whitelist entry
fn validate_whitelist_entry(
    whitelist_entry_account: &Option<UncheckedAccount>,
    config_key: &Pubkey,
    spending_config: &SpendingConfig,
    target: &Pubkey,
) -> Result<()> {
    match whitelist_entry_account {
        Some(account) => {
            // Verify the account is the correct PDA
            let config_key_bytes = config_key.to_bytes();
            let expected_seeds: &[&[u8]] = &[
                WHITELIST_SEED,
                &config_key_bytes,
                target.as_ref(),
            ];
            let (expected_pda, _bump) =
                Pubkey::find_program_address(expected_seeds, &crate::ID);

            require!(
                account.key() == expected_pda,
                SpendingLimitError::EntryNotFound
            );

            // Deserialize and check the entry
            if !account.data_is_empty() {
                let data = account.try_borrow_data()?;
                // Skip discriminator (8 bytes)
                if data.len() >= 8 + 32 + 32 + 1 + 1 {
                    let is_allowed = data[8 + 32 + 32] == 1;
                    let is_blacklisted = data[8 + 32 + 32 + 1] == 1;

                    // Blacklist always blocks
                    require!(
                        !is_blacklisted,
                        SpendingLimitError::TargetBlacklisted
                    );

                    // In whitelist mode, must be explicitly allowed
                    if spending_config.whitelist_only {
                        require!(
                            is_allowed,
                            SpendingLimitError::NotWhitelisted
                        );
                    }
                }
            }
        }
        None => {
            // No whitelist entry provided
            if spending_config.whitelist_only {
                return Err(SpendingLimitError::WhitelistRequired.into());
            }
        }
    }

    Ok(())
}

/// Accounts for read-only validation (no state changes)
#[derive(Accounts)]
#[instruction(amount: u64, target: Pubkey)]
pub struct CheckTransfer<'info> {
    /// The spending config PDA (read-only)
    #[account(
        seeds = [SPENDING_CONFIG_SEED, spending_config.authority.as_ref()],
        bump = spending_config.bump,
    )]
    pub spending_config: Account<'info, SpendingConfig>,

    /// Optional whitelist entry for the target
    /// CHECK: This account is optional and validated in the handler
    pub whitelist_entry: Option<UncheckedAccount<'info>>,
}

/// Check if a transfer would be allowed (read-only, no authority required)
///
/// This is a view-like function that checks limits without requiring
/// the authority signature. Useful for UIs to preview if a transfer would succeed.
///
/// # Arguments
/// * `ctx` - The instruction context
/// * `amount` - The transfer amount in lamports
/// * `target` - The target address
///
/// # Returns
/// * `Ok(())` if the transfer would be allowed (at current state)
pub fn handler_check(ctx: Context<CheckTransfer>, amount: u64, target: Pubkey) -> Result<()> {
    let spending_config = &ctx.accounts.spending_config;
    let clock = Clock::get()?;
    let current_slot = clock.slot;

    // Check if paused
    require!(!spending_config.is_paused, SpendingLimitError::ConfigPaused);

    // Calculate effective spent amounts (accounting for period resets)
    let effective_daily = if spending_config.should_reset_daily(current_slot) {
        0
    } else {
        spending_config.daily_spent
    };

    let effective_weekly = if spending_config.should_reset_weekly(current_slot) {
        0
    } else {
        spending_config.weekly_spent
    };

    let effective_monthly = if spending_config.should_reset_monthly(current_slot) {
        0
    } else {
        spending_config.monthly_spent
    };

    // Check per-transaction limit
    require!(
        amount <= spending_config.per_tx_limit,
        SpendingLimitError::PerTxLimitExceeded
    );

    // Check daily limit
    let new_daily = effective_daily
        .checked_add(amount)
        .ok_or(SpendingLimitError::MathOverflow)?;
    require!(
        new_daily <= spending_config.daily_limit,
        SpendingLimitError::DailyLimitExceeded
    );

    // Check weekly limit
    let new_weekly = effective_weekly
        .checked_add(amount)
        .ok_or(SpendingLimitError::MathOverflow)?;
    require!(
        new_weekly <= spending_config.weekly_limit,
        SpendingLimitError::WeeklyLimitExceeded
    );

    // Check monthly limit
    let new_monthly = effective_monthly
        .checked_add(amount)
        .ok_or(SpendingLimitError::MathOverflow)?;
    require!(
        new_monthly <= spending_config.monthly_limit,
        SpendingLimitError::MonthlyLimitExceeded
    );

    // Check whitelist if applicable
    if spending_config.whitelist_only || ctx.accounts.whitelist_entry.is_some() {
        let config_key = ctx.accounts.spending_config.key();
        validate_whitelist_entry(
            &ctx.accounts.whitelist_entry,
            &config_key,
            spending_config,
            &target,
        )?;
    }

    msg!(
        "Transfer check passed: {} lamports to {} is within limits",
        amount,
        target
    );

    Ok(())
}

/// Get remaining spending allowance
#[derive(Accounts)]
pub struct GetRemaining<'info> {
    /// The spending config PDA (read-only)
    #[account(
        seeds = [SPENDING_CONFIG_SEED, spending_config.authority.as_ref()],
        bump = spending_config.bump,
    )]
    pub spending_config: Account<'info, SpendingConfig>,
}

/// Return type for remaining allowance query
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct RemainingAllowance {
    pub per_tx_limit: u64,
    pub daily_remaining: u64,
    pub weekly_remaining: u64,
    pub monthly_remaining: u64,
    pub minimum_remaining: u64,
    pub is_paused: bool,
}

/// Get remaining spending allowance (read-only)
///
/// Returns the current remaining spending allowance across all periods.
/// This accounts for any period resets that would occur at the current slot.
pub fn handler_get_remaining(ctx: Context<GetRemaining>) -> Result<RemainingAllowance> {
    let spending_config = &ctx.accounts.spending_config;
    let clock = Clock::get()?;
    let current_slot = clock.slot;

    // Calculate effective spent amounts (accounting for period resets)
    let effective_daily = if spending_config.should_reset_daily(current_slot) {
        0
    } else {
        spending_config.daily_spent
    };

    let effective_weekly = if spending_config.should_reset_weekly(current_slot) {
        0
    } else {
        spending_config.weekly_spent
    };

    let effective_monthly = if spending_config.should_reset_monthly(current_slot) {
        0
    } else {
        spending_config.monthly_spent
    };

    let daily_remaining = spending_config.daily_limit.saturating_sub(effective_daily);
    let weekly_remaining = spending_config.weekly_limit.saturating_sub(effective_weekly);
    let monthly_remaining = spending_config.monthly_limit.saturating_sub(effective_monthly);
    let minimum_remaining = daily_remaining
        .min(weekly_remaining)
        .min(monthly_remaining)
        .min(spending_config.per_tx_limit);

    Ok(RemainingAllowance {
        per_tx_limit: spending_config.per_tx_limit,
        daily_remaining,
        weekly_remaining,
        monthly_remaining,
        minimum_remaining,
        is_paused: spending_config.is_paused,
    })
}
