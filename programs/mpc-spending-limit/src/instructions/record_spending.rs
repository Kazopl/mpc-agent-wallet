//! Record spending instruction for updating counters after transfers

use anchor_lang::prelude::*;

use crate::error::SpendingLimitError;
use crate::state::*;

/// Accounts for the record_spending instruction
#[derive(Accounts)]
pub struct RecordSpending<'info> {
    /// The authority recording the spending
    pub authority: Signer<'info>,

    /// The spending config PDA
    #[account(
        mut,
        seeds = [SPENDING_CONFIG_SEED, authority.key().as_ref()],
        bump = spending_config.bump,
        constraint = spending_config.authority == authority.key() @ SpendingLimitError::Unauthorized
    )]
    pub spending_config: Account<'info, SpendingConfig>,
}

/// Record a completed transfer
///
/// Updates the spending counters after a transfer has been executed.
/// This should be called after the actual SOL/token transfer to track spending.
///
/// # Arguments
/// * `ctx` - The instruction context
/// * `amount` - The transfer amount in lamports
///
/// # Errors
/// * `Unauthorized` - If the signer is not the authority
/// * `ConfigPaused` - If the config is paused
/// * `MathOverflow` - If counters overflow
pub fn handler(ctx: Context<RecordSpending>, amount: u64) -> Result<()> {
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

    // Update counters
    spending_config.daily_spent = spending_config
        .daily_spent
        .checked_add(amount)
        .ok_or(SpendingLimitError::MathOverflow)?;

    spending_config.weekly_spent = spending_config
        .weekly_spent
        .checked_add(amount)
        .ok_or(SpendingLimitError::MathOverflow)?;

    spending_config.monthly_spent = spending_config
        .monthly_spent
        .checked_add(amount)
        .ok_or(SpendingLimitError::MathOverflow)?;

    emit!(SpendingRecorded {
        config: config_key,
        target: Pubkey::default(), // Target not tracked in this simple version
        amount,
        daily_spent: spending_config.daily_spent,
        weekly_spent: spending_config.weekly_spent,
        monthly_spent: spending_config.monthly_spent,
    });

    msg!(
        "Recorded spending: {} lamports, totals: daily={}, weekly={}, monthly={}",
        amount,
        spending_config.daily_spent,
        spending_config.weekly_spent,
        spending_config.monthly_spent
    );

    Ok(())
}

/// Accounts for recording spending with target tracking
#[derive(Accounts)]
#[instruction(amount: u64, target: Pubkey)]
pub struct RecordSpendingWithTarget<'info> {
    /// The authority recording the spending
    pub authority: Signer<'info>,

    /// The spending config PDA
    #[account(
        mut,
        seeds = [SPENDING_CONFIG_SEED, authority.key().as_ref()],
        bump = spending_config.bump,
        constraint = spending_config.authority == authority.key() @ SpendingLimitError::Unauthorized
    )]
    pub spending_config: Account<'info, SpendingConfig>,
}

/// Record a completed transfer with target information
///
/// Similar to `record_spending` but also emits the target address in events.
///
/// # Arguments
/// * `ctx` - The instruction context
/// * `amount` - The transfer amount in lamports
/// * `target` - The target address (for event emission)
pub fn handler_with_target(
    ctx: Context<RecordSpendingWithTarget>,
    amount: u64,
    target: Pubkey,
) -> Result<()> {
    let config_key = ctx.accounts.spending_config.key();
    let spending_config = &mut ctx.accounts.spending_config;
    let clock = Clock::get()?;
    let current_slot = clock.slot;

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

    // Update counters
    spending_config.daily_spent = spending_config
        .daily_spent
        .checked_add(amount)
        .ok_or(SpendingLimitError::MathOverflow)?;

    spending_config.weekly_spent = spending_config
        .weekly_spent
        .checked_add(amount)
        .ok_or(SpendingLimitError::MathOverflow)?;

    spending_config.monthly_spent = spending_config
        .monthly_spent
        .checked_add(amount)
        .ok_or(SpendingLimitError::MathOverflow)?;

    emit!(SpendingRecorded {
        config: config_key,
        target,
        amount,
        daily_spent: spending_config.daily_spent,
        weekly_spent: spending_config.weekly_spent,
        monthly_spent: spending_config.monthly_spent,
    });

    msg!(
        "Recorded spending: {} lamports to {}, totals: daily={}, weekly={}, monthly={}",
        amount,
        target,
        spending_config.daily_spent,
        spending_config.weekly_spent,
        spending_config.monthly_spent
    );

    Ok(())
}

/// Accounts for validating and recording in one instruction
#[derive(Accounts)]
#[instruction(amount: u64, target: Pubkey)]
pub struct ValidateAndRecord<'info> {
    /// The authority
    pub authority: Signer<'info>,

    /// The spending config PDA
    #[account(
        mut,
        seeds = [SPENDING_CONFIG_SEED, authority.key().as_ref()],
        bump = spending_config.bump,
        constraint = spending_config.authority == authority.key() @ SpendingLimitError::Unauthorized
    )]
    pub spending_config: Account<'info, SpendingConfig>,

    /// Optional whitelist entry for the target
    /// CHECK: This account is optional and validated in the handler
    pub whitelist_entry: Option<UncheckedAccount<'info>>,
}

/// Validate and record a transfer in a single instruction
///
/// Combines validation and recording for atomic operations.
/// This is the recommended approach for most use cases.
///
/// # Arguments
/// * `ctx` - The instruction context
/// * `amount` - The transfer amount in lamports
/// * `target` - The target address
pub fn handler_validate_and_record(
    ctx: Context<ValidateAndRecord>,
    amount: u64,
    target: Pubkey,
) -> Result<()> {
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
    if spending_config.whitelist_only {
        match &ctx.accounts.whitelist_entry {
            Some(account) => {
                // Verify PDA
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

                // Check entry
                if !account.data_is_empty() {
                    let data = account.try_borrow_data()?;
                    if data.len() >= 8 + 32 + 32 + 1 + 1 {
                        let is_allowed = data[8 + 32 + 32] == 1;
                        let is_blacklisted = data[8 + 32 + 32 + 1] == 1;

                        require!(!is_blacklisted, SpendingLimitError::TargetBlacklisted);
                        require!(is_allowed, SpendingLimitError::NotWhitelisted);
                    }
                }
            }
            None => {
                return Err(SpendingLimitError::WhitelistRequired.into());
            }
        }
    }

    // Update counters
    spending_config.daily_spent = new_daily;
    spending_config.weekly_spent = new_weekly;
    spending_config.monthly_spent = new_monthly;

    // Emit both events
    emit!(TransferValidated {
        config: config_key,
        target,
        amount,
        daily_remaining: spending_config.daily_limit.saturating_sub(new_daily),
        weekly_remaining: spending_config.weekly_limit.saturating_sub(new_weekly),
        monthly_remaining: spending_config.monthly_limit.saturating_sub(new_monthly),
    });

    emit!(SpendingRecorded {
        config: config_key,
        target,
        amount,
        daily_spent: new_daily,
        weekly_spent: new_weekly,
        monthly_spent: new_monthly,
    });

    msg!(
        "Validated and recorded: {} lamports to {}, totals: daily={}, weekly={}, monthly={}",
        amount,
        target,
        new_daily,
        new_weekly,
        new_monthly
    );

    Ok(())
}

/// Accounts for resetting spending counters (emergency)
#[derive(Accounts)]
pub struct ResetCounters<'info> {
    /// The authority or guardian
    pub signer: Signer<'info>,

    /// The spending config PDA
    #[account(
        mut,
        seeds = [SPENDING_CONFIG_SEED, spending_config.authority.as_ref()],
        bump = spending_config.bump,
        constraint = spending_config.authority == signer.key()
            || spending_config.guardian == Some(signer.key()) @ SpendingLimitError::Unauthorized
    )]
    pub spending_config: Account<'info, SpendingConfig>,
}

/// Reset spending counters
///
/// Can be used by authority or guardian to reset all spending counters.
/// This is useful for emergency situations or config migration.
///
/// # Arguments
/// * `ctx` - The instruction context
/// * `reset_daily` - Whether to reset daily counter
/// * `reset_weekly` - Whether to reset weekly counter
/// * `reset_monthly` - Whether to reset monthly counter
pub fn handler_reset_counters(
    ctx: Context<ResetCounters>,
    reset_daily: bool,
    reset_weekly: bool,
    reset_monthly: bool,
) -> Result<()> {
    let spending_config = &mut ctx.accounts.spending_config;
    let clock = Clock::get()?;
    let current_slot = clock.slot;

    if reset_daily {
        spending_config.reset_daily(current_slot);
        msg!("Reset daily counter");
    }

    if reset_weekly {
        spending_config.reset_weekly(current_slot);
        msg!("Reset weekly counter");
    }

    if reset_monthly {
        spending_config.reset_monthly(current_slot);
        msg!("Reset monthly counter");
    }

    Ok(())
}
