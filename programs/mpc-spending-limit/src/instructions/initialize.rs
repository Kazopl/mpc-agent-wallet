//! Initialize instruction for creating a new spending config

use anchor_lang::prelude::*;

use crate::error::SpendingLimitError;
use crate::state::*;

/// Accounts for the initialize instruction
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The authority that will control this spending config
    #[account(mut)]
    pub authority: Signer<'info>,

    /// The spending config PDA to initialize
    #[account(
        init,
        payer = authority,
        space = SpendingConfig::SIZE,
        seeds = [SPENDING_CONFIG_SEED, authority.key().as_ref()],
        bump
    )]
    pub spending_config: Account<'info, SpendingConfig>,

    /// System program for account creation
    pub system_program: Program<'info, System>,
}

/// Initialize a new spending configuration
///
/// Creates a PDA that stores spending limits for an MPC wallet.
/// The authority (usually the MPC wallet address) controls all config updates.
///
/// # Arguments
/// * `ctx` - The instruction context
/// * `config_input` - Initial configuration parameters
///
/// # Errors
/// * `InvalidLimitConfig` - If the limit configuration is invalid
pub fn handler(ctx: Context<Initialize>, config_input: SpendingConfigInput) -> Result<()> {
    // Validate input
    require!(config_input.validate(), SpendingLimitError::InvalidLimitConfig);

    let config_key = ctx.accounts.spending_config.key();
    let spending_config = &mut ctx.accounts.spending_config;
    let clock = Clock::get()?;
    let current_slot = clock.slot;

    // Initialize the spending config
    spending_config.authority = ctx.accounts.authority.key();
    spending_config.guardian = None;
    spending_config.per_tx_limit = config_input.per_tx_limit;
    spending_config.daily_limit = config_input.daily_limit;
    spending_config.weekly_limit = config_input.weekly_limit;
    spending_config.monthly_limit = config_input.monthly_limit;
    spending_config.daily_spent = 0;
    spending_config.weekly_spent = 0;
    spending_config.monthly_spent = 0;
    spending_config.daily_reset_slot = current_slot + SLOTS_PER_DAY;
    spending_config.weekly_reset_slot = current_slot + SLOTS_PER_WEEK;
    spending_config.monthly_reset_slot = current_slot + SLOTS_PER_MONTH;
    spending_config.whitelist_only = config_input.whitelist_only;
    spending_config.is_paused = false;
    spending_config.whitelist_count = 0;
    spending_config.update_cooldown_slots = config_input.update_cooldown_slots;
    spending_config.pending_update_slot = 0;
    spending_config.bump = ctx.bumps.spending_config;
    spending_config._reserved = [0u8; 64];

    // Emit event
    emit!(ConfigInitialized {
        config: config_key,
        authority: spending_config.authority,
        per_tx_limit: spending_config.per_tx_limit,
        daily_limit: spending_config.daily_limit,
        weekly_limit: spending_config.weekly_limit,
        monthly_limit: spending_config.monthly_limit,
    });

    msg!(
        "Initialized spending config for authority {} with limits: per_tx={}, daily={}, weekly={}, monthly={}",
        spending_config.authority,
        spending_config.per_tx_limit,
        spending_config.daily_limit,
        spending_config.weekly_limit,
        spending_config.monthly_limit
    );

    Ok(())
}

/// Accounts for initializing with a custom authority
#[derive(Accounts)]
#[instruction(authority: Pubkey)]
pub struct InitializeFor<'info> {
    /// The payer for account creation
    #[account(mut)]
    pub payer: Signer<'info>,

    /// The spending config PDA to initialize
    #[account(
        init,
        payer = payer,
        space = SpendingConfig::SIZE,
        seeds = [SPENDING_CONFIG_SEED, authority.as_ref()],
        bump
    )]
    pub spending_config: Account<'info, SpendingConfig>,

    /// System program for account creation
    pub system_program: Program<'info, System>,
}

/// Initialize a spending config for a specific authority
///
/// Allows creating a config for an authority that may not be present as a signer.
/// This is useful when the MPC wallet address is known but not yet operational.
///
/// # Arguments
/// * `ctx` - The instruction context
/// * `authority` - The authority pubkey to set
/// * `config_input` - Initial configuration parameters
pub fn handler_for(
    ctx: Context<InitializeFor>,
    authority: Pubkey,
    config_input: SpendingConfigInput,
) -> Result<()> {
    require!(config_input.validate(), SpendingLimitError::InvalidLimitConfig);

    let config_key = ctx.accounts.spending_config.key();
    let spending_config = &mut ctx.accounts.spending_config;
    let clock = Clock::get()?;
    let current_slot = clock.slot;

    spending_config.authority = authority;
    spending_config.guardian = None;
    spending_config.per_tx_limit = config_input.per_tx_limit;
    spending_config.daily_limit = config_input.daily_limit;
    spending_config.weekly_limit = config_input.weekly_limit;
    spending_config.monthly_limit = config_input.monthly_limit;
    spending_config.daily_spent = 0;
    spending_config.weekly_spent = 0;
    spending_config.monthly_spent = 0;
    spending_config.daily_reset_slot = current_slot + SLOTS_PER_DAY;
    spending_config.weekly_reset_slot = current_slot + SLOTS_PER_WEEK;
    spending_config.monthly_reset_slot = current_slot + SLOTS_PER_MONTH;
    spending_config.whitelist_only = config_input.whitelist_only;
    spending_config.is_paused = false;
    spending_config.whitelist_count = 0;
    spending_config.update_cooldown_slots = config_input.update_cooldown_slots;
    spending_config.pending_update_slot = 0;
    spending_config.bump = ctx.bumps.spending_config;
    spending_config._reserved = [0u8; 64];

    emit!(ConfigInitialized {
        config: config_key,
        authority: spending_config.authority,
        per_tx_limit: spending_config.per_tx_limit,
        daily_limit: spending_config.daily_limit,
        weekly_limit: spending_config.weekly_limit,
        monthly_limit: spending_config.monthly_limit,
    });

    msg!(
        "Initialized spending config for authority {} (paid by {})",
        authority,
        ctx.accounts.payer.key()
    );

    Ok(())
}
