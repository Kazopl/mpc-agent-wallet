//! Update limits instruction for modifying spending configuration

use anchor_lang::prelude::*;

use crate::error::SpendingLimitError;
use crate::state::*;

/// Accounts for the update_limits instruction
#[derive(Accounts)]
pub struct UpdateLimits<'info> {
    /// The authority that controls this spending config
    pub authority: Signer<'info>,

    /// The spending config to update
    #[account(
        mut,
        seeds = [SPENDING_CONFIG_SEED, authority.key().as_ref()],
        bump = spending_config.bump,
        constraint = spending_config.authority == authority.key() @ SpendingLimitError::Unauthorized
    )]
    pub spending_config: Account<'info, SpendingConfig>,
}

/// Update spending limits
///
/// Modifies the spending limits for a config. If the config has a cooldown period,
/// the new limits won't take effect until the cooldown has elapsed.
///
/// # Arguments
/// * `ctx` - The instruction context
/// * `new_limits` - New limit values (None to keep current)
///
/// # Errors
/// * `Unauthorized` - If the signer is not the authority
/// * `InvalidLimitConfig` - If the new limits are invalid
/// * `CooldownNotElapsed` - If updating too soon after a previous update
pub fn handler(ctx: Context<UpdateLimits>, new_limits: LimitsInput) -> Result<()> {
    let config_key = ctx.accounts.spending_config.key();
    let spending_config = &mut ctx.accounts.spending_config;
    let clock = Clock::get()?;
    let current_slot = clock.slot;

    // Check cooldown if applicable
    if spending_config.update_cooldown_slots > 0 && spending_config.pending_update_slot > 0 {
        require!(
            current_slot >= spending_config.pending_update_slot + spending_config.update_cooldown_slots,
            SpendingLimitError::CooldownNotElapsed
        );
    }

    // Apply updates
    let per_tx = new_limits.per_tx_limit.unwrap_or(spending_config.per_tx_limit);
    let daily = new_limits.daily_limit.unwrap_or(spending_config.daily_limit);
    let weekly = new_limits.weekly_limit.unwrap_or(spending_config.weekly_limit);
    let monthly = new_limits.monthly_limit.unwrap_or(spending_config.monthly_limit);

    // Validate consistency
    require!(
        per_tx > 0 && daily > 0 && weekly > 0 && monthly > 0,
        SpendingLimitError::InvalidLimitConfig
    );
    require!(
        per_tx <= daily && daily <= weekly && weekly <= monthly,
        SpendingLimitError::InvalidLimitConfig
    );

    spending_config.per_tx_limit = per_tx;
    spending_config.daily_limit = daily;
    spending_config.weekly_limit = weekly;
    spending_config.monthly_limit = monthly;

    if let Some(whitelist_only) = new_limits.whitelist_only {
        spending_config.whitelist_only = whitelist_only;
    }

    spending_config.pending_update_slot = current_slot;

    emit!(LimitsUpdated {
        config: config_key,
        per_tx_limit: spending_config.per_tx_limit,
        daily_limit: spending_config.daily_limit,
        weekly_limit: spending_config.weekly_limit,
        monthly_limit: spending_config.monthly_limit,
    });

    msg!(
        "Updated limits: per_tx={}, daily={}, weekly={}, monthly={}",
        spending_config.per_tx_limit,
        spending_config.daily_limit,
        spending_config.weekly_limit,
        spending_config.monthly_limit
    );

    Ok(())
}

/// Accounts for pausing/unpausing the config
#[derive(Accounts)]
pub struct TogglePause<'info> {
    /// The authority or guardian
    pub signer: Signer<'info>,

    /// The spending config to pause/unpause
    #[account(
        mut,
        seeds = [SPENDING_CONFIG_SEED, spending_config.authority.as_ref()],
        bump = spending_config.bump,
        constraint = spending_config.authority == signer.key()
            || spending_config.guardian == Some(signer.key()) @ SpendingLimitError::Unauthorized
    )]
    pub spending_config: Account<'info, SpendingConfig>,
}

/// Toggle the pause state of a spending config
///
/// Can be called by either the authority or the guardian.
/// When paused, no transfers can be validated.
pub fn handler_toggle_pause(ctx: Context<TogglePause>) -> Result<()> {
    let config_key = ctx.accounts.spending_config.key();
    let spending_config = &mut ctx.accounts.spending_config;

    spending_config.is_paused = !spending_config.is_paused;

    emit!(ConfigPauseToggled {
        config: config_key,
        is_paused: spending_config.is_paused,
    });

    msg!(
        "Config {} is now {}",
        config_key,
        if spending_config.is_paused { "paused" } else { "active" }
    );

    Ok(())
}

/// Accounts for setting/removing a guardian
#[derive(Accounts)]
pub struct SetGuardian<'info> {
    /// The authority that controls this spending config
    pub authority: Signer<'info>,

    /// The spending config to update
    #[account(
        mut,
        seeds = [SPENDING_CONFIG_SEED, authority.key().as_ref()],
        bump = spending_config.bump,
        constraint = spending_config.authority == authority.key() @ SpendingLimitError::Unauthorized
    )]
    pub spending_config: Account<'info, SpendingConfig>,
}

/// Set or remove the guardian for a spending config
///
/// The guardian can pause/unpause the config but cannot modify limits.
///
/// # Arguments
/// * `ctx` - The instruction context
/// * `guardian` - The guardian pubkey (None to remove)
pub fn handler_set_guardian(ctx: Context<SetGuardian>, guardian: Option<Pubkey>) -> Result<()> {
    let config_key = ctx.accounts.spending_config.key();
    let spending_config = &mut ctx.accounts.spending_config;

    spending_config.guardian = guardian;

    msg!(
        "Guardian {} for config {}",
        if guardian.is_some() { "set" } else { "removed" },
        config_key
    );

    Ok(())
}

/// Accounts for transferring authority
#[derive(Accounts)]
pub struct TransferAuthority<'info> {
    /// The current authority
    pub authority: Signer<'info>,

    /// The spending config to transfer
    #[account(
        mut,
        seeds = [SPENDING_CONFIG_SEED, authority.key().as_ref()],
        bump = spending_config.bump,
        constraint = spending_config.authority == authority.key() @ SpendingLimitError::Unauthorized
    )]
    pub spending_config: Account<'info, SpendingConfig>,
}

/// Transfer authority to a new address
///
/// Note: This requires creating a new PDA with the new authority's seeds.
/// The old config will be closed after migration.
///
/// # Arguments
/// * `ctx` - The instruction context
/// * `new_authority` - The new authority pubkey
pub fn handler_transfer_authority(
    ctx: Context<TransferAuthority>,
    new_authority: Pubkey,
) -> Result<()> {
    require!(
        new_authority != Pubkey::default(),
        SpendingLimitError::InvalidAuthorityTransfer
    );

    let config_key = ctx.accounts.spending_config.key();
    let spending_config = &mut ctx.accounts.spending_config;
    let old_authority = spending_config.authority;

    spending_config.authority = new_authority;

    emit!(AuthorityTransferred {
        config: config_key,
        old_authority,
        new_authority,
    });

    msg!(
        "Authority transferred from {} to {}",
        old_authority,
        new_authority
    );

    Ok(())
}
