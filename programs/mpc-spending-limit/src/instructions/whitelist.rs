//! Whitelist management instructions

use anchor_lang::prelude::*;

use crate::error::SpendingLimitError;
use crate::state::*;

/// Accounts for adding a whitelist entry
#[derive(Accounts)]
#[instruction(target: Pubkey)]
pub struct AddToWhitelist<'info> {
    /// The authority that controls this spending config
    #[account(mut)]
    pub authority: Signer<'info>,

    /// The spending config
    #[account(
        mut,
        seeds = [SPENDING_CONFIG_SEED, authority.key().as_ref()],
        bump = spending_config.bump,
        constraint = spending_config.authority == authority.key() @ SpendingLimitError::Unauthorized
    )]
    pub spending_config: Account<'info, SpendingConfig>,

    /// The whitelist entry PDA to create
    #[account(
        init,
        payer = authority,
        space = WhitelistEntry::SIZE,
        seeds = [WHITELIST_SEED, spending_config.key().as_ref(), target.as_ref()],
        bump
    )]
    pub whitelist_entry: Account<'info, WhitelistEntry>,

    /// System program for account creation
    pub system_program: Program<'info, System>,
}

/// Add an address to the whitelist
///
/// Creates a PDA for the whitelist entry. The entry can be set as either
/// a whitelist (allowed) or blacklist (blocked) entry.
///
/// # Arguments
/// * `ctx` - The instruction context
/// * `target` - The target address to whitelist
/// * `is_blacklisted` - If true, this is a blacklist entry
/// * `label` - Optional label for the entry (up to 32 bytes)
pub fn handler_add_to_whitelist(
    ctx: Context<AddToWhitelist>,
    target: Pubkey,
    is_blacklisted: bool,
    label: Option<[u8; 32]>,
) -> Result<()> {
    let config_key = ctx.accounts.spending_config.key();
    let spending_config = &mut ctx.accounts.spending_config;
    let whitelist_entry = &mut ctx.accounts.whitelist_entry;
    let clock = Clock::get()?;

    // Check whitelist capacity
    require!(
        spending_config.whitelist_count < MAX_WHITELIST_ENTRIES,
        SpendingLimitError::WhitelistFull
    );

    // Initialize whitelist entry
    whitelist_entry.config = config_key;
    whitelist_entry.target = target;
    whitelist_entry.is_allowed = !is_blacklisted;
    whitelist_entry.is_blacklisted = is_blacklisted;
    whitelist_entry.label = label.unwrap_or([0u8; 32]);
    whitelist_entry.created_at = clock.slot;
    whitelist_entry.updated_at = clock.slot;
    whitelist_entry.bump = ctx.bumps.whitelist_entry;
    whitelist_entry._reserved = [0u8; 16];

    // Increment whitelist count
    spending_config.whitelist_count = spending_config
        .whitelist_count
        .checked_add(1)
        .ok_or(SpendingLimitError::MathOverflow)?;

    emit!(WhitelistAdded {
        config: config_key,
        target,
        is_blacklisted,
    });

    msg!(
        "Added {} to {} for config {}",
        target,
        if is_blacklisted { "blacklist" } else { "whitelist" },
        config_key
    );

    Ok(())
}

/// Accounts for removing a whitelist entry
#[derive(Accounts)]
#[instruction(target: Pubkey)]
pub struct RemoveFromWhitelist<'info> {
    /// The authority that controls this spending config
    #[account(mut)]
    pub authority: Signer<'info>,

    /// The spending config
    #[account(
        mut,
        seeds = [SPENDING_CONFIG_SEED, authority.key().as_ref()],
        bump = spending_config.bump,
        constraint = spending_config.authority == authority.key() @ SpendingLimitError::Unauthorized
    )]
    pub spending_config: Account<'info, SpendingConfig>,

    /// The whitelist entry PDA to close
    #[account(
        mut,
        close = authority,
        seeds = [WHITELIST_SEED, spending_config.key().as_ref(), target.as_ref()],
        bump = whitelist_entry.bump,
        constraint = whitelist_entry.config == spending_config.key() @ SpendingLimitError::EntryNotFound
    )]
    pub whitelist_entry: Account<'info, WhitelistEntry>,
}

/// Remove an address from the whitelist
///
/// Closes the whitelist entry PDA and returns the rent to the authority.
///
/// # Arguments
/// * `ctx` - The instruction context
/// * `target` - The target address to remove
pub fn handler_remove_from_whitelist(
    ctx: Context<RemoveFromWhitelist>,
    target: Pubkey,
) -> Result<()> {
    let config_key = ctx.accounts.spending_config.key();
    let spending_config = &mut ctx.accounts.spending_config;

    // Decrement whitelist count
    spending_config.whitelist_count = spending_config
        .whitelist_count
        .checked_sub(1)
        .ok_or(SpendingLimitError::MathOverflow)?;

    emit!(WhitelistRemoved {
        config: config_key,
        target,
    });

    msg!(
        "Removed {} from whitelist for config {}",
        target,
        config_key
    );

    Ok(())
}

/// Accounts for updating a whitelist entry
#[derive(Accounts)]
#[instruction(target: Pubkey)]
pub struct UpdateWhitelistEntry<'info> {
    /// The authority that controls this spending config
    pub authority: Signer<'info>,

    /// The spending config
    #[account(
        seeds = [SPENDING_CONFIG_SEED, authority.key().as_ref()],
        bump = spending_config.bump,
        constraint = spending_config.authority == authority.key() @ SpendingLimitError::Unauthorized
    )]
    pub spending_config: Account<'info, SpendingConfig>,

    /// The whitelist entry PDA to update
    #[account(
        mut,
        seeds = [WHITELIST_SEED, spending_config.key().as_ref(), target.as_ref()],
        bump = whitelist_entry.bump,
        constraint = whitelist_entry.config == spending_config.key() @ SpendingLimitError::EntryNotFound
    )]
    pub whitelist_entry: Account<'info, WhitelistEntry>,
}

/// Update a whitelist entry
///
/// Modifies the allowed/blacklisted status or label of an existing entry.
///
/// # Arguments
/// * `ctx` - The instruction context
/// * `target` - The target address (for PDA derivation)
/// * `is_allowed` - New allowed status (None to keep current)
/// * `is_blacklisted` - New blacklist status (None to keep current)
/// * `label` - New label (None to keep current)
pub fn handler_update_whitelist_entry(
    ctx: Context<UpdateWhitelistEntry>,
    _target: Pubkey,
    is_allowed: Option<bool>,
    is_blacklisted: Option<bool>,
    label: Option<[u8; 32]>,
) -> Result<()> {
    let whitelist_entry = &mut ctx.accounts.whitelist_entry;
    let clock = Clock::get()?;

    if let Some(allowed) = is_allowed {
        whitelist_entry.is_allowed = allowed;
    }

    if let Some(blacklisted) = is_blacklisted {
        whitelist_entry.is_blacklisted = blacklisted;
    }

    if let Some(new_label) = label {
        whitelist_entry.label = new_label;
    }

    whitelist_entry.updated_at = clock.slot;

    msg!(
        "Updated whitelist entry for target {}",
        whitelist_entry.target
    );

    Ok(())
}

/// Accounts for batch whitelist operations
#[derive(Accounts)]
pub struct BatchWhitelist<'info> {
    /// The authority that controls this spending config
    #[account(mut)]
    pub authority: Signer<'info>,

    /// The spending config
    #[account(
        mut,
        seeds = [SPENDING_CONFIG_SEED, authority.key().as_ref()],
        bump = spending_config.bump,
        constraint = spending_config.authority == authority.key() @ SpendingLimitError::Unauthorized
    )]
    pub spending_config: Account<'info, SpendingConfig>,

    /// System program for account creation
    pub system_program: Program<'info, System>,
}

/// Input for batch whitelist operations
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct BatchWhitelistInput {
    pub target: Pubkey,
    pub is_blacklisted: bool,
    pub label: Option<[u8; 32]>,
}
