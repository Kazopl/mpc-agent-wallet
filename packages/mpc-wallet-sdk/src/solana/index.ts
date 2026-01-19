/**
 * Solana-specific modules for MPC Wallet SDK
 *
 * This module provides Solana-specific functionality including:
 * - Spending limits with on-chain enforcement
 * - PDA-based configuration management
 * - Whitelist/blacklist management
 */

export {
  // Main class
  SolanaSpendingLimits,

  // Constants
  MPC_SPENDING_LIMIT_PROGRAM_ID,
  SPENDING_CONFIG_SEED,
  WHITELIST_SEED,
  SLOTS_PER_DAY,
  SLOTS_PER_WEEK,
  SLOTS_PER_MONTH,

  // Network presets
  SolanaLimitNetworks,

  // Types
  type SolanaNetwork,
  type SpendingConfig,
  type SpendingState,
  type RemainingAllowance,
  type WhitelistEntry,
  type UpdateLimitsOptions,
  type SolanaSpendingLimitsConfig,
  type TransactionResult,

  // Errors
  SpendingLimitError,
  SpendingLimitErrorCode,
} from './spending-limit';
