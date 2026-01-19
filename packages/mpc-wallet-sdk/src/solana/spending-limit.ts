/**
 * Solana Spending Limits SDK
 *
 * TypeScript SDK for interacting with the MPC Spending Limit Solana program.
 * Provides on-chain enforcement of spending limits for MPC wallets.
 *
 * @example
 * ```typescript
 * import { SolanaSpendingLimits, SolanaNetworks } from '@mpc-wallet/sdk';
 *
 * const limits = new SolanaSpendingLimits({
 *   network: SolanaNetworks.DEVNET,
 *   authority: walletPublicKey,
 * });
 *
 * // Initialize spending config
 * await limits.initialize({
 *   perTxLimit: 1_000_000_000n,  // 1 SOL
 *   dailyLimit: 10_000_000_000n, // 10 SOL
 *   weeklyLimit: 50_000_000_000n,
 *   monthlyLimit: 100_000_000_000n,
 * });
 *
 * // Validate before transfer
 * const isValid = await limits.validateTransfer(amount, targetPubkey);
 *
 * // Get remaining allowance
 * const remaining = await limits.getRemaining();
 * ```
 */

// ============================================================================
// Constants
// ============================================================================

/** Program ID for the MPC Spending Limit program */
export const MPC_SPENDING_LIMIT_PROGRAM_ID =
  'MpcSLim1t1111111111111111111111111111111111';

/** Seed for SpendingConfig PDA */
export const SPENDING_CONFIG_SEED = 'spending_config';

/** Seed for WhitelistEntry PDA */
export const WHITELIST_SEED = 'whitelist';

/** Approximate slots per day (assuming 400ms slot time) */
export const SLOTS_PER_DAY = 216_000n;

/** Approximate slots per week */
export const SLOTS_PER_WEEK = SLOTS_PER_DAY * 7n;

/** Approximate slots per month (30 days) */
export const SLOTS_PER_MONTH = SLOTS_PER_DAY * 30n;

// ============================================================================
// Types
// ============================================================================

/**
 * Network configuration for Solana
 */
export interface SolanaNetwork {
  name: string;
  rpcUrl: string;
  commitment: 'processed' | 'confirmed' | 'finalized';
}

/**
 * Pre-configured Solana networks
 */
export const SolanaLimitNetworks = {
  MAINNET: {
    name: 'Solana Mainnet',
    rpcUrl: 'https://api.mainnet-beta.solana.com',
    commitment: 'confirmed' as const,
  },
  DEVNET: {
    name: 'Solana Devnet',
    rpcUrl: 'https://api.devnet.solana.com',
    commitment: 'confirmed' as const,
  },
  TESTNET: {
    name: 'Solana Testnet',
    rpcUrl: 'https://api.testnet.solana.com',
    commitment: 'confirmed' as const,
  },
} as const;

/**
 * Configuration for initializing spending limits
 */
export interface SpendingConfig {
  /** Maximum amount per single transaction (in lamports) */
  perTxLimit: bigint;
  /** Maximum daily spending (in lamports) */
  dailyLimit: bigint;
  /** Maximum weekly spending (in lamports) */
  weeklyLimit: bigint;
  /** Maximum monthly spending (in lamports) */
  monthlyLimit: bigint;
  /** Whether whitelist mode is enabled (only allow whitelisted targets) */
  whitelistOnly?: boolean;
  /** Cooldown slots before limit updates take effect (0 for no cooldown) */
  updateCooldownSlots?: bigint;
}

/**
 * Current state of spending limits
 */
export interface SpendingState {
  /** Authority pubkey */
  authority: string;
  /** Guardian pubkey (if set) */
  guardian: string | null;
  /** Maximum per-transaction limit */
  perTxLimit: bigint;
  /** Daily limit */
  dailyLimit: bigint;
  /** Weekly limit */
  weeklyLimit: bigint;
  /** Monthly limit */
  monthlyLimit: bigint;
  /** Current daily spending */
  dailySpent: bigint;
  /** Current weekly spending */
  weeklySpent: bigint;
  /** Current monthly spending */
  monthlySpent: bigint;
  /** Slot when daily counter resets */
  dailyResetSlot: bigint;
  /** Slot when weekly counter resets */
  weeklyResetSlot: bigint;
  /** Slot when monthly counter resets */
  monthlyResetSlot: bigint;
  /** Whether whitelist mode is enabled */
  whitelistOnly: boolean;
  /** Whether the config is paused */
  isPaused: boolean;
  /** Number of whitelist entries */
  whitelistCount: number;
}

/**
 * Remaining spending allowance
 */
export interface RemainingAllowance {
  /** Per-transaction limit */
  perTxLimit: bigint;
  /** Remaining daily allowance */
  daily: bigint;
  /** Remaining weekly allowance */
  weekly: bigint;
  /** Remaining monthly allowance */
  monthly: bigint;
  /** Minimum remaining across all periods */
  minimum: bigint;
  /** Whether config is paused */
  isPaused: boolean;
}

/**
 * Whitelist entry
 */
export interface WhitelistEntry {
  /** Target address */
  target: string;
  /** Whether this target is allowed */
  isAllowed: boolean;
  /** Whether this is a blacklist entry */
  isBlacklisted: boolean;
  /** Label for the entry */
  label: string;
  /** When the entry was created (slot) */
  createdAt: bigint;
  /** When the entry was last updated (slot) */
  updatedAt: bigint;
}

/**
 * Options for updating spending limits
 */
export interface UpdateLimitsOptions {
  /** New per-transaction limit (undefined to keep current) */
  perTxLimit?: bigint;
  /** New daily limit (undefined to keep current) */
  dailyLimit?: bigint;
  /** New weekly limit (undefined to keep current) */
  weeklyLimit?: bigint;
  /** New monthly limit (undefined to keep current) */
  monthlyLimit?: bigint;
  /** New whitelist mode (undefined to keep current) */
  whitelistOnly?: boolean;
}

/**
 * Configuration for SolanaSpendingLimits
 */
export interface SolanaSpendingLimitsConfig {
  /** Network configuration or preset */
  network: SolanaNetwork;
  /** Authority public key (base58 string) */
  authority: string;
  /** Custom program ID (defaults to deployed program) */
  programId?: string;
}

/**
 * Transaction result
 */
export interface TransactionResult {
  /** Transaction signature */
  signature: string;
  /** Whether the transaction was confirmed */
  confirmed: boolean;
  /** Slot at which the transaction was confirmed */
  slot?: number;
}

// ============================================================================
// Errors
// ============================================================================

/**
 * Errors that can occur in spending limit operations
 */
export class SpendingLimitError extends Error {
  constructor(
    public code: SpendingLimitErrorCode,
    message: string
  ) {
    super(message);
    this.name = 'SpendingLimitError';
  }
}

export enum SpendingLimitErrorCode {
  PerTxLimitExceeded = 'PER_TX_LIMIT_EXCEEDED',
  DailyLimitExceeded = 'DAILY_LIMIT_EXCEEDED',
  WeeklyLimitExceeded = 'WEEKLY_LIMIT_EXCEEDED',
  MonthlyLimitExceeded = 'MONTHLY_LIMIT_EXCEEDED',
  NotWhitelisted = 'NOT_WHITELISTED',
  WhitelistRequired = 'WHITELIST_REQUIRED',
  TargetBlacklisted = 'TARGET_BLACKLISTED',
  Unauthorized = 'UNAUTHORIZED',
  InvalidConfig = 'INVALID_CONFIG',
  ConfigPaused = 'CONFIG_PAUSED',
  ConfigNotFound = 'CONFIG_NOT_FOUND',
  RpcError = 'RPC_ERROR',
  TransactionFailed = 'TRANSACTION_FAILED',
}

// ============================================================================
// SolanaSpendingLimits Class
// ============================================================================

/**
 * SDK for managing Solana spending limits
 *
 * Provides methods to initialize, configure, and validate spending limits
 * using the on-chain MPC Spending Limit program.
 */
export class SolanaSpendingLimits {
  private readonly network: SolanaNetwork;
  private readonly authority: string;
  private readonly programId: string;
  private configPda: string | null = null;

  constructor(config: SolanaSpendingLimitsConfig) {
    this.network = config.network;
    this.authority = config.authority;
    this.programId = config.programId ?? MPC_SPENDING_LIMIT_PROGRAM_ID;
  }

  // ==========================================================================
  // PDA Derivation
  // ==========================================================================

  /**
   * Derive the spending config PDA for an authority
   */
  async deriveConfigPda(authority?: string): Promise<{ pda: string; bump: number }> {
    const auth = authority ?? this.authority;
    const seeds = [
      new TextEncoder().encode(SPENDING_CONFIG_SEED),
      base58Decode(auth),
    ];

    return findProgramAddress(seeds, this.programId);
  }

  /**
   * Derive a whitelist entry PDA
   */
  async deriveWhitelistPda(
    configPda: string,
    target: string
  ): Promise<{ pda: string; bump: number }> {
    const seeds = [
      new TextEncoder().encode(WHITELIST_SEED),
      base58Decode(configPda),
      base58Decode(target),
    ];

    return findProgramAddress(seeds, this.programId);
  }

  /**
   * Get or derive the config PDA
   */
  async getConfigPda(): Promise<string> {
    if (!this.configPda) {
      const { pda } = await this.deriveConfigPda();
      this.configPda = pda;
    }
    return this.configPda;
  }

  // ==========================================================================
  // Initialization
  // ==========================================================================

  /**
   * Initialize a new spending configuration
   *
   * Creates a PDA account that stores the spending limits for the authority.
   *
   * @param config - The spending configuration
   * @param signTransaction - Function to sign the transaction
   * @returns Transaction result
   */
  async initialize(
    config: SpendingConfig,
    signTransaction: (message: Uint8Array) => Promise<Uint8Array>
  ): Promise<TransactionResult> {
    // Validate config
    if (!this.validateConfig(config)) {
      throw new SpendingLimitError(
        SpendingLimitErrorCode.InvalidConfig,
        'Invalid spending configuration: limits must be positive and consistent'
      );
    }

    const { pda } = await this.deriveConfigPda();
    this.configPda = pda;

    // Build initialize instruction
    const instruction = this.buildInitializeInstruction(config);

    // Get recent blockhash
    const recentBlockhash = await this.getRecentBlockhash();

    // Build transaction message
    const message = buildTransactionMessage(
      this.authority,
      [instruction],
      recentBlockhash
    );

    // Sign transaction
    const signature = await signTransaction(message);

    // Build and broadcast transaction
    return this.broadcastTransaction(message, signature);
  }

  /**
   * Check if a spending config exists for the authority
   */
  async configExists(): Promise<boolean> {
    try {
      await this.getState();
      return true;
    } catch {
      return false;
    }
  }

  // ==========================================================================
  // State Queries
  // ==========================================================================

  /**
   * Get the current spending state
   */
  async getState(): Promise<SpendingState> {
    const configPda = await this.getConfigPda();
    const accountInfo = await this.getAccountInfo(configPda);

    if (!accountInfo) {
      throw new SpendingLimitError(
        SpendingLimitErrorCode.ConfigNotFound,
        'Spending config not found for this authority'
      );
    }

    return this.parseSpendingConfig(accountInfo.data);
  }

  /**
   * Get remaining spending allowance
   *
   * Returns the current remaining spending allowance across all periods.
   */
  async getRemaining(): Promise<RemainingAllowance> {
    const state = await this.getState();
    const currentSlot = await this.getCurrentSlot();

    // Calculate effective spent amounts (accounting for period resets)
    const effectiveDaily =
      BigInt(currentSlot) >= state.dailyResetSlot ? 0n : state.dailySpent;
    const effectiveWeekly =
      BigInt(currentSlot) >= state.weeklyResetSlot ? 0n : state.weeklySpent;
    const effectiveMonthly =
      BigInt(currentSlot) >= state.monthlyResetSlot ? 0n : state.monthlySpent;

    const dailyRemaining = state.dailyLimit - effectiveDaily;
    const weeklyRemaining = state.weeklyLimit - effectiveWeekly;
    const monthlyRemaining = state.monthlyLimit - effectiveMonthly;

    const minimum = minBigInt(
      state.perTxLimit,
      minBigInt(dailyRemaining, minBigInt(weeklyRemaining, monthlyRemaining))
    );

    return {
      perTxLimit: state.perTxLimit,
      daily: dailyRemaining,
      weekly: weeklyRemaining,
      monthly: monthlyRemaining,
      minimum,
      isPaused: state.isPaused,
    };
  }

  /**
   * Get whitelist entry for a target
   */
  async getWhitelistEntry(target: string): Promise<WhitelistEntry | null> {
    const configPda = await this.getConfigPda();
    const { pda } = await this.deriveWhitelistPda(configPda, target);

    const accountInfo = await this.getAccountInfo(pda);
    if (!accountInfo) {
      return null;
    }

    return this.parseWhitelistEntry(accountInfo.data);
  }

  /**
   * Check if a target is whitelisted
   */
  async isWhitelisted(target: string): Promise<boolean> {
    const entry = await this.getWhitelistEntry(target);
    return entry !== null && entry.isAllowed && !entry.isBlacklisted;
  }

  /**
   * Check if a target is blacklisted
   */
  async isBlacklisted(target: string): Promise<boolean> {
    const entry = await this.getWhitelistEntry(target);
    return entry !== null && entry.isBlacklisted;
  }

  // ==========================================================================
  // Validation
  // ==========================================================================

  /**
   * Validate if a transfer would be allowed
   *
   * Checks the transfer against all spending limits without modifying state.
   *
   * @param amount - Transfer amount in lamports
   * @param target - Target address
   * @returns True if the transfer would be allowed
   * @throws SpendingLimitError if the transfer would be rejected
   */
  async validateTransfer(amount: bigint, target: string): Promise<boolean> {
    const state = await this.getState();
    const remaining = await this.getRemaining();

    // Check if paused
    if (state.isPaused) {
      throw new SpendingLimitError(
        SpendingLimitErrorCode.ConfigPaused,
        'Spending config is paused'
      );
    }

    // Check per-transaction limit
    if (amount > state.perTxLimit) {
      throw new SpendingLimitError(
        SpendingLimitErrorCode.PerTxLimitExceeded,
        `Amount ${amount} exceeds per-transaction limit ${state.perTxLimit}`
      );
    }

    // Check daily limit
    if (amount > remaining.daily) {
      throw new SpendingLimitError(
        SpendingLimitErrorCode.DailyLimitExceeded,
        `Amount ${amount} exceeds daily remaining ${remaining.daily}`
      );
    }

    // Check weekly limit
    if (amount > remaining.weekly) {
      throw new SpendingLimitError(
        SpendingLimitErrorCode.WeeklyLimitExceeded,
        `Amount ${amount} exceeds weekly remaining ${remaining.weekly}`
      );
    }

    // Check monthly limit
    if (amount > remaining.monthly) {
      throw new SpendingLimitError(
        SpendingLimitErrorCode.MonthlyLimitExceeded,
        `Amount ${amount} exceeds monthly remaining ${remaining.monthly}`
      );
    }

    // Check whitelist if enabled
    if (state.whitelistOnly) {
      const entry = await this.getWhitelistEntry(target);

      if (!entry) {
        throw new SpendingLimitError(
          SpendingLimitErrorCode.WhitelistRequired,
          `Target ${target} is not whitelisted (whitelist mode is enabled)`
        );
      }

      if (entry.isBlacklisted) {
        throw new SpendingLimitError(
          SpendingLimitErrorCode.TargetBlacklisted,
          `Target ${target} is blacklisted`
        );
      }

      if (!entry.isAllowed) {
        throw new SpendingLimitError(
          SpendingLimitErrorCode.NotWhitelisted,
          `Target ${target} is not allowed in whitelist`
        );
      }
    }

    return true;
  }

  /**
   * Check if a transfer would be allowed (returns boolean, no throw)
   */
  async canTransfer(amount: bigint, target: string): Promise<boolean> {
    try {
      await this.validateTransfer(amount, target);
      return true;
    } catch {
      return false;
    }
  }

  // ==========================================================================
  // Limit Management
  // ==========================================================================

  /**
   * Update spending limits
   *
   * @param options - New limit values (undefined to keep current)
   * @param signTransaction - Function to sign the transaction
   * @returns Transaction result
   */
  async updateLimits(
    options: UpdateLimitsOptions,
    signTransaction: (message: Uint8Array) => Promise<Uint8Array>
  ): Promise<TransactionResult> {
    const instruction = this.buildUpdateLimitsInstruction(options);
    const recentBlockhash = await this.getRecentBlockhash();
    const message = buildTransactionMessage(
      this.authority,
      [instruction],
      recentBlockhash
    );
    const signature = await signTransaction(message);
    return this.broadcastTransaction(message, signature);
  }

  /**
   * Toggle pause state
   */
  async togglePause(
    signTransaction: (message: Uint8Array) => Promise<Uint8Array>
  ): Promise<TransactionResult> {
    const instruction = this.buildTogglePauseInstruction();
    const recentBlockhash = await this.getRecentBlockhash();
    const message = buildTransactionMessage(
      this.authority,
      [instruction],
      recentBlockhash
    );
    const signature = await signTransaction(message);
    return this.broadcastTransaction(message, signature);
  }

  /**
   * Set or remove guardian
   */
  async setGuardian(
    guardian: string | null,
    signTransaction: (message: Uint8Array) => Promise<Uint8Array>
  ): Promise<TransactionResult> {
    const instruction = this.buildSetGuardianInstruction(guardian);
    const recentBlockhash = await this.getRecentBlockhash();
    const message = buildTransactionMessage(
      this.authority,
      [instruction],
      recentBlockhash
    );
    const signature = await signTransaction(message);
    return this.broadcastTransaction(message, signature);
  }

  // ==========================================================================
  // Whitelist Management
  // ==========================================================================

  /**
   * Add an address to the whitelist
   *
   * @param target - Address to whitelist
   * @param options - Whitelist options
   * @param signTransaction - Function to sign the transaction
   */
  async addToWhitelist(
    target: string,
    options: { isBlacklisted?: boolean; label?: string },
    signTransaction: (message: Uint8Array) => Promise<Uint8Array>
  ): Promise<TransactionResult> {
    const instruction = this.buildAddToWhitelistInstruction(target, options);
    const recentBlockhash = await this.getRecentBlockhash();
    const message = buildTransactionMessage(
      this.authority,
      [instruction],
      recentBlockhash
    );
    const signature = await signTransaction(message);
    return this.broadcastTransaction(message, signature);
  }

  /**
   * Remove an address from the whitelist
   *
   * @param target - Address to remove
   * @param signTransaction - Function to sign the transaction
   */
  async removeFromWhitelist(
    target: string,
    signTransaction: (message: Uint8Array) => Promise<Uint8Array>
  ): Promise<TransactionResult> {
    const instruction = this.buildRemoveFromWhitelistInstruction(target);
    const recentBlockhash = await this.getRecentBlockhash();
    const message = buildTransactionMessage(
      this.authority,
      [instruction],
      recentBlockhash
    );
    const signature = await signTransaction(message);
    return this.broadcastTransaction(message, signature);
  }

  /**
   * Update whitelist for multiple addresses
   *
   * @param targets - Addresses to update
   * @param allowed - Whether each address should be allowed
   * @param signTransaction - Function to sign the transaction
   */
  async updateWhitelist(
    targets: string[],
    allowed: boolean[],
    signTransaction: (message: Uint8Array) => Promise<Uint8Array>
  ): Promise<TransactionResult[]> {
    const results: TransactionResult[] = [];

    for (let i = 0; i < targets.length; i++) {
      const target = targets[i];
      const isAllowed = allowed[i];

      if (isAllowed) {
        const result = await this.addToWhitelist(target, {}, signTransaction);
        results.push(result);
      } else {
        const result = await this.removeFromWhitelist(target, signTransaction);
        results.push(result);
      }
    }

    return results;
  }

  // ==========================================================================
  // Spending Recording
  // ==========================================================================

  /**
   * Record spending after a transfer
   *
   * Updates the spending counters. Should be called after the actual transfer.
   *
   * @param amount - Amount that was transferred (in lamports)
   * @param signTransaction - Function to sign the transaction
   */
  async recordSpending(
    amount: bigint,
    signTransaction: (message: Uint8Array) => Promise<Uint8Array>
  ): Promise<TransactionResult> {
    const instruction = this.buildRecordSpendingInstruction(amount);
    const recentBlockhash = await this.getRecentBlockhash();
    const message = buildTransactionMessage(
      this.authority,
      [instruction],
      recentBlockhash
    );
    const signature = await signTransaction(message);
    return this.broadcastTransaction(message, signature);
  }

  /**
   * Validate and record spending atomically
   *
   * Combines validation and recording in one transaction.
   *
   * @param amount - Transfer amount in lamports
   * @param target - Target address
   * @param signTransaction - Function to sign the transaction
   */
  async validateAndRecord(
    amount: bigint,
    target: string,
    signTransaction: (message: Uint8Array) => Promise<Uint8Array>
  ): Promise<TransactionResult> {
    const instruction = this.buildValidateAndRecordInstruction(amount, target);
    const recentBlockhash = await this.getRecentBlockhash();
    const message = buildTransactionMessage(
      this.authority,
      [instruction],
      recentBlockhash
    );
    const signature = await signTransaction(message);
    return this.broadcastTransaction(message, signature);
  }

  // ==========================================================================
  // Private Methods - RPC
  // ==========================================================================

  private async rpcCall<T>(method: string, params: unknown[]): Promise<T> {
    const response = await fetch(this.network.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method,
        params,
        id: Date.now(),
      }),
    });

    const data = await response.json();

    if (data.error) {
      throw new SpendingLimitError(
        SpendingLimitErrorCode.RpcError,
        data.error.message || 'RPC error'
      );
    }

    return data.result;
  }

  private async getRecentBlockhash(): Promise<string> {
    const result = await this.rpcCall<{
      value: { blockhash: string };
    }>('getLatestBlockhash', [{ commitment: this.network.commitment }]);

    return result.value.blockhash;
  }

  private async getCurrentSlot(): Promise<number> {
    return this.rpcCall<number>('getSlot', [
      { commitment: this.network.commitment },
    ]);
  }

  private async getAccountInfo(
    address: string
  ): Promise<{ data: Uint8Array; lamports: number } | null> {
    const result = await this.rpcCall<{
      value: { data: [string, string]; lamports: number } | null;
    }>('getAccountInfo', [address, { encoding: 'base64' }]);

    if (!result.value) {
      return null;
    }

    const [dataBase64] = result.value.data;
    const data = Uint8Array.from(atob(dataBase64), (c) => c.charCodeAt(0));

    return { data, lamports: result.value.lamports };
  }

  private async broadcastTransaction(
    message: Uint8Array,
    signature: Uint8Array
  ): Promise<TransactionResult> {
    // Build transaction with signature
    const tx = new Uint8Array(1 + 64 + message.length);
    tx[0] = 1; // Signature count
    tx.set(signature.slice(0, 64), 1);
    tx.set(message, 65);

    const txBase64 = btoa(String.fromCharCode(...tx));

    const sig = await this.rpcCall<string>('sendTransaction', [
      txBase64,
      {
        encoding: 'base64',
        skipPreflight: false,
        preflightCommitment: this.network.commitment,
      },
    ]);

    // Wait for confirmation
    const confirmed = await this.waitForConfirmation(sig);

    return {
      signature: sig,
      confirmed: confirmed.confirmed,
      slot: confirmed.slot,
    };
  }

  private async waitForConfirmation(
    signature: string,
    timeoutMs = 60000
  ): Promise<{ confirmed: boolean; slot?: number }> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeoutMs) {
      try {
        const result = await this.rpcCall<{
          value: Array<{
            confirmationStatus: string;
            slot: number;
          } | null>;
        }>('getSignatureStatuses', [[signature]]);

        const status = result.value[0];
        if (status) {
          if (
            status.confirmationStatus === 'confirmed' ||
            status.confirmationStatus === 'finalized'
          ) {
            return { confirmed: true, slot: status.slot };
          }
        }
      } catch {
        // Status not available yet
      }

      await sleep(2000);
    }

    return { confirmed: false };
  }

  // ==========================================================================
  // Private Methods - Parsing
  // ==========================================================================

  private parseSpendingConfig(data: Uint8Array): SpendingState {
    // Skip discriminator (8 bytes)
    const view = new DataView(data.buffer, data.byteOffset + 8);
    let offset = 0;

    // authority (32 bytes)
    const authority = base58Encode(data.slice(8 + offset, 8 + offset + 32));
    offset += 32;

    // guardian (Option<Pubkey> = 1 byte discriminant + 32 bytes if Some)
    const hasGuardian = data[8 + offset] === 1;
    offset += 1;
    let guardian: string | null = null;
    if (hasGuardian) {
      guardian = base58Encode(data.slice(8 + offset, 8 + offset + 32));
    }
    offset += 32;

    // Read u64 values
    const perTxLimit = view.getBigUint64(offset, true);
    offset += 8;
    const dailyLimit = view.getBigUint64(offset, true);
    offset += 8;
    const weeklyLimit = view.getBigUint64(offset, true);
    offset += 8;
    const monthlyLimit = view.getBigUint64(offset, true);
    offset += 8;
    const dailySpent = view.getBigUint64(offset, true);
    offset += 8;
    const weeklySpent = view.getBigUint64(offset, true);
    offset += 8;
    const monthlySpent = view.getBigUint64(offset, true);
    offset += 8;
    const dailyResetSlot = view.getBigUint64(offset, true);
    offset += 8;
    const weeklyResetSlot = view.getBigUint64(offset, true);
    offset += 8;
    const monthlyResetSlot = view.getBigUint64(offset, true);
    offset += 8;

    // Read bools and u16
    const whitelistOnly = data[8 + offset] === 1;
    offset += 1;
    const isPaused = data[8 + offset] === 1;
    offset += 1;
    const whitelistCount = view.getUint16(offset, true);

    return {
      authority,
      guardian,
      perTxLimit,
      dailyLimit,
      weeklyLimit,
      monthlyLimit,
      dailySpent,
      weeklySpent,
      monthlySpent,
      dailyResetSlot,
      weeklyResetSlot,
      monthlyResetSlot,
      whitelistOnly,
      isPaused,
      whitelistCount,
    };
  }

  private parseWhitelistEntry(data: Uint8Array): WhitelistEntry {
    // Skip discriminator (8 bytes)
    let offset = 8;

    // config (32 bytes) - skip
    offset += 32;

    // target (32 bytes)
    const target = base58Encode(data.slice(offset, offset + 32));
    offset += 32;

    // is_allowed (1 byte)
    const isAllowed = data[offset] === 1;
    offset += 1;

    // is_blacklisted (1 byte)
    const isBlacklisted = data[offset] === 1;
    offset += 1;

    // label (32 bytes)
    const labelBytes = data.slice(offset, offset + 32);
    const label = new TextDecoder()
      .decode(labelBytes)
      .replace(/\0/g, '')
      .trim();
    offset += 32;

    // created_at (8 bytes)
    const view = new DataView(data.buffer, data.byteOffset);
    const createdAt = view.getBigUint64(offset, true);
    offset += 8;

    // updated_at (8 bytes)
    const updatedAt = view.getBigUint64(offset, true);

    return {
      target,
      isAllowed,
      isBlacklisted,
      label,
      createdAt,
      updatedAt,
    };
  }

  // ==========================================================================
  // Private Methods - Instruction Building
  // ==========================================================================

  private buildInitializeInstruction(config: SpendingConfig): Instruction {
    // Build instruction data
    // discriminator (8 bytes) + SpendingConfigInput
    const data = new Uint8Array(8 + 8 + 8 + 8 + 8 + 1 + 8);
    const view = new DataView(data.buffer);

    // Anchor discriminator for "initialize"
    const discriminator = [175, 175, 109, 31, 13, 152, 155, 237];
    data.set(discriminator, 0);

    let offset = 8;
    view.setBigUint64(offset, config.perTxLimit, true);
    offset += 8;
    view.setBigUint64(offset, config.dailyLimit, true);
    offset += 8;
    view.setBigUint64(offset, config.weeklyLimit, true);
    offset += 8;
    view.setBigUint64(offset, config.monthlyLimit, true);
    offset += 8;
    data[offset] = config.whitelistOnly ? 1 : 0;
    offset += 1;
    view.setBigUint64(offset, config.updateCooldownSlots ?? 0n, true);

    return {
      programId: this.programId,
      keys: [
        { pubkey: this.authority, isSigner: true, isWritable: true },
        { pubkey: this.configPda!, isSigner: false, isWritable: true },
        {
          pubkey: '11111111111111111111111111111111',
          isSigner: false,
          isWritable: false,
        },
      ],
      data,
    };
  }

  private buildUpdateLimitsInstruction(options: UpdateLimitsOptions): Instruction {
    const data = new Uint8Array(8 + 5 * 9); // discriminator + 5 Option<u64/bool>
    const view = new DataView(data.buffer);

    // Anchor discriminator for "update_limits"
    const discriminator = [114, 169, 200, 47, 167, 144, 113, 171];
    data.set(discriminator, 0);

    let offset = 8;

    // Option<u64> for each limit
    const writeOptionU64 = (value: bigint | undefined) => {
      if (value !== undefined) {
        data[offset] = 1;
        offset += 1;
        view.setBigUint64(offset, value, true);
        offset += 8;
      } else {
        data[offset] = 0;
        offset += 1;
      }
    };

    writeOptionU64(options.perTxLimit);
    writeOptionU64(options.dailyLimit);
    writeOptionU64(options.weeklyLimit);
    writeOptionU64(options.monthlyLimit);

    // Option<bool> for whitelist_only
    if (options.whitelistOnly !== undefined) {
      data[offset] = 1;
      offset += 1;
      data[offset] = options.whitelistOnly ? 1 : 0;
    } else {
      data[offset] = 0;
    }

    return {
      programId: this.programId,
      keys: [
        { pubkey: this.authority, isSigner: true, isWritable: false },
        { pubkey: this.configPda!, isSigner: false, isWritable: true },
      ],
      data: data.slice(0, offset + 1),
    };
  }

  private buildTogglePauseInstruction(): Instruction {
    const discriminator = [252, 44, 101, 97, 135, 147, 118, 65];
    const data = new Uint8Array(discriminator);

    return {
      programId: this.programId,
      keys: [
        { pubkey: this.authority, isSigner: true, isWritable: false },
        { pubkey: this.configPda!, isSigner: false, isWritable: true },
      ],
      data,
    };
  }

  private buildSetGuardianInstruction(guardian: string | null): Instruction {
    const data = new Uint8Array(8 + 1 + (guardian ? 32 : 0));
    const discriminator = [185, 119, 0, 137, 93, 229, 26, 47];
    data.set(discriminator, 0);

    if (guardian) {
      data[8] = 1;
      data.set(base58Decode(guardian), 9);
    } else {
      data[8] = 0;
    }

    return {
      programId: this.programId,
      keys: [
        { pubkey: this.authority, isSigner: true, isWritable: false },
        { pubkey: this.configPda!, isSigner: false, isWritable: true },
      ],
      data,
    };
  }

  private buildAddToWhitelistInstruction(
    target: string,
    options: { isBlacklisted?: boolean; label?: string }
  ): Instruction {
    const data = new Uint8Array(8 + 32 + 1 + 1 + 32);
    const discriminator = [157, 125, 119, 15, 93, 248, 252, 165];
    data.set(discriminator, 0);

    // target pubkey
    data.set(base58Decode(target), 8);

    // is_blacklisted
    data[8 + 32] = options.isBlacklisted ? 1 : 0;

    // Option<label>
    if (options.label) {
      data[8 + 32 + 1] = 1;
      const labelBytes = new TextEncoder().encode(
        options.label.slice(0, 32).padEnd(32, '\0')
      );
      data.set(labelBytes, 8 + 32 + 1 + 1);
    } else {
      data[8 + 32 + 1] = 0;
    }

    return {
      programId: this.programId,
      keys: [
        { pubkey: this.authority, isSigner: true, isWritable: true },
        { pubkey: this.configPda!, isSigner: false, isWritable: true },
        // whitelist entry PDA will be derived
        {
          pubkey: '11111111111111111111111111111111',
          isSigner: false,
          isWritable: false,
        },
      ],
      data,
    };
  }

  private buildRemoveFromWhitelistInstruction(target: string): Instruction {
    const data = new Uint8Array(8 + 32);
    const discriminator = [93, 132, 26, 133, 133, 211, 196, 16];
    data.set(discriminator, 0);
    data.set(base58Decode(target), 8);

    return {
      programId: this.programId,
      keys: [
        { pubkey: this.authority, isSigner: true, isWritable: true },
        { pubkey: this.configPda!, isSigner: false, isWritable: true },
        // whitelist entry PDA will be derived
      ],
      data,
    };
  }

  private buildRecordSpendingInstruction(amount: bigint): Instruction {
    const data = new Uint8Array(8 + 8);
    const view = new DataView(data.buffer);
    const discriminator = [147, 216, 209, 185, 171, 205, 163, 144];
    data.set(discriminator, 0);
    view.setBigUint64(8, amount, true);

    return {
      programId: this.programId,
      keys: [
        { pubkey: this.authority, isSigner: true, isWritable: false },
        { pubkey: this.configPda!, isSigner: false, isWritable: true },
      ],
      data,
    };
  }

  private buildValidateAndRecordInstruction(
    amount: bigint,
    target: string
  ): Instruction {
    const data = new Uint8Array(8 + 8 + 32);
    const view = new DataView(data.buffer);
    const discriminator = [50, 56, 87, 138, 221, 32, 46, 24];
    data.set(discriminator, 0);
    view.setBigUint64(8, amount, true);
    data.set(base58Decode(target), 16);

    return {
      programId: this.programId,
      keys: [
        { pubkey: this.authority, isSigner: true, isWritable: false },
        { pubkey: this.configPda!, isSigner: false, isWritable: true },
      ],
      data,
    };
  }

  // ==========================================================================
  // Validation
  // ==========================================================================

  private validateConfig(config: SpendingConfig): boolean {
    return (
      config.perTxLimit > 0n &&
      config.dailyLimit > 0n &&
      config.weeklyLimit > 0n &&
      config.monthlyLimit > 0n &&
      config.perTxLimit <= config.dailyLimit &&
      config.dailyLimit <= config.weeklyLimit &&
      config.weeklyLimit <= config.monthlyLimit
    );
  }
}

// ============================================================================
// Helper Types and Functions
// ============================================================================

interface Instruction {
  programId: string;
  keys: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>;
  data: Uint8Array;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function minBigInt(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}

// Base58 encoding/decoding
const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  // Count leading zeros
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) {
    zeros++;
  }

  // Convert to base58
  const size = ((bytes.length - zeros) * 138) / 100 + 1;
  const b58 = new Uint8Array(size);
  let length = 0;

  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    let j = 0;

    for (
      let k = size - 1;
      (carry !== 0 || j < length) && k >= 0;
      k--, j++
    ) {
      carry += 256 * b58[k];
      b58[k] = carry % 58;
      carry = Math.floor(carry / 58);
    }

    length = j;
  }

  // Skip leading zeros in base58 result
  let i = size - length;
  while (i < size && b58[i] === 0) {
    i++;
  }

  // Translate
  let result = '1'.repeat(zeros);
  for (; i < size; i++) {
    result += BASE58_ALPHABET[b58[i]];
  }

  return result;
}

function base58Decode(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0);

  // Count leading '1's
  let zeros = 0;
  while (zeros < str.length && str[zeros] === '1') {
    zeros++;
  }

  // Allocate enough space
  const size = ((str.length - zeros) * 733) / 1000 + 1;
  const b256 = new Uint8Array(size);
  let length = 0;

  for (let i = zeros; i < str.length; i++) {
    const ch = BASE58_ALPHABET.indexOf(str[i]);
    if (ch === -1) {
      throw new Error(`Invalid base58 character: ${str[i]}`);
    }

    let carry = ch;
    let j = 0;

    for (
      let k = size - 1;
      (carry !== 0 || j < length) && k >= 0;
      k--, j++
    ) {
      carry += 58 * b256[k];
      b256[k] = carry % 256;
      carry = Math.floor(carry / 256);
    }

    length = j;
  }

  // Skip leading zeros in b256
  let i = size - length;
  while (i < size && b256[i] === 0) {
    i++;
  }

  // Build result
  const result = new Uint8Array(zeros + (size - i));
  result.fill(0, 0, zeros);
  let j = zeros;
  while (i < size) {
    result[j++] = b256[i++];
  }

  return result;
}

async function findProgramAddress(
  seeds: Uint8Array[],
  programId: string
): Promise<{ pda: string; bump: number }> {
  // Simplified PDA derivation
  // In production, use @solana/web3.js PublicKey.findProgramAddressSync
  const programIdBytes = base58Decode(programId);

  for (let bump = 255; bump >= 0; bump--) {
    try {
      const seedsWithBump = [...seeds, new Uint8Array([bump])];
      const hash = await derivePda(seedsWithBump, programIdBytes);

      // Check if point is on curve (simplified - in production use proper check)
      // For now, return the hash as base58
      const pda = base58Encode(hash);
      return { pda, bump };
    } catch {
      continue;
    }
  }

  throw new Error('Unable to find program address');
}

async function derivePda(
  seeds: Uint8Array[],
  programId: Uint8Array
): Promise<Uint8Array> {
  // Concatenate seeds with program ID and "ProgramDerivedAddress"
  const marker = new TextEncoder().encode('ProgramDerivedAddress');

  let totalLength = marker.length + programId.length;
  for (const seed of seeds) {
    totalLength += seed.length;
  }

  const buffer = new Uint8Array(totalLength);
  let offset = 0;

  for (const seed of seeds) {
    buffer.set(seed, offset);
    offset += seed.length;
  }

  buffer.set(programId, offset);
  offset += programId.length;

  buffer.set(marker, offset);

  // Use SubtleCrypto for SHA256
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return new Uint8Array(hashBuffer);
}

function buildTransactionMessage(
  feePayer: string,
  instructions: Instruction[],
  recentBlockhash: string
): Uint8Array {
  // Simplified transaction message building
  // In production, use @solana/web3.js Transaction class

  // This is a simplified version - real implementation would use proper
  // Solana transaction format with compact arrays, account lists, etc.
  const message: Record<string, unknown> = {
    feePayer,
    instructions: instructions.map((ix) => ({
      programId: ix.programId,
      keys: ix.keys,
      data: Array.from(ix.data),
    })),
    recentBlockhash,
  };

  return new TextEncoder().encode(JSON.stringify(message));
}
