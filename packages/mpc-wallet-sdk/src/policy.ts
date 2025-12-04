/**
 * Policy engine for transaction validation
 */

import type { ChainType, TransactionRequest } from './types';

/**
 * Policy decision result
 */
export interface PolicyDecision {
  /** Whether transaction is approved */
  approved: boolean;
  /** Whether additional approval is required */
  requiresAdditionalApproval: boolean;
  /** Reason for rejection (if any) */
  reason?: string;
}

/**
 * Spending limits configuration
 */
export interface SpendingLimits {
  /** Per-transaction limit (in wei) */
  perTransaction?: bigint;
  /** Daily limit (in wei) */
  daily?: bigint;
  /** Weekly limit (in wei) */
  weekly?: bigint;
  /** Currency symbol */
  currency: string;
}

/**
 * Time window restriction
 */
export interface TimeBounds {
  /** Start hour (0-23, UTC) */
  startHour: number;
  /** End hour (0-23, UTC) */
  endHour: number;
  /** Allowed days (0=Sunday, 6=Saturday) */
  allowedDays: number[];
}

/**
 * Contract interaction restriction
 */
export interface ContractRestriction {
  /** Allowed contract addresses (empty = all allowed) */
  allowedContracts: Set<string>;
  /** Allowed function selectors (4-byte hex) */
  allowedSelectors: Set<string>;
  /** Blocked function selectors */
  blockedSelectors: Set<string>;
}

/**
 * Policy configuration
 */
export class PolicyConfig {
  spendingLimits: Map<ChainType, SpendingLimits> = new Map();
  whitelist: Set<string> | null = null;
  blacklist: Set<string> = new Set();
  timeBounds: TimeBounds | null = null;
  contractRestrictions: ContractRestriction | null = null;
  additionalApprovalThreshold: bigint | null = null;
  maxPendingRequests: number = 10;
  enabled: boolean = true;

  /**
   * Create a new policy config
   */
  static create(): PolicyConfig {
    return new PolicyConfig();
  }

  /**
   * Create a disabled policy (all transactions allowed)
   */
  static disabled(): PolicyConfig {
    const config = new PolicyConfig();
    config.enabled = false;
    return config;
  }

  /**
   * Set per-transaction spending limit
   */
  withPerTxLimit(amount: bigint, currency = 'ETH'): PolicyConfig {
    const limits = this.spendingLimits.get(0) ?? { currency };
    limits.perTransaction = amount;
    limits.currency = currency;
    this.spendingLimits.set(0, limits);
    return this;
  }

  /**
   * Set daily spending limit
   */
  withDailyLimit(amount: bigint, currency = 'ETH'): PolicyConfig {
    const limits = this.spendingLimits.get(0) ?? { currency };
    limits.daily = amount;
    limits.currency = currency;
    this.spendingLimits.set(0, limits);
    return this;
  }

  /**
   * Set weekly spending limit
   */
  withWeeklyLimit(amount: bigint, currency = 'ETH'): PolicyConfig {
    const limits = this.spendingLimits.get(0) ?? { currency };
    limits.weekly = amount;
    limits.currency = currency;
    this.spendingLimits.set(0, limits);
    return this;
  }

  /**
   * Set address whitelist
   */
  withWhitelist(addresses: string[]): PolicyConfig {
    this.whitelist = new Set(addresses.map((a) => a.toLowerCase()));
    return this;
  }

  /**
   * Set address blacklist
   */
  withBlacklist(addresses: string[]): PolicyConfig {
    this.blacklist = new Set(addresses.map((a) => a.toLowerCase()));
    return this;
  }

  /**
   * Set time bounds
   */
  withTimeBounds(bounds: TimeBounds): PolicyConfig {
    this.timeBounds = bounds;
    return this;
  }

  /**
   * Set business hours (9 AM - 5 PM UTC, weekdays)
   */
  withBusinessHours(): PolicyConfig {
    this.timeBounds = {
      startHour: 9,
      endHour: 17,
      allowedDays: [1, 2, 3, 4, 5],
    };
    return this;
  }

  /**
   * Set contract restrictions
   */
  withContractRestrictions(restrictions: ContractRestriction): PolicyConfig {
    this.contractRestrictions = restrictions;
    return this;
  }

  /**
   * Set additional approval threshold
   */
  withAdditionalApprovalThreshold(amount: bigint): PolicyConfig {
    this.additionalApprovalThreshold = amount;
    return this;
  }

  /**
   * Convert to JSON for storage
   */
  toJSON(): object {
    return {
      spendingLimits: Object.fromEntries(
        Array.from(this.spendingLimits.entries()).map(([k, v]) => [
          k,
          {
            ...v,
            perTransaction: v.perTransaction?.toString(),
            daily: v.daily?.toString(),
            weekly: v.weekly?.toString(),
          },
        ])
      ),
      whitelist: this.whitelist ? Array.from(this.whitelist) : null,
      blacklist: Array.from(this.blacklist),
      timeBounds: this.timeBounds,
      contractRestrictions: this.contractRestrictions
        ? {
            allowedContracts: Array.from(
              this.contractRestrictions.allowedContracts
            ),
            allowedSelectors: Array.from(
              this.contractRestrictions.allowedSelectors
            ),
            blockedSelectors: Array.from(
              this.contractRestrictions.blockedSelectors
            ),
          }
        : null,
      additionalApprovalThreshold:
        this.additionalApprovalThreshold?.toString() ?? null,
      maxPendingRequests: this.maxPendingRequests,
      enabled: this.enabled,
    };
  }

  /**
   * Create from JSON
   */
  static fromJSON(json: object): PolicyConfig {
    const config = new PolicyConfig();
    const data = json as Record<string, unknown>;

    config.enabled = (data.enabled as boolean) ?? true;

    if (data.whitelist && Array.isArray(data.whitelist)) {
      config.whitelist = new Set(data.whitelist as string[]);
    }

    if (data.blacklist && Array.isArray(data.blacklist)) {
      config.blacklist = new Set(data.blacklist as string[]);
    }

    if (data.timeBounds) {
      config.timeBounds = data.timeBounds as TimeBounds;
    }

    if (data.additionalApprovalThreshold) {
      config.additionalApprovalThreshold = BigInt(
        data.additionalApprovalThreshold as string
      );
    }

    return config;
  }
}

/**
 * Policy engine for evaluating transactions
 */
export class PolicyEngine {
  private config: PolicyConfig;
  private dailySpending: Map<string, bigint> = new Map();
  private weeklySpending: Map<string, bigint> = new Map();

  constructor(config: PolicyConfig) {
    this.config = config;
  }

  /**
   * Get the policy configuration
   */
  getConfig(): PolicyConfig {
    return this.config;
  }

  /**
   * Update the policy configuration
   */
  setConfig(config: PolicyConfig): void {
    this.config = config;
  }

  /**
   * Evaluate a transaction against the policy
   */
  evaluate(tx: TransactionRequest): PolicyDecision {
    // Skip evaluation if policy is disabled
    if (!this.config.enabled) {
      return { approved: true, requiresAdditionalApproval: false };
    }

    const toAddress = tx.to.toLowerCase();

    // Check blacklist
    if (this.config.blacklist.has(toAddress)) {
      return {
        approved: false,
        requiresAdditionalApproval: false,
        reason: `Address ${tx.to} is blacklisted`,
      };
    }

    // Check whitelist
    if (this.config.whitelist && !this.config.whitelist.has(toAddress)) {
      return {
        approved: false,
        requiresAdditionalApproval: false,
        reason: `Address ${tx.to} is not whitelisted`,
      };
    }

    // Check time bounds
    if (this.config.timeBounds) {
      const now = new Date();
      const hour = now.getUTCHours();
      const day = now.getUTCDay();

      const { startHour, endHour, allowedDays } = this.config.timeBounds;

      const hourOk =
        startHour <= endHour
          ? hour >= startHour && hour < endHour
          : hour >= startHour || hour < endHour;

      if (!hourOk || !allowedDays.includes(day)) {
        return {
          approved: false,
          requiresAdditionalApproval: false,
          reason: `Transaction outside allowed time window (${startHour}:00-${endHour}:00 UTC)`,
        };
      }
    }

    // Check contract restrictions
    if (tx.data && this.config.contractRestrictions) {
      const restrictions = this.config.contractRestrictions;

      // Check allowed contracts
      if (
        restrictions.allowedContracts.size > 0 &&
        !restrictions.allowedContracts.has(toAddress)
      ) {
        return {
          approved: false,
          requiresAdditionalApproval: false,
          reason: `Contract ${tx.to} is not in allowed list`,
        };
      }

      // Check function selectors
      const selector = tx.data.slice(0, 10).toLowerCase();

      if (restrictions.blockedSelectors.has(selector)) {
        return {
          approved: false,
          requiresAdditionalApproval: false,
          reason: `Function selector ${selector} is blocked`,
        };
      }

      if (
        restrictions.allowedSelectors.size > 0 &&
        !restrictions.allowedSelectors.has(selector)
      ) {
        return {
          approved: false,
          requiresAdditionalApproval: false,
          reason: `Function selector ${selector} is not in allowed list`,
        };
      }
    }

    // Parse transaction value
    const value = this.parseValue(tx.value);

    // Check spending limits
    const limits = this.config.spendingLimits.get(tx.chain);
    if (limits) {
      // Per-transaction limit
      if (limits.perTransaction && value > limits.perTransaction) {
        return {
          approved: false,
          requiresAdditionalApproval: false,
          reason: `Transaction value exceeds per-transaction limit of ${limits.perTransaction}`,
        };
      }

      // Daily limit
      if (limits.daily) {
        const dateKey = new Date().toISOString().split('T')[0];
        const spent = this.dailySpending.get(dateKey) ?? 0n;
        if (spent + value > limits.daily) {
          return {
            approved: false,
            requiresAdditionalApproval: false,
            reason: `Transaction would exceed daily limit of ${limits.daily}`,
          };
        }
      }

      // Weekly limit
      if (limits.weekly) {
        const now = new Date();
        const weekKey = `${now.getFullYear()}-W${Math.ceil(
          now.getDate() / 7
        )}`;
        const spent = this.weeklySpending.get(weekKey) ?? 0n;
        if (spent + value > limits.weekly) {
          return {
            approved: false,
            requiresAdditionalApproval: false,
            reason: `Transaction would exceed weekly limit of ${limits.weekly}`,
          };
        }
      }
    }

    // Check additional approval threshold
    if (
      this.config.additionalApprovalThreshold &&
      value > this.config.additionalApprovalThreshold
    ) {
      return {
        approved: false,
        requiresAdditionalApproval: true,
        reason: `Transaction value exceeds additional approval threshold`,
      };
    }

    return { approved: true, requiresAdditionalApproval: false };
  }

  /**
   * Record a completed transaction for spending tracking
   */
  recordTransaction(tx: TransactionRequest): void {
    const value = this.parseValue(tx.value);
    const dateKey = new Date().toISOString().split('T')[0];
    const now = new Date();
    const weekKey = `${now.getFullYear()}-W${Math.ceil(now.getDate() / 7)}`;

    // Update daily spending
    const dailySpent = this.dailySpending.get(dateKey) ?? 0n;
    this.dailySpending.set(dateKey, dailySpent + value);

    // Update weekly spending
    const weeklySpent = this.weeklySpending.get(weekKey) ?? 0n;
    this.weeklySpending.set(weekKey, weeklySpent + value);
  }

  /**
   * Get current daily spending
   */
  getDailySpending(): bigint {
    const dateKey = new Date().toISOString().split('T')[0];
    return this.dailySpending.get(dateKey) ?? 0n;
  }

  /**
   * Get current weekly spending
   */
  getWeeklySpending(): bigint {
    const now = new Date();
    const weekKey = `${now.getFullYear()}-W${Math.ceil(now.getDate() / 7)}`;
    return this.weeklySpending.get(weekKey) ?? 0n;
  }

  /**
   * Reset spending trackers
   */
  resetSpending(): void {
    this.dailySpending.clear();
    this.weeklySpending.clear();
  }

  /**
   * Parse a value string to bigint
   */
  private parseValue(value: string): bigint {
    // Handle decimal values (e.g., "1.5" ETH -> wei)
    if (value.includes('.')) {
      const [whole, decimal] = value.split('.');
      const wholeBigInt = BigInt(whole || '0') * 10n ** 18n;
      const decimalPadded = decimal.padEnd(18, '0').slice(0, 18);
      const decimalBigInt = BigInt(decimalPadded);
      return wholeBigInt + decimalBigInt;
    }
    return BigInt(value);
  }
}
