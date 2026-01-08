/**
 * Base Strategy
 *
 * Abstract base class for DeFi strategies.
 */

import type { MpcAgentWallet } from '@mpc-wallet/sdk';

export interface StrategyContext {
  wallet: MpcAgentWallet;
  portfolioValue: bigint;
  riskParameters: {
    maxPositionSize: bigint;
    maxDailyLoss: bigint;
    maxSlippage: number;
    minLiquidity: number;
  };
}

export interface StrategyAction {
  type: 'swap' | 'deposit' | 'withdraw' | 'claim' | 'rebalance';
  params: {
    to?: string;
    value?: bigint;
    tokenIn?: string;
    tokenOut?: string;
    protocol?: string;
    slippage?: number;
    data?: string;
  };
  reason: string;
}

export interface StrategyConfig {
  name: string;
  enabled?: boolean;
}

export abstract class BaseStrategy {
  name: string;
  enabled: boolean;

  constructor(config: StrategyConfig) {
    this.name = config.name;
    this.enabled = config.enabled ?? true;
  }

  /**
   * Evaluate the strategy and return an action if one should be taken
   */
  abstract evaluate(ctx: StrategyContext): Promise<StrategyAction | null>;

  /**
   * Called when the strategy is started
   */
  async onStart(): Promise<void> {
    // Override in subclass if needed
  }

  /**
   * Called when the strategy is stopped
   */
  async onStop(): Promise<void> {
    // Override in subclass if needed
  }
}
