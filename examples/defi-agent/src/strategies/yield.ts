/**
 * Yield Farming Strategy
 *
 * Automatically allocates funds to the highest-yielding protocols.
 */

import { BaseStrategy, type StrategyContext, type StrategyAction } from './base.js';

interface YieldOpportunity {
  protocol: string;
  asset: string;
  apy: number;
  tvl: number;
  address: string;
}

export interface YieldFarmingConfig {
  name: string;
  protocols: string[];
  targetAPY: number;
  maxAllocation: bigint;
  rebalanceInterval: number;
}

export class YieldFarmingStrategy extends BaseStrategy {
  private config: YieldFarmingConfig;
  private lastRebalance = 0;
  private currentPosition: {
    protocol: string;
    amount: bigint;
  } | null = null;

  constructor(config: YieldFarmingConfig) {
    super({ name: config.name });
    this.config = config;
  }

  async evaluate(ctx: StrategyContext): Promise<StrategyAction | null> {
    if (!this.enabled) return null;

    // Check if it's time to rebalance
    const now = Date.now();
    if (now - this.lastRebalance < this.config.rebalanceInterval) {
      return null;
    }

    // Find best yield opportunity
    const opportunities = await this.getYieldOpportunities();
    const best = opportunities.find(
      (o) =>
        o.apy >= this.config.targetAPY &&
        this.config.protocols.includes(o.protocol)
    );

    if (!best) {
      return null;
    }

    // Check if we should switch positions
    if (
      this.currentPosition &&
      this.currentPosition.protocol === best.protocol
    ) {
      // Already in best position
      return null;
    }

    this.lastRebalance = now;

    // Calculate allocation
    const allocation = this.calculateAllocation(ctx, best);

    if (allocation === BigInt(0)) {
      return null;
    }

    // If we have an existing position, withdraw first
    if (this.currentPosition) {
      return {
        type: 'withdraw',
        params: {
          protocol: this.currentPosition.protocol,
          value: this.currentPosition.amount,
        },
        reason: `Moving funds from ${this.currentPosition.protocol} to ${best.protocol} (${best.apy}% APY)`,
      };
    }

    // Deposit to new protocol
    return {
      type: 'deposit',
      params: {
        to: best.address,
        value: allocation,
        protocol: best.protocol,
      },
      reason: `Depositing to ${best.protocol} for ${best.apy}% APY`,
    };
  }

  private async getYieldOpportunities(): Promise<YieldOpportunity[]> {
    // In production, fetch from DeFi Llama API or similar
    return [
      {
        protocol: 'aave',
        asset: 'ETH',
        apy: 6.5,
        tvl: 5_000_000_000,
        address: '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2',
      },
      {
        protocol: 'compound',
        asset: 'ETH',
        apy: 5.2,
        tvl: 3_000_000_000,
        address: '0xc3d688B66703497DAA19211EEdff47f25384cdc3',
      },
      {
        protocol: 'lido',
        asset: 'ETH',
        apy: 4.8,
        tvl: 15_000_000_000,
        address: '0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84',
      },
    ];
  }

  private calculateAllocation(
    ctx: StrategyContext,
    opportunity: YieldOpportunity
  ): bigint {
    // Allocate up to maxAllocation or 20% of portfolio, whichever is smaller
    const maxByPortfolio = (ctx.portfolioValue * BigInt(20)) / BigInt(100);
    const maxByConfig = this.config.maxAllocation;

    return maxByPortfolio < maxByConfig ? maxByPortfolio : maxByConfig;
  }
}
