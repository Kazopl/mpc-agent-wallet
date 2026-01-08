/**
 * Portfolio Rebalance Strategy
 *
 * Maintains target asset allocation by rebalancing when drift exceeds threshold.
 */

import { BaseStrategy, type StrategyContext, type StrategyAction } from './base.js';

interface PortfolioPosition {
  asset: string;
  amount: bigint;
  valueUsd: number;
}

export interface RebalanceConfig {
  name: string;
  target: Record<string, number>; // Asset -> percentage
  threshold: number; // Percentage drift to trigger rebalance
  minTradeSize: bigint;
}

export class RebalanceStrategy extends BaseStrategy {
  private config: RebalanceConfig;
  private lastCheck = 0;
  private checkInterval = 60 * 60 * 1000; // 1 hour

  constructor(config: RebalanceConfig) {
    super({ name: config.name });
    this.config = config;
  }

  async evaluate(ctx: StrategyContext): Promise<StrategyAction | null> {
    if (!this.enabled) return null;

    // Rate limit checks
    const now = Date.now();
    if (now - this.lastCheck < this.checkInterval) {
      return null;
    }
    this.lastCheck = now;

    // Get current portfolio
    const positions = await this.getCurrentPositions();
    const totalValue = positions.reduce((sum, p) => sum + p.valueUsd, 0);

    // Calculate current allocation
    const currentAllocation: Record<string, number> = {};
    for (const position of positions) {
      currentAllocation[position.asset] = (position.valueUsd / totalValue) * 100;
    }

    // Find largest drift
    let maxDrift = 0;
    let driftAsset: string | null = null;
    let driftDirection: 'over' | 'under' | null = null;

    for (const [asset, targetPct] of Object.entries(this.config.target)) {
      const currentPct = currentAllocation[asset] ?? 0;
      const drift = currentPct - targetPct;

      if (Math.abs(drift) > maxDrift) {
        maxDrift = Math.abs(drift);
        driftAsset = asset;
        driftDirection = drift > 0 ? 'over' : 'under';
      }
    }

    // Check if rebalance needed
    if (maxDrift < this.config.threshold || !driftAsset || !driftDirection) {
      return null;
    }

    // Calculate trade
    const trade = this.calculateRebalanceTrade(
      driftAsset,
      driftDirection,
      maxDrift,
      totalValue
    );

    if (trade.value < this.config.minTradeSize) {
      return null;
    }

    return {
      type: 'swap',
      params: {
        tokenIn: trade.from,
        tokenOut: trade.to,
        value: trade.value,
        slippage: 0.5,
      },
      reason: `Rebalancing: ${driftAsset} is ${maxDrift.toFixed(1)}% ${driftDirection}weight (target: ${this.config.target[driftAsset]}%)`,
    };
  }

  private async getCurrentPositions(): Promise<PortfolioPosition[]> {
    // In production, fetch from wallet and price feeds
    return [
      { asset: 'ETH', amount: BigInt('6000000000000000000'), valueUsd: 12000 },
      { asset: 'USDC', amount: BigInt('3500000000'), valueUsd: 3500 },
      { asset: 'WBTC', amount: BigInt('5000000'), valueUsd: 2000 },
    ];
  }

  private calculateRebalanceTrade(
    asset: string,
    direction: 'over' | 'under',
    driftPct: number,
    totalValueUsd: number
  ): { from: string; to: string; value: bigint } {
    // Calculate USD value to trade
    const tradeValueUsd = (driftPct / 100) * totalValueUsd;

    // Find counter-asset (most underweight/overweight)
    const counterAsset = this.findCounterAsset(asset, direction);

    // Convert to ETH equivalent for value
    const ethPrice = 2000; // Mock price
    const ethValue = tradeValueUsd / ethPrice;

    if (direction === 'over') {
      // Sell overweight asset
      return {
        from: asset,
        to: counterAsset,
        value: BigInt(Math.floor(ethValue * 1e18)),
      };
    } else {
      // Buy underweight asset
      return {
        from: counterAsset,
        to: asset,
        value: BigInt(Math.floor(ethValue * 1e18)),
      };
    }
  }

  private findCounterAsset(asset: string, direction: 'over' | 'under'): string {
    // Find the asset with opposite drift
    const target = this.config.target;
    const assets = Object.keys(target).filter((a) => a !== asset);

    // For simplicity, return first different asset
    // In production, find most complementary
    return assets[0] ?? 'USDC';
  }
}
