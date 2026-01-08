/**
 * DeFi Agent
 *
 * Main agent class that orchestrates DeFi strategies.
 */

import { EventEmitter } from 'events';
import type { MpcAgentWallet } from '@mpc-wallet/sdk';
import type { BaseStrategy, StrategyAction } from './strategies/base.js';

export interface AgentConfig {
  wallet: MpcAgentWallet;
  relayUrl: string;
  rpcUrls: Record<string, string>;
  riskParameters: RiskParameters;
}

export interface RiskParameters {
  maxPositionSize: bigint;
  maxDailyLoss: bigint;
  maxSlippage: number;
  minLiquidity: number;
}

export interface AgentStatus {
  running: boolean;
  activeStrategies: string[];
  portfolioValue: string;
  pendingApprovals: number;
  dailyPnL: string;
}

export class DeFiAgent extends EventEmitter {
  private config: AgentConfig;
  private strategies: Map<string, BaseStrategy> = new Map();
  private running = false;
  private evaluationInterval: NodeJS.Timeout | null = null;
  private pendingApprovals: Set<string> = new Set();
  private dailyPnL = BigInt(0);

  constructor(config: AgentConfig) {
    super();
    this.config = config;
  }

  /**
   * Add a strategy to the agent
   */
  addStrategy(strategy: BaseStrategy): void {
    this.strategies.set(strategy.name, strategy);
  }

  /**
   * Remove a strategy
   */
  removeStrategy(name: string): void {
    this.strategies.delete(name);
  }

  /**
   * Start the agent
   */
  async start(): Promise<void> {
    if (this.running) {
      throw new Error('Agent already running');
    }

    this.running = true;

    // Start strategy evaluation loop
    this.evaluationInterval = setInterval(async () => {
      await this.evaluateStrategies();
    }, 60000); // Evaluate every minute

    // Initial evaluation
    await this.evaluateStrategies();
  }

  /**
   * Stop the agent
   */
  async stop(): Promise<void> {
    this.running = false;

    if (this.evaluationInterval) {
      clearInterval(this.evaluationInterval);
      this.evaluationInterval = null;
    }
  }

  /**
   * Pause all strategies
   */
  pause(): void {
    this.running = false;
  }

  /**
   * Resume strategies
   */
  resume(): void {
    this.running = true;
  }

  /**
   * Get current status
   */
  async getStatus(): Promise<AgentStatus> {
    const portfolioValue = await this.getPortfolioValue();

    return {
      running: this.running,
      activeStrategies: Array.from(this.strategies.keys()),
      portfolioValue: `${formatEther(portfolioValue)} ETH`,
      pendingApprovals: this.pendingApprovals.size,
      dailyPnL: `${this.dailyPnL >= 0 ? '+' : ''}${formatEther(this.dailyPnL)} ETH`,
    };
  }

  /**
   * Get total portfolio value in ETH
   */
  async getPortfolioValue(): Promise<bigint> {
    // In production, aggregate all positions and balances
    return BigInt('12500000000000000000'); // Mock: 12.5 ETH
  }

  /**
   * Evaluate all strategies and execute actions
   */
  private async evaluateStrategies(): Promise<void> {
    if (!this.running) return;

    for (const [name, strategy] of this.strategies) {
      try {
        const context = await this.buildStrategyContext();
        const action = await strategy.evaluate(context);

        if (action) {
          this.emit('strategy:action', { strategy: name, ...action });
          await this.executeAction(action);
        }
      } catch (error) {
        this.emit('error', { strategy: name, error });
      }
    }
  }

  /**
   * Build context for strategy evaluation
   */
  private async buildStrategyContext() {
    const portfolioValue = await this.getPortfolioValue();

    return {
      wallet: this.config.wallet,
      portfolioValue,
      riskParameters: this.config.riskParameters,
      // In production, add market data, positions, etc.
    };
  }

  /**
   * Execute a strategy action
   */
  private async executeAction(action: StrategyAction): Promise<void> {
    // Check risk parameters
    if (!this.checkRiskLimits(action)) {
      this.emit('action:rejected', { action, reason: 'Risk limits exceeded' });
      return;
    }

    // Check policy
    const policyCheck = this.config.wallet.evaluatePolicy({
      requestId: crypto.randomUUID(),
      chain: 0, // EVM
      to: action.params.to ?? '',
      value: action.params.value?.toString() ?? '0',
      chainId: 1,
      timestamp: Date.now(),
    });

    if (!policyCheck.approved) {
      this.emit('action:rejected', { action, reason: policyCheck.reason });
      return;
    }

    // Request approval
    const sessionId = crypto.randomUUID();
    this.pendingApprovals.add(sessionId);

    this.emit('approval:requested', {
      sessionId,
      action,
      requiresRecovery: policyCheck.requiresAdditionalApproval,
    });

    // In production, send to relay and wait for approval
    // For demo, auto-approve after delay
    setTimeout(() => {
      this.pendingApprovals.delete(sessionId);

      this.emit('transaction:executed', {
        hash: '0x' + crypto.randomUUID().replace(/-/g, ''),
        action,
      });
    }, 3000);
  }

  /**
   * Check if action passes risk limits
   */
  private checkRiskLimits(action: StrategyAction): boolean {
    const { riskParameters } = this.config;

    // Check position size
    const value = BigInt(action.params.value ?? 0);
    if (value > riskParameters.maxPositionSize) {
      return false;
    }

    // Check daily loss limit
    if (this.dailyPnL < -riskParameters.maxDailyLoss) {
      return false;
    }

    // Check slippage
    if ((action.params.slippage ?? 0) > riskParameters.maxSlippage) {
      return false;
    }

    return true;
  }

  /**
   * Execute a manual trade
   */
  async executeTrade(params: {
    type: 'swap' | 'deposit' | 'withdraw';
    tokenIn?: string;
    tokenOut?: string;
    amount: string;
    protocol?: string;
  }): Promise<{ success: boolean; txHash?: string; error?: string }> {
    const action: StrategyAction = {
      type: params.type,
      params: {
        tokenIn: params.tokenIn,
        tokenOut: params.tokenOut,
        value: BigInt(Math.floor(parseFloat(params.amount) * 1e18)),
      },
      reason: 'Manual trade',
    };

    try {
      await this.executeAction(action);
      return { success: true };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  }

  /**
   * Set risk parameters
   */
  setRiskParameters(params: Partial<RiskParameters>): void {
    this.config.riskParameters = {
      ...this.config.riskParameters,
      ...params,
    };
  }
}

function formatEther(wei: bigint): string {
  const eth = Number(wei) / 1e18;
  return eth.toFixed(4);
}
