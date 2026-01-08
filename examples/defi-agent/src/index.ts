/**
 * DeFi Agent Example
 *
 * Demonstrates automated DeFi operations with MPC wallet security.
 */

import 'dotenv/config';
import { DeFiAgent } from './agent.js';
import { YieldFarmingStrategy } from './strategies/yield.js';
import { RebalanceStrategy } from './strategies/rebalance.js';
import {
  MpcAgentWallet,
  PartyRole,
  PolicyConfig,
} from '@mpc-wallet/sdk';

async function main() {
  console.log('Starting DeFi Agent...\n');

  // ============================================================================
  // Step 1: Initialize MPC Wallet
  // ============================================================================
  console.log('[1] Initializing MPC Wallet...');

  const wallet = await MpcAgentWallet.create({
    role: PartyRole.Agent,
    policy: new PolicyConfig()
      .withPerTxLimit(parseEther('5'))  // Max 5 ETH per transaction
      .withDailyLimit(parseEther('20'))  // Max 20 ETH daily
      .withWeeklyLimit(parseEther('100'))  // Max 100 ETH weekly
      .withWhitelist([
        // Aave V3
        '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2',
        // Uniswap V3 Router
        '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        // Compound V3
        '0xc3d688B66703497DAA19211EEdff47f25384cdc3',
      ])
      // Require additional approval for large transactions
      .withAdditionalApprovalThreshold(parseEther('10')),
  });

  // Load key share
  const keyPath = process.env.WALLET_KEY_PATH;
  const password = process.env.WALLET_PASSWORD;

  if (keyPath && password) {
    await wallet.loadKeyShare(keyPath, password);
    console.log(`    Wallet: ${wallet.getAddress()}`);
  } else {
    console.log('    [WARN] No key share configured (demo mode)');
  }

  console.log('    [OK] Wallet initialized\n');

  // ============================================================================
  // Step 2: Create DeFi Agent
  // ============================================================================
  console.log('[2] Creating DeFi Agent...');

  const agent = new DeFiAgent({
    wallet,
    relayUrl: process.env.RELAY_URL ?? '',
    rpcUrls: {
      ethereum: process.env.ETH_RPC_URL ?? 'https://eth.llamarpc.com',
      arbitrum: process.env.ARBITRUM_RPC_URL ?? 'https://arb1.arbitrum.io/rpc',
    },
    riskParameters: {
      maxPositionSize: parseEther('10'),
      maxDailyLoss: parseEther('1'),
      maxSlippage: 0.5,
      minLiquidity: 1000000,
    },
  });

  console.log('    [OK] Agent created\n');

  // ============================================================================
  // Step 3: Configure Strategies
  // ============================================================================
  console.log('[3] Configuring strategies...');

  // Yield Farming Strategy
  const yieldStrategy = new YieldFarmingStrategy({
    name: 'yield-farming',
    protocols: ['aave', 'compound'],
    targetAPY: 5,
    maxAllocation: parseEther('10'),
    rebalanceInterval: 24 * 60 * 60 * 1000, // 24 hours
  });

  agent.addStrategy(yieldStrategy);
  console.log('    [OK] Yield farming strategy added');

  // Portfolio Rebalancing Strategy
  const rebalanceStrategy = new RebalanceStrategy({
    name: 'rebalance',
    target: {
      ETH: 50,
      USDC: 30,
      WBTC: 20,
    },
    threshold: 5,
    minTradeSize: parseEther('0.1'),
  });

  agent.addStrategy(rebalanceStrategy);
  console.log('    [OK] Rebalance strategy added\n');

  // ============================================================================
  // Step 4: Start Agent
  // ============================================================================
  console.log('[4] Starting agent...\n');

  // Event handlers
  agent.on('strategy:action', (action) => {
    console.log(`[ACTION] Strategy action: ${action.type}`);
    console.log(`         Reason: ${action.reason}`);
  });

  agent.on('approval:requested', (request) => {
    console.log(`[APPROVAL] Approval requested: ${request.sessionId}`);
  });

  agent.on('transaction:executed', (tx) => {
    console.log(`[TX] Transaction executed: ${tx.hash}`);
  });

  agent.on('error', (error) => {
    console.error(`[ERROR] ${error.message}`);
  });

  // Start the agent
  await agent.start();

  console.log('DeFi Agent is running!\n');
  console.log('Press Ctrl+C to stop\n');

  // Show status periodically
  setInterval(async () => {
    const status = await agent.getStatus();
    console.log('[STATUS]', JSON.stringify(status, null, 2));
  }, 60000);

  // Handle shutdown
  process.on('SIGINT', async () => {
    console.log('\nShutting down...');
    await agent.stop();
    process.exit(0);
  });
}

function parseEther(eth: string | number): bigint {
  const value = typeof eth === 'string' ? parseFloat(eth) : eth;
  return BigInt(Math.floor(value * 1e18));
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
