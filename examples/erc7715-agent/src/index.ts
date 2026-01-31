/**
 * ERC-7715 AI Agent - Entry Point
 *
 * Demonstrates an AI agent using ERC-7715 wallet execution permissions
 * to autonomously execute transactions with fine-grained constraints.
 */

import 'dotenv/config';
import { ERC7715Agent, type AgentConfig } from './agent.js';
import type { ChainIdHex } from '@mpc-wallet/sdk/erc7715';

// Configuration from environment
const config: AgentConfig = {
  walletAddress: (process.env.WALLET_ADDRESS ?? '0x') as `0x${string}`,
  agentAddress: process.env.AGENT_ADDRESS as `0x${string}` | undefined,
  chainId: (process.env.CHAIN_ID ?? '0x14a34') as ChainIdHex, // Base Sepolia default
  maxSpendingLimit: BigInt(process.env.MAX_SPENDING_LIMIT ?? '1000000000000000000'), // 1 ETH default
};

async function main() {
  console.log('='.repeat(60));
  console.log('  ERC-7715 AI Agent - Wallet Execution Permissions Demo');
  console.log('='.repeat(60));
  console.log();

  // Validate configuration
  if (!config.walletAddress || config.walletAddress === '0x') {
    console.log('Please set WALLET_ADDRESS in .env file');
    console.log('Example: WALLET_ADDRESS=0x1234567890123456789012345678901234567890');
    process.exit(1);
  }

  // Create agent
  const agent = new ERC7715Agent(config);
  console.log('Agent initialized');
  console.log(`  Wallet: ${config.walletAddress}`);
  console.log(`  Chain: ${config.chainId}`);
  console.log();

  // Query supported permissions
  console.log('Querying supported permissions...');
  const supported = await agent.getSupportedPermissions();
  console.log('Supported permission types:');
  for (const perm of supported.permissions) {
    console.log(`  - ${perm.type}`);
    console.log(`    Policies: ${perm.supportedPolicies.join(', ')}`);
  }
  console.log();

  // Request trading permissions
  console.log('Requesting trading permissions...');
  const permission = await agent.requestTradingPermission({
    spendingLimit: '0.1', // 0.1 ETH
    duration: 3600,       // 1 hour
    allowedProtocols: ['uniswap'],
  });

  console.log('Permission granted!');
  console.log(`  Permission ID: ${permission.permissionId.slice(0, 18)}...`);
  console.log(`  Expires: ${new Date(permission.expiry * 1000).toISOString()}`);
  console.log();

  // Get permission status
  const status = await agent.getPermissionStatus();
  console.log('Current permission status:');
  console.log(`  Active permissions: ${status.activeCount}`);
  console.log(`  Total spending limit: ${status.totalSpendingLimit} wei`);
  console.log();

  // Demonstrate executing actions
  console.log('Simulating trade execution...');
  try {
    const result = await agent.executeSwap({
      tokenIn: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE', // ETH
      tokenOut: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', // USDC on Base
      amountIn: '0.01',
      minAmountOut: '10',
    });

    console.log('Trade executed!');
    console.log(`  Transaction: ${result.transactionHash}`);
  } catch (error) {
    console.log('Trade simulation (no actual execution in demo)');
    console.log(`  Would swap 0.01 ETH for USDC`);
  }
  console.log();

  // Show remaining allowance
  const remaining = agent.getRemainingAllowance();
  console.log('Remaining permissions:');
  console.log(`  Spending: ${remaining.spending} wei`);
  console.log(`  Time: ${remaining.timeSeconds} seconds`);
  console.log();

  // Cleanup
  console.log('Revoking permissions...');
  await agent.revokeAllPermissions();
  console.log('All permissions revoked');
  console.log();

  console.log('Demo complete!');
}

main().catch((error) => {
  console.error('Error:', error.message);
  process.exit(1);
});
