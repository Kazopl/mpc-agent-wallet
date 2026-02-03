/**
 * Agent-to-Agent Demo
 *
 * Demonstrates the full workflow of two AI agents:
 * 1. Registering their identities (ERC-8004 Identity Registry)
 * 2. Discovering each other
 * 3. Verifying reputation before transacting
 * 4. Executing a cross-agent transaction
 * 5. Submitting feedback after the transaction
 */

import { TrustModel } from '@mpc-wallet/sdk';
import { AgentClient, parseEther, formatEther } from './agent.js';
import {
  registerInSimulatedRegistry,
  discoverAgent,
  formatAgentInfo,
  hasService,
  clearSimulatedRegistry,
} from './discovery.js';
import {
  submitFeedback,
  checkReputation,
  meetsReputationThreshold,
  formatReputation,
  clearSimulatedReputation,
} from './reputation.js';

async function main() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('           MPC Agent Wallet - Agent-to-Agent Demo              ');
  console.log('═══════════════════════════════════════════════════════════════\n');

  clearSimulatedRegistry();
  clearSimulatedReputation();

  // ============================================================================
  // Step 1: Create and initialize both agents
  // ============================================================================
  console.log('[Step 1] Creating and initializing agents...\n');

  const alice = new AgentClient('alice', {
    name: 'AliceTradingAgent',
    description: 'An automated DeFi trading assistant specializing in token swaps',
    version: '2.0.0',
    services: [
      {
        name: 'swap',
        endpoint: 'https://alice.agent.ai/api/swap',
        description: 'Execute token swaps across multiple DEXs',
      },
      {
        name: 'quote',
        endpoint: 'https://alice.agent.ai/api/quote',
        description: 'Get best swap quotes',
      },
    ],
    trustModels: [TrustModel.Reputation, TrustModel.CryptoEconomic],
    website: 'https://alice.agent.ai',
  });

  const bob = new AgentClient('bob', {
    name: 'BobLiquidityAgent',
    description: 'Liquidity provision and yield farming automation agent',
    version: '1.5.0',
    services: [
      {
        name: 'provide-liquidity',
        endpoint: 'https://bob.agent.ai/api/provide',
        description: 'Add liquidity to AMM pools',
      },
      {
        name: 'harvest',
        endpoint: 'https://bob.agent.ai/api/harvest',
        description: 'Harvest farming rewards',
      },
    ],
    trustModels: [TrustModel.Reputation],
    website: 'https://bob.agent.ai',
  });

  await alice.initialize();
  await bob.initialize();

  console.log('');

  // ============================================================================
  // Step 2: Register both agents in the Identity Registry
  // ============================================================================
  console.log('[Step 2] Registering agents in ERC-8004 Identity Registry...\n');

  await alice.register();
  await bob.register();

  registerInSimulatedRegistry(alice);
  registerInSimulatedRegistry(bob);

  console.log('');

  // ============================================================================
  // Step 3: Simulate some initial reputation for Bob
  // ============================================================================
  console.log('[Step 3] Building initial reputation...\n');

  const fakeReviewer1 = new AgentClient('reviewer1', {
    name: 'TrustedReviewer1',
    description: 'A trusted protocol reviewer',
  });
  await fakeReviewer1.initialize();
  await fakeReviewer1.register();

  const fakeReviewer2 = new AgentClient('reviewer2', {
    name: 'TrustedReviewer2',
    description: 'Another trusted reviewer',
  });
  await fakeReviewer2.initialize();
  await fakeReviewer2.register();

  await submitFeedback({
    fromAgent: fakeReviewer1,
    toAgentId: bob.getAgentId(),
    value: 450n,
    decimals: 2,
    tags: ['reliability', 'execution'],
    proofOfPayment: '0x' + '1'.repeat(64),
  });

  await submitFeedback({
    fromAgent: fakeReviewer2,
    toAgentId: bob.getAgentId(),
    value: 380n,
    decimals: 2,
    tags: ['speed', 'accuracy'],
    proofOfPayment: '0x' + '2'.repeat(64),
  });

  console.log('');

  // ============================================================================
  // Step 4: Alice discovers Bob
  // ============================================================================
  console.log('[Step 4] Alice discovers Bob through Identity Registry...\n');

  const discoveredBob = await discoverAgent(bob.getAgentId());

  console.log('\n--- Discovered Agent Info ---');
  console.log(formatAgentInfo(discoveredBob));
  console.log('');

  const hasLiquidityService = hasService(discoveredBob, 'provide-liquidity');
  console.log(`Has liquidity service: ${hasLiquidityService}`);
  console.log('');

  // ============================================================================
  // Step 5: Alice checks Bob's reputation
  // ============================================================================
  console.log('[Step 5] Alice verifies Bob\'s reputation...\n');

  const bobReputation = await checkReputation(bob.getAgentId());

  console.log('\n--- Reputation Summary ---');
  console.log(formatReputation(bobReputation));
  console.log('');

  const REPUTATION_THRESHOLD = 0.7;
  const reputationOk = meetsReputationThreshold(bobReputation, REPUTATION_THRESHOLD);

  if (!reputationOk) {
    console.log(`[Alice] Bob's reputation is below threshold (${REPUTATION_THRESHOLD}). Aborting transaction.`);
    return;
  }

  console.log(`[Alice] Bob's reputation meets threshold. Proceeding with transaction.\n`);

  // ============================================================================
  // Step 6: Alice sends payment to Bob
  // ============================================================================
  console.log('[Step 6] Alice sends payment to Bob...\n');

  const paymentAmount = parseEther('0.1');

  const policyResult = await alice.evaluatePolicy(bob.getWalletAddress(), paymentAmount);
  if (!policyResult.approved) {
    console.log(`[Alice] Policy rejected transaction: ${policyResult.reason}`);
    return;
  }

  console.log(`[Alice] Policy approved. Sending ${formatEther(paymentAmount)} ETH...`);

  const txHash = await alice.sendTo(bob.getWalletAddress(), paymentAmount);

  console.log(`[Alice] Transaction confirmed: ${txHash.slice(0, 18)}...\n`);

  // ============================================================================
  // Step 7: Alice submits positive feedback for Bob
  // ============================================================================
  console.log('[Step 7] Alice submits feedback for Bob...\n');

  await submitFeedback({
    fromAgent: alice,
    toAgentId: bob.getAgentId(),
    value: 420n,
    decimals: 2,
    tags: ['reliability', 'liquidity'],
    proofOfPayment: txHash,
  });

  console.log('');

  // ============================================================================
  // Step 8: Check updated reputation
  // ============================================================================
  console.log('[Step 8] Checking Bob\'s updated reputation...\n');

  const updatedReputation = await checkReputation(bob.getAgentId());

  console.log('\n--- Updated Reputation ---');
  console.log(formatReputation(updatedReputation));
  console.log('');

  // ============================================================================
  // Summary
  // ============================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('                         Demo Complete                          ');
  console.log('═══════════════════════════════════════════════════════════════\n');

  console.log('Summary:');
  console.log('  1. Created two AI agents (Alice and Bob)');
  console.log('  2. Registered both in ERC-8004 Identity Registry');
  console.log('  3. Built initial reputation for Bob');
  console.log('  4. Alice discovered Bob through the registry');
  console.log('  5. Alice verified Bob\'s reputation (threshold: 0.7)');
  console.log('  6. Alice sent 0.1 ETH payment to Bob');
  console.log('  7. Alice submitted positive feedback with proof of payment');
  console.log('  8. Bob\'s reputation improved from 3 feedback signals');
  console.log('');
  console.log('This demonstrates the trustless agent economy enabled by ERC-8004!\n');
}

main().catch(console.error);
