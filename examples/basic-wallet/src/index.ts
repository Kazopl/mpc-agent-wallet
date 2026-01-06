/**
 * Basic MPC Wallet Example
 *
 * Demonstrates core wallet functionality:
 * - Creating a wallet with policy
 * - Key generation
 * - Transaction signing
 * - Key share storage
 */

import {
  MpcAgentWallet,
  PartyRole,
  PolicyConfig,
  ChainType,
  type TransactionRequest,
} from '@mpc-wallet/sdk';
import { simulateKeyGeneration, type SimulatedKeyShares } from './keygen.js';
import { signWithSimulatedParties } from './signing.js';

// Utility to parse ETH amounts
function parseEther(eth: string): bigint {
  return BigInt(Math.floor(parseFloat(eth) * 1e18));
}

async function main() {
  console.log('MPC Agent Wallet - Basic Example\n');

  // ============================================================================
  // Step 1: Create wallet with spending policy
  // ============================================================================
  console.log('[1] Creating wallet with policy...');

  const wallet = await MpcAgentWallet.create({
    role: PartyRole.Agent,
    policy: new PolicyConfig()
      .withPerTxLimit(parseEther('1'))  // Max 1 ETH per transaction
      .withDailyLimit(parseEther('10'))  // Max 10 ETH per day
      .withWeeklyLimit(parseEther('50'))  // Max 50 ETH per week
      .withWhitelist([
        '0x742d35Cc6634C0532925a3b844Bc9e7595f12345', // Example allowed address
        '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45', // Uniswap Router
      ])
      .withTimeBounds({
        startHour: 6,
        endHour: 22,
        allowedDays: [1, 2, 3, 4, 5], // Weekdays only
      }),
  });

  console.log('    [OK] Wallet created with policy\n');

  // ============================================================================
  // Step 2: Generate key shares (simulated 3-party DKG)
  // ============================================================================
  console.log('[2] Generating key shares (simulated 3-party DKG)...');

  const keyShares: SimulatedKeyShares = await simulateKeyGeneration();

  // Agent gets its share
  wallet.setKeyShare(keyShares.agent);

  console.log('    [OK] Key generation complete');
  console.log(`    Wallet Address: ${wallet.getAddress()}`);
  console.log(`    Public Key: ${wallet.getPublicKey().slice(0, 20)}...\n`);

  // ============================================================================
  // Step 3: Test policy evaluation
  // ============================================================================
  console.log('[3] Testing policy evaluation...\n');

  // Test 1: Valid transaction
  const validTx: TransactionRequest = {
    requestId: crypto.randomUUID(),
    chain: ChainType.Evm,
    to: '0x742d35Cc6634C0532925a3b844Bc9e7595f12345',
    value: parseEther('0.5').toString(),
    chainId: 1,
    timestamp: Date.now(),
  };

  const validResult = wallet.evaluatePolicy(validTx);
  console.log('    Transaction: 0.5 ETH to whitelisted address');
  console.log(`    Result: ${validResult.approved ? '[OK] Approved' : '[FAIL] Rejected'}\n`);

  // Test 2: Exceeds per-transaction limit
  const tooLargeTx: TransactionRequest = {
    requestId: crypto.randomUUID(),
    chain: ChainType.Evm,
    to: '0x742d35Cc6634C0532925a3b844Bc9e7595f12345',
    value: parseEther('2').toString(), // 2 ETH > 1 ETH limit
    chainId: 1,
    timestamp: Date.now(),
  };

  const tooLargeResult = wallet.evaluatePolicy(tooLargeTx);
  console.log('    Transaction: 2 ETH (exceeds 1 ETH limit)');
  console.log(`    Result: ${tooLargeResult.approved ? '[OK] Approved' : `[FAIL] Rejected - ${tooLargeResult.reason}`}\n`);

  // Test 3: Non-whitelisted address
  const nonWhitelistedTx: TransactionRequest = {
    requestId: crypto.randomUUID(),
    chain: ChainType.Evm,
    to: '0x0000000000000000000000000000000000000001', // Not whitelisted
    value: parseEther('0.1').toString(),
    chainId: 1,
    timestamp: Date.now(),
  };

  const nonWhitelistedResult = wallet.evaluatePolicy(nonWhitelistedTx);
  console.log('    Transaction: 0.1 ETH to non-whitelisted address');
  console.log(`    Result: ${nonWhitelistedResult.approved ? '[OK] Approved' : `[FAIL] Rejected - ${nonWhitelistedResult.reason}`}\n`);

  // ============================================================================
  // Step 4: Sign a valid transaction
  // ============================================================================
  console.log('[4] Signing valid transaction...');

  if (validResult.approved) {
    try {
      const signature = await signWithSimulatedParties(
        wallet,
        keyShares,
        validTx,
        [PartyRole.Agent, PartyRole.User] // 2-of-3 signing
      );

      console.log('    [OK] Transaction signed successfully');
      console.log(`    Signature R: ${signature.r.slice(0, 20)}...`);
      console.log(`    Signature S: ${signature.s.slice(0, 20)}...`);
      console.log(`    Recovery ID: ${signature.recoveryId}\n`);
    } catch (error) {
      console.log(`    [FAIL] Signing failed: ${error}\n`);
    }
  }

  // ============================================================================
  // Step 5: Save and load key share
  // ============================================================================
  console.log('[5] Testing key share storage...');

  const password = 'secure-test-password-123';
  const shareId = 'test-wallet-' + Date.now();

  // Save key share
  await wallet.saveKeyShare(shareId, password);
  console.log(`    Key share saved: ${shareId}`);

  // Create new wallet and load the share
  const loadedWallet = await MpcAgentWallet.create({
    role: PartyRole.Agent,
    policy: wallet.getPolicy()!,
  });

  await loadedWallet.loadKeyShare(shareId, password);
  console.log('    Key share loaded into new wallet');
  console.log(`    Address matches: ${loadedWallet.getAddress() === wallet.getAddress()}`);

  // Clean up
  await wallet.deleteKeyShare(shareId);
  console.log('    Key share deleted\n');

  // ============================================================================
  // Summary
  // ============================================================================
  console.log('Summary:');
  console.log('   - Created MPC wallet with spending policy');
  console.log('   - Generated 3 key shares (threshold: 2-of-3)');
  console.log('   - Tested policy evaluation for various scenarios');
  console.log('   - Signed transaction with 2-of-3 parties');
  console.log('   - Saved/loaded encrypted key share');
  console.log('\nExample complete!\n');
}

main().catch(console.error);
