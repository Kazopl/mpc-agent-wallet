/**
 * ERC-7715 AI Agent Demo
 *
 * A standalone demo that doesn't require blockchain connectivity.
 * Shows the full workflow of requesting and using ERC-7715 permissions.
 */

import {
  PermissionRequestBuilder,
  createERC7715Provider,
} from '@mpc-wallet/sdk';

import type {
  ChainIdHex,
  Action,
  PermissionRequest,
  PermissionsContext,
} from '@mpc-wallet/sdk/erc7715';

// Demo addresses
const DEMO_WALLET = '0x1234567890123456789012345678901234567890' as const;
const DEMO_AGENT = '0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd' as const;
const DEMO_CHAIN: ChainIdHex = '0x1' as ChainIdHex; // Ethereum Mainnet

// Sample contract addresses
const UNISWAP_ROUTER = '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45' as const;
const USDC_ADDRESS = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' as const;

async function demo() {
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║           ERC-7715 Wallet Execution Permissions Demo          ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log();

  // Step 1: Create the provider
  console.log('┌─ Step 1: Initialize ERC-7715 Provider ─────────────────────────┐');
  const provider = createERC7715Provider({
    accountAddress: DEMO_WALLET,
    chainId: DEMO_CHAIN,
    onApprovalRequest: async (request: PermissionRequest): Promise<boolean> => {
      console.log('│ Permission request received:');
      console.log(`│    Chain: ${request.chainId}`);
      console.log(`│    Expiry: ${new Date(request.expiry * 1000).toLocaleString()}`);
      console.log(`│    Permissions: ${request.permissions.length}`);
      for (const perm of request.permissions) {
        console.log(`│      - ${perm.type}`);
      }
      console.log('│ Auto-approving for demo...');
      return true;
    },
    onExecuteActions: async (
      context: PermissionsContext,
      actions: readonly Action[]
    ): Promise<`0x${string}`> => {
      console.log(`│ Executing ${actions.length} action(s)`);
      console.log(`│    Context: ${(context as string).slice(0, 20)}...`);
      for (const action of actions) {
        console.log(`│    -> ${action.to.slice(0, 10)}... value=${action.value}`);
      }
      // Return mock transaction hash
      return ('0x' + 'a'.repeat(64)) as `0x${string}`;
    },
  });
  console.log('│ [OK] Provider created');
  console.log('└───────────────────────────────────────────────────────────────┘');
  console.log();

  // Step 2: Query supported permissions
  console.log('┌─ Step 2: Query Supported Permissions ─────────────────────────┐');
  const supported = await provider.getSupportedPermissions();
  console.log('│ Supported permission types:');
  for (const perm of supported.permissions) {
    console.log(`│   - ${perm.type}`);
    console.log(`│     Policies: ${perm.supportedPolicies.join(', ')}`);
  }
  console.log('└───────────────────────────────────────────────────────────────┘');
  console.log();

  // Step 3: Request permissions using the builder
  console.log('┌─ Step 3: Request Trading Permissions ─────────────────────────┐');
  console.log('│ Building permission request...');

  const permissionRequest = new PermissionRequestBuilder(DEMO_CHAIN)
    .expireIn(3600)  // 1 hour
    .withSigner({
      type: 'account',
      data: { id: DEMO_AGENT },
    })
    // Allow up to 1 ETH native token transfer
    .allowNativeTransfer('0xDE0B6B3A7640000')
    // Allow USDC transfers up to 1000 USDC
    .allowErc20Transfer(USDC_ADDRESS, '0x3B9ACA00')
    // Allow calls to Uniswap router
    .allowContractCall(UNISWAP_ROUTER, [
      '0x5ae401dc', // multicall
      '0x04e45aaf', // exactInputSingle
    ])
    // Limit to 10 tx per hour
    .allowRateLimit(10, 3600)
    // Add spending limit policy
    .withSpendingLimit('0xDE0B6B3A7640000')
    // Add gas limit policy
    .withGasLimit('0x7A120')
    .build();

  console.log('│');
  console.log('│ Permission request:');
  console.log(`│   Chain: ${permissionRequest.chainId}`);
  console.log(`│   Expiry: ${new Date(permissionRequest.expiry * 1000).toLocaleString()}`);
  console.log(`│   Signer: ${DEMO_AGENT.slice(0, 10)}...`);
  console.log(`│   Permissions: ${permissionRequest.permissions.length}`);
  console.log('│');

  // Request permission
  const permission = await provider.requestPermissions(permissionRequest);

  console.log('│ [OK] Permission granted!');
  console.log(`│   ID: ${permission.permissionId.slice(0, 20)}...`);
  console.log(`│   Context: ${permission.permissionsContext.slice(0, 20)}...`);
  console.log('└───────────────────────────────────────────────────────────────┘');
  console.log();

  // Step 4: Execute actions using permission
  console.log('┌─ Step 4: Execute Actions with Permission ─────────────────────┐');

  // 4a: Simple ETH transfer
  console.log('│ 4a. Simple ETH Transfer');
  const transferAction: Action = {
    to: '0x9999999999999999999999999999999999999999',
    value: '0x38D7EA4C68000', // 0.001 ETH
    data: '0x',
  };

  const transferResult = await provider.executeWithPermission(
    permission.permissionsContext,
    [transferAction]
  );
  console.log(`│     Result: ${transferResult.success ? '[OK] Success' : '[FAIL] Failed'}`);
  console.log(`│     Tx Hash: ${transferResult.transactionHash.slice(0, 20)}...`);
  console.log('│');

  // 4b: Contract call (Uniswap swap)
  console.log('│ 4b. Contract Call (Uniswap Swap)');
  const swapAction: Action = {
    to: UNISWAP_ROUTER,
    value: '0x16345785D8A0000', // 0.1 ETH
    data: ('0x04e45aaf' + // exactInputSingle selector
      '0'.repeat(64) + // tokenIn (padded)
      '0'.repeat(64) + // tokenOut (padded)
      '0'.repeat(64)) as `0x${string}`,  // params
  };

  const swapResult = await provider.executeWithPermission(
    permission.permissionsContext,
    [swapAction]
  );
  console.log(`│     Result: ${swapResult.success ? '[OK] Success' : '[FAIL] Failed'}`);
  console.log(`│     Tx Hash: ${swapResult.transactionHash.slice(0, 20)}...`);
  console.log('└───────────────────────────────────────────────────────────────┘');
  console.log();

  // Step 5: Check permission status
  console.log('┌─ Step 5: Check Permission Status ─────────────────────────────┐');
  const isValid = provider.isPermissionValid(permission.permissionId);
  const timeRemaining = provider.getPermissionTimeRemaining(permission.permissionId);
  const granted = await provider.getGrantedPermissions();

  console.log(`│ Permission ${permission.permissionId.slice(0, 16)}...`);
  console.log(`│   Valid: ${isValid ? '[OK] Yes' : '[NO] No'}`);
  console.log(`│   Time Remaining: ${timeRemaining} seconds`);
  console.log(`│   Total Granted: ${granted.permissions.length}`);
  console.log('└───────────────────────────────────────────────────────────────┘');
  console.log();

  // Step 6: Demonstrate error handling
  console.log('┌─ Step 6: Error Handling ──────────────────────────────────────┐');

  // Try to execute to non-whitelisted contract
  console.log('│ 6a. Attempting call to non-whitelisted contract...');
  try {
    const badAction: Action = {
      to: '0x0000000000000000000000000000000000000bad',
      value: '0x0',
      data: '0xdeadbeef', // Random selector
    };
    await provider.executeWithPermission(permission.permissionsContext, [badAction]);
    console.log('│     [FAIL] Should have failed!');
  } catch (error) {
    console.log(`│     [OK] Correctly rejected: ${(error as Error).message.slice(0, 40)}...`);
  }
  console.log('│');

  // Try to exceed spending limit
  console.log('│ 6b. Attempting to exceed spending limit...');
  try {
    const bigAction: Action = {
      to: '0x9999999999999999999999999999999999999999',
      value: '0x56BC75E2D63100000', // 100 ETH
      data: '0x',
    };
    await provider.executeWithPermission(permission.permissionsContext, [bigAction]);
    console.log('│     [FAIL] Should have failed!');
  } catch (error) {
    console.log(`│     [OK] Correctly rejected: ${(error as Error).message.slice(0, 40)}...`);
  }
  console.log('└───────────────────────────────────────────────────────────────┘');
  console.log();

  // Step 7: Revoke permission
  console.log('┌─ Step 7: Revoke Permission ───────────────────────────────────┐');
  const revoked = await provider.revokePermission(permission.permissionId);
  console.log(`│ Revoked: ${revoked.success ? '[OK] Yes' : '[FAIL] No'}`);
  console.log(`│ Revoked At: ${new Date(revoked.revokedAt * 1000).toLocaleString()}`);

  // Verify revocation
  const isStillValid = provider.isPermissionValid(permission.permissionId);
  console.log(`│ Still Valid: ${isStillValid ? '[FAIL] Yes (bug!)' : '[OK] No (correct)'}`);
  console.log('└───────────────────────────────────────────────────────────────┘');
  console.log();

  // Summary
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║                         Demo Complete!                         ║');
  console.log('╠══════════════════════════════════════════════════════════════╣');
  console.log('║ This demo showed:                                             ║');
  console.log('║  - Querying supported permissions                             ║');
  console.log('║  - Building permission requests with the builder pattern      ║');
  console.log('║  - Granting fine-grained execution permissions               ║');
  console.log('║  - Executing actions within permission bounds                ║');
  console.log('║  - Permission validation and error handling                  ║');
  console.log('║  - Revoking permissions                                       ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
}

// Run demo
demo().catch((error) => {
  console.error('Demo failed:', error);
  process.exit(1);
});
