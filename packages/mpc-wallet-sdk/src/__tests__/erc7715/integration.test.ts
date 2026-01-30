/**
 * ERC-7715 Integration Tests
 *
 * End-to-end tests for the complete ERC-7715 permission flow including
 * SDK integration, permission lifecycle, and multi-party scenarios.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  ERC7715Provider,
  PermissionRequestBuilder,
  createERC7715Provider,
} from '../../erc7715/provider';
import { PermissionManager } from '../../erc7715/manager';
import type { ChainIdHex, Action, PermissionResponse } from '../../erc7715/types';

// Test constants
const TEST_CHAINS: ChainIdHex[] = ['0x1' as ChainIdHex, '0x2105' as ChainIdHex];
const WALLET_ADDRESS = '0x1234567890123456789012345678901234567890' as const;
const AGENT_ADDRESS = '0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd' as const;
const UNISWAP_ROUTER = '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45' as const;
const USDC_ADDRESS = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' as const;

describe('ERC-7715 Integration Tests', () => {
  let provider: ERC7715Provider;
  let executedActions: { context: string; actions: Action[] }[] = [];

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-01-15T12:00:00Z'));
    executedActions = [];

    provider = createERC7715Provider({
      accountAddress: WALLET_ADDRESS,
      chainId: TEST_CHAINS[0],
      permissionManagerConfig: {
        supportedChains: TEST_CHAINS,
      },
      onApprovalRequest: async () => true, // Auto-approve for testing
      onExecuteActions: async (context, actions) => {
        executedActions.push({ context: context as string, actions: [...actions] });
        return ('0x' + 'a'.repeat(64)) as `0x${string}`;
      },
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('Full Permission Flow', () => {
    it('should complete full permission request -> execute -> revoke flow', async () => {
      // 1. Request permission
      const permission = await provider.requestPermissions({
        chainId: TEST_CHAINS[0],
        expiry: Math.floor(Date.now() / 1000) + 86400,
        signer: { type: 'account', data: { id: AGENT_ADDRESS } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0xDE0B6B3A7640000' },
            required: true,
          },
        ],
      });

      expect(permission.permissionId).toBeDefined();
      expect(provider.isPermissionValid(permission.permissionId)).toBe(true);

      // 2. Execute action
      const action: Action = {
        to: '0x9999999999999999999999999999999999999999',
        value: '0x38D7EA4C68000',
        data: '0x',
      };

      const result = await provider.executeWithPermission(
        permission.permissionsContext,
        [action]
      );

      expect(result.success).toBe(true);
      expect(executedActions.length).toBe(1);
      expect(executedActions[0].actions[0].to).toBe(action.to);

      // 3. Revoke permission
      const revoked = await provider.revokePermission(permission.permissionId);

      expect(revoked.success).toBe(true);
      expect(provider.isPermissionValid(permission.permissionId)).toBe(false);

      // 4. Verify execution fails after revocation
      await expect(
        provider.executeWithPermission(permission.permissionsContext, [action])
      ).rejects.toThrow();
    });

    it('should handle multiple concurrent permissions', async () => {
      // Request multiple permissions
      const permission1 = await provider.requestPermissions({
        chainId: TEST_CHAINS[0],
        expiry: Math.floor(Date.now() / 1000) + 3600,
        signer: { type: 'account', data: { id: AGENT_ADDRESS } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0xDE0B6B3A7640000' },
            required: true,
          },
        ],
      });

      const permission2 = await provider.requestPermissions({
        chainId: TEST_CHAINS[0],
        expiry: Math.floor(Date.now() / 1000) + 7200,
        signer: { type: 'account', data: { id: AGENT_ADDRESS } },
        permissions: [
          {
            type: 'contract-call',
            data: {
              address: UNISWAP_ROUTER,
              calls: [{ selector: '0x5ae401dc' }],
            },
            required: true,
          },
        ],
      });

      expect(permission1.permissionId).not.toBe(permission2.permissionId);

      // Query all granted permissions
      const granted = await provider.getGrantedPermissions();
      expect(granted.permissions.length).toBe(2);

      // Both should be valid
      expect(provider.isPermissionValid(permission1.permissionId)).toBe(true);
      expect(provider.isPermissionValid(permission2.permissionId)).toBe(true);

      // Revoke one, other should remain valid
      await provider.revokePermission(permission1.permissionId);
      expect(provider.isPermissionValid(permission1.permissionId)).toBe(false);
      expect(provider.isPermissionValid(permission2.permissionId)).toBe(true);
    });
  });

  describe('Complex Permission Scenarios', () => {
    it('should handle DeFi trading permission with multiple constraints', async () => {
      // Build a realistic DeFi permission
      const request = new PermissionRequestBuilder(TEST_CHAINS[0])
        .expireIn(86400) // 24 hours
        .withSigner({ type: 'account', data: { id: AGENT_ADDRESS } })
        // Allow ETH spending for swaps
        .allowNativeTransfer('0x1BC16D674EC80000') // 2 ETH
        // Allow USDC transfers
        .allowErc20Transfer(USDC_ADDRESS, '0x2540BE400') // 10,000 USDC
        // Allow Uniswap router calls
        .allowContractCall(UNISWAP_ROUTER, [
          '0x5ae401dc', // multicall
          '0x04e45aaf', // exactInputSingle
          '0x5023b4df', // exactOutputSingle
        ])
        // Rate limit
        .allowRateLimit(20, 3600) // 20 tx/hour
        // Spending policy
        .withSpendingLimit('0x1BC16D674EC80000') // 2 ETH max
        // Gas limit
        .withGasLimit('0xF4240') // 1M gas
        .build();

      const permission = await provider.requestPermissions(request);

      expect(permission.permissions.length).toBe(4);

      // Execute a swap action
      const swapAction: Action = {
        to: UNISWAP_ROUTER,
        value: '0x8AC7230489E80000', // 10 ETH - but limited by permission
        data: '0x04e45aaf' + '0'.repeat(64 * 6), // exactInputSingle call
      };

      // Should fail because value exceeds native-token-transfer allowance
      await expect(
        provider.executeWithPermission(permission.permissionsContext, [swapAction])
      ).rejects.toThrow(/exceeds/i);

      // Execute with valid amount
      const validSwapAction: Action = {
        to: UNISWAP_ROUTER,
        value: '0xDE0B6B3A7640000', // 1 ETH
        data: '0x04e45aaf' + '0'.repeat(64 * 6),
      };

      const result = await provider.executeWithPermission(
        permission.permissionsContext,
        [validSwapAction]
      );

      expect(result.success).toBe(true);
    });

    it('should enforce whitelist restrictions', async () => {
      const allowedContract = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      const blockedContract = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

      const permission = await provider.requestPermissions({
        chainId: TEST_CHAINS[0],
        expiry: Math.floor(Date.now() / 1000) + 3600,
        signer: { type: 'account', data: { id: AGENT_ADDRESS } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0xDE0B6B3A7640000' },
            required: true,
          },
          {
            type: 'contract-call',
            data: {
              address: allowedContract,
              calls: [],
            },
            required: true,
          },
        ],
      });

      // Should succeed with allowed contract
      const allowedAction: Action = {
        to: allowedContract,
        value: '0x0',
        data: '0xdeadbeef',
      };

      const result = await provider.executeWithPermission(
        permission.permissionsContext,
        [allowedAction]
      );
      expect(result.success).toBe(true);

      // Should fail with blocked contract
      const blockedAction: Action = {
        to: blockedContract,
        value: '0x0',
        data: '0xdeadbeef',
      };

      await expect(
        provider.executeWithPermission(permission.permissionsContext, [blockedAction])
      ).rejects.toThrow(/not permitted/i);
    });

    it('should handle batch actions', async () => {
      const permission = await provider.requestPermissions({
        chainId: TEST_CHAINS[0],
        expiry: Math.floor(Date.now() / 1000) + 3600,
        signer: { type: 'account', data: { id: AGENT_ADDRESS } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0xDE0B6B3A7640000' }, // 1 ETH
            required: true,
          },
        ],
      });

      const actions: Action[] = [
        {
          to: '0x1111111111111111111111111111111111111111',
          value: '0x38D7EA4C68000', // 0.001 ETH
          data: '0x',
        },
        {
          to: '0x2222222222222222222222222222222222222222',
          value: '0x38D7EA4C68000', // 0.001 ETH
          data: '0x',
        },
        {
          to: '0x3333333333333333333333333333333333333333',
          value: '0x38D7EA4C68000', // 0.001 ETH
          data: '0x',
        },
      ];

      const result = await provider.executeWithPermission(
        permission.permissionsContext,
        actions
      );

      expect(result.success).toBe(true);
      expect(executedActions.length).toBe(1);
      expect(executedActions[0].actions.length).toBe(3);
    });
  });

  describe('Expiry and Time-based Tests', () => {
    it('should reject expired permissions', async () => {
      const permission = await provider.requestPermissions({
        chainId: TEST_CHAINS[0],
        expiry: Math.floor(Date.now() / 1000) + 60, // 1 minute
        signer: { type: 'account', data: { id: AGENT_ADDRESS } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0xDE0B6B3A7640000' },
            required: true,
          },
        ],
      });

      // Initially valid
      expect(provider.isPermissionValid(permission.permissionId)).toBe(true);
      expect(provider.getPermissionTimeRemaining(permission.permissionId)).toBeGreaterThan(0);

      // Fast forward past expiry
      vi.advanceTimersByTime(120 * 1000); // 2 minutes

      // Now expired
      expect(provider.isPermissionValid(permission.permissionId)).toBe(false);
      expect(provider.getPermissionTimeRemaining(permission.permissionId)).toBe(0);

      // Execution should fail
      const action: Action = {
        to: '0x9999999999999999999999999999999999999999',
        value: '0x1',
        data: '0x',
      };

      await expect(
        provider.executeWithPermission(permission.permissionsContext, [action])
      ).rejects.toThrow();
    });

    it('should track time remaining correctly', async () => {
      const duration = 7200; // 2 hours
      const permission = await provider.requestPermissions({
        chainId: TEST_CHAINS[0],
        expiry: Math.floor(Date.now() / 1000) + duration,
        signer: { type: 'account', data: { id: AGENT_ADDRESS } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0x1' },
            required: true,
          },
        ],
      });

      // Initial time remaining
      let remaining = provider.getPermissionTimeRemaining(permission.permissionId);
      expect(remaining).toBeLessThanOrEqual(duration);
      expect(remaining).toBeGreaterThan(duration - 5);

      // After 1 hour
      vi.advanceTimersByTime(3600 * 1000);
      remaining = provider.getPermissionTimeRemaining(permission.permissionId);
      expect(remaining).toBeLessThanOrEqual(3600);
      expect(remaining).toBeGreaterThan(3595);

      // After 2 hours (expired)
      vi.advanceTimersByTime(3600 * 1000);
      remaining = provider.getPermissionTimeRemaining(permission.permissionId);
      expect(remaining).toBe(0);
    });
  });

  describe('Error Handling', () => {
    it('should handle missing permission gracefully', async () => {
      const fakeContext = '0x01' + '00'.repeat(68);

      const action: Action = {
        to: '0x9999999999999999999999999999999999999999',
        value: '0x1',
        data: '0x',
      };

      await expect(
        provider.executeWithPermission(fakeContext as any, [action])
      ).rejects.toThrow();
    });

    it('should reject permission requests for unsupported chains', async () => {
      const unsupportedChain = '0xBAD' as ChainIdHex;

      await expect(
        provider.requestPermissions({
          chainId: unsupportedChain,
          expiry: Math.floor(Date.now() / 1000) + 3600,
          signer: { type: 'account', data: { id: AGENT_ADDRESS } },
          permissions: [
            {
              type: 'native-token-transfer',
              data: { allowance: '0x1' },
              required: true,
            },
          ],
        })
      ).rejects.toThrow(/not supported/i);
    });

    it('should handle user denial of permission request', async () => {
      const denyingProvider = createERC7715Provider({
        accountAddress: WALLET_ADDRESS,
        chainId: TEST_CHAINS[0],
        onApprovalRequest: async () => false, // Always deny
      });

      await expect(
        denyingProvider.requestPermissions({
          chainId: TEST_CHAINS[0],
          expiry: Math.floor(Date.now() / 1000) + 3600,
          signer: { type: 'account', data: { id: AGENT_ADDRESS } },
          permissions: [
            {
              type: 'native-token-transfer',
              data: { allowance: '0x1' },
              required: true,
            },
          ],
        })
      ).rejects.toThrow(/denied/i);
    });
  });

  describe('Chain Switching', () => {
    it('should switch chains and maintain permissions', async () => {
      // Initial chain
      expect(provider.getChainId()).toBe(TEST_CHAINS[0]);

      // Grant permission on first chain
      const permission1 = await provider.requestPermissions({
        chainId: TEST_CHAINS[0],
        expiry: Math.floor(Date.now() / 1000) + 3600,
        signer: { type: 'account', data: { id: AGENT_ADDRESS } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0x1' },
            required: true,
          },
        ],
      });

      // Switch chain
      await provider.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: TEST_CHAINS[1] }],
      });

      expect(provider.getChainId()).toBe(TEST_CHAINS[1]);

      // Permission from first chain should still be tracked
      const granted = await provider.getGrantedPermissions({
        chainId: TEST_CHAINS[0],
      });
      expect(granted.permissions.length).toBe(1);

      // Query second chain should be empty
      const granted2 = await provider.getGrantedPermissions({
        chainId: TEST_CHAINS[1],
      });
      expect(granted2.permissions.length).toBe(0);
    });
  });
});
