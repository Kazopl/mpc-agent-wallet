/**
 * ERC-7715 Permission Manager Tests
 *
 * Unit tests for PermissionManager including permission lifecycle,
 * conversion to session keys, and context validation.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { PermissionManager, type PermissionManagerConfig } from '../../erc7715/manager';
import type {
  ChainIdHex,
  PermissionRequest,
  Permission,
  SignerInfo,
  PermissionId,
} from '../../erc7715/types';

// Test constants
const TEST_CHAIN: ChainIdHex = '0x1' as ChainIdHex;
const TEST_ACCOUNT = '0x1234567890123456789012345678901234567890';
const TEST_AGENT = '0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd';

// Helper to create a basic permission request
function createTestRequest(overrides: Partial<PermissionRequest> = {}): PermissionRequest & { address: string } {
  const now = Math.floor(Date.now() / 1000);
  return {
    chainId: TEST_CHAIN,
    address: TEST_ACCOUNT,
    expiry: now + 3600, // 1 hour
    signer: {
      type: 'account',
      data: { id: TEST_AGENT },
    },
    permissions: [
      {
        type: 'native-token-transfer',
        data: { allowance: '0xDE0B6B3A7640000' }, // 1 ETH
        required: true,
      },
    ],
    ...overrides,
  };
}

describe('PermissionManager', () => {
  let manager: PermissionManager;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-01-15T12:00:00Z'));

    manager = new PermissionManager({
      supportedChains: [TEST_CHAIN, '0x89' as ChainIdHex],
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('Chain Support', () => {
    it('should check chain support', () => {
      expect(manager.isChainSupported(TEST_CHAIN)).toBe(true);
      expect(manager.isChainSupported('0x89' as ChainIdHex)).toBe(true);
      expect(manager.isChainSupported('0xBAD' as ChainIdHex)).toBe(false);
    });

    it('should add chain support', () => {
      expect(manager.isChainSupported('0xNEW' as ChainIdHex)).toBe(false);
      manager.addChainSupport('0xNEW' as ChainIdHex);
      expect(manager.isChainSupported('0xNEW' as ChainIdHex)).toBe(true);
    });

    it('should remove chain support', () => {
      expect(manager.isChainSupported('0x89' as ChainIdHex)).toBe(true);
      manager.removeChainSupport('0x89' as ChainIdHex);
      expect(manager.isChainSupported('0x89' as ChainIdHex)).toBe(false);
    });

    it('should get supported chains', () => {
      const chains = manager.getSupportedChains();
      expect(chains).toContain(TEST_CHAIN);
      expect(chains).toContain('0x89');
      expect(chains.length).toBe(2);
    });
  });

  describe('Supported Permissions Query', () => {
    it('should return supported permissions', () => {
      const response = manager.getSupportedPermissions(TEST_CHAIN);

      expect(response.chainId).toBe(TEST_CHAIN);
      expect(response.permissions.length).toBeGreaterThan(0);

      const permTypes = response.permissions.map((p) => p.type);
      expect(permTypes).toContain('native-token-transfer');
      expect(permTypes).toContain('erc20-token-transfer');
      expect(permTypes).toContain('contract-call');
      expect(permTypes).toContain('rate-limit');
    });

    it('should include supported policies for each permission type', () => {
      const response = manager.getSupportedPermissions(TEST_CHAIN);

      const nativeTransfer = response.permissions.find(
        (p) => p.type === 'native-token-transfer'
      );
      expect(nativeTransfer).toBeDefined();
      expect(nativeTransfer!.supportedPolicies).toContain('spending-limit');
      expect(nativeTransfer!.supportedPolicies).toContain('rate-limit');
    });
  });

  describe('Grant Permission', () => {
    it('should grant a basic permission', async () => {
      const request = createTestRequest();
      const response = await manager.grantPermission(request);

      expect(response.permissionId).toBeDefined();
      expect(response.expiry).toBe(request.expiry);
      expect(response.signer).toEqual(request.signer);
      expect(response.permissions.length).toBe(1);
      expect(response.permissionsContext).toBeDefined();
      expect(response.permissionsContext.startsWith('0x')).toBe(true);
      expect(response.chainId).toBe(TEST_CHAIN);
      expect(response.accountAddress).toBe(TEST_ACCOUNT);
    });

    it('should create session key for granted permission', async () => {
      const request = createTestRequest();
      const response = await manager.grantPermission(request);

      const sessionKey = manager.getSessionKeyForPermission(response.permissionId);
      expect(sessionKey).not.toBeNull();
      expect(sessionKey?.spendingLimit).toBe(BigInt('0xDE0B6B3A7640000'));
    });

    it('should grant permission with multiple permission types', async () => {
      const request = createTestRequest({
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0xDE0B6B3A7640000' },
            required: true,
          },
          {
            type: 'erc20-token-transfer',
            data: {
              address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
              allowance: '0x3B9ACA00',
            },
            required: true,
          },
          {
            type: 'contract-call',
            data: {
              address: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
              calls: [{ selector: '0x5ae401dc' }],
            },
            required: true,
          },
        ] as Permission[],
      });

      const response = await manager.grantPermission(request);

      expect(response.permissions.length).toBe(3);

      // Check session key has whitelist
      const sessionKey = manager.getSessionKeyForPermission(response.permissionId);
      expect(sessionKey?.whitelist.length).toBe(2); // ERC20 + contract
    });

    it('should reject permission with excessive duration', async () => {
      const now = Math.floor(Date.now() / 1000);
      const request = createTestRequest({
        expiry: now + 40 * 24 * 60 * 60, // 40 days (exceeds 30 day max)
      });

      await expect(manager.grantPermission(request)).rejects.toThrow(
        /exceeds maximum/
      );
    });

    it('should apply spending limit policy', async () => {
      const request = createTestRequest({
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0x1BC16D674EC80000' }, // 2 ETH
            required: true,
          },
        ] as Permission[],
        policies: [
          {
            type: 'spending-limit',
            data: { allowance: '0xDE0B6B3A7640000' }, // 1 ETH (more restrictive)
          },
        ],
      });

      const response = await manager.grantPermission(request);
      const sessionKey = manager.getSessionKeyForPermission(response.permissionId);

      // Spending limit should be the more restrictive policy value
      expect(sessionKey?.spendingLimit).toBe(BigInt('0xDE0B6B3A7640000'));
    });
  });

  describe('Revoke Permission', () => {
    it('should revoke a permission', async () => {
      const request = createTestRequest();
      const response = await manager.grantPermission(request);

      const revoked = await manager.revokePermission(response.permissionId);

      expect(revoked.success).toBe(true);
      expect(revoked.permissionId).toBe(response.permissionId);
      expect(revoked.revokedAt).toBeGreaterThan(0);

      // Verify permission is no longer valid
      const info = manager.getPermissionInfo(response.permissionId);
      expect(info?.status).toBe('revoked');
    });

    it('should throw when revoking non-existent permission', async () => {
      const fakeId = ('0x' + 'a'.repeat(64)) as PermissionId;
      await expect(manager.revokePermission(fakeId)).rejects.toThrow(
        /not found/
      );
    });

    it('should revoke associated session key', async () => {
      const request = createTestRequest();
      const response = await manager.grantPermission(request);

      // Verify session key exists before revocation
      let sessionKey = manager.getSessionKeyForPermission(response.permissionId);
      expect(sessionKey).not.toBeNull();
      expect(sessionKey?.revoked).toBe(false);

      await manager.revokePermission(response.permissionId);

      // Session key should be revoked
      sessionKey = manager.getSessionKeyForPermission(response.permissionId);
      expect(sessionKey?.revoked).toBe(true);
    });
  });

  describe('Query Permissions', () => {
    it('should get permission by ID', async () => {
      const request = createTestRequest();
      const response = await manager.grantPermission(request);

      const permission = manager.getPermission(response.permissionId);

      expect(permission).not.toBeNull();
      expect(permission?.permissionId).toBe(response.permissionId);
      expect(permission?.expiry).toBe(response.expiry);
    });

    it('should return null for non-existent permission', () => {
      const fakeId = ('0x' + 'b'.repeat(64)) as PermissionId;
      expect(manager.getPermission(fakeId)).toBeNull();
    });

    it('should get permission info including status', async () => {
      const request = createTestRequest();
      const response = await manager.grantPermission(request);

      const info = manager.getPermissionInfo(response.permissionId);

      expect(info).not.toBeNull();
      expect(info?.status).toBe('active');
      expect(info?.grantedAt).toBeGreaterThan(0);
    });

    it('should mark expired permissions', async () => {
      const now = Math.floor(Date.now() / 1000);
      const request = createTestRequest({
        expiry: now + 60, // 1 minute
      });

      const response = await manager.grantPermission(request);

      // Initially active
      let info = manager.getPermissionInfo(response.permissionId);
      expect(info?.status).toBe('active');

      // Fast forward past expiry
      vi.advanceTimersByTime(120 * 1000); // 2 minutes

      // Now expired
      info = manager.getPermissionInfo(response.permissionId);
      expect(info?.status).toBe('expired');
    });

    it('should get granted permissions for account', async () => {
      // Grant multiple permissions
      const request1 = createTestRequest();
      const request2 = createTestRequest();

      await manager.grantPermission(request1);
      await manager.grantPermission(request2);

      const response = manager.getGrantedPermissions({
        chainId: TEST_CHAIN,
        address: TEST_ACCOUNT,
      });

      expect(response.chainId).toBe(TEST_CHAIN);
      expect(response.accountAddress).toBe(TEST_ACCOUNT);
      expect(response.permissions.length).toBe(2);
    });

    it('should filter by chain ID', async () => {
      const request = createTestRequest();
      await manager.grantPermission(request);

      const response = manager.getGrantedPermissions({
        chainId: '0x89' as ChainIdHex, // Different chain
      });

      expect(response.permissions.length).toBe(0);
    });

    it('should get active permissions only', async () => {
      const request1 = createTestRequest();
      const request2 = createTestRequest();

      const response1 = await manager.grantPermission(request1);
      await manager.grantPermission(request2);

      // Revoke the first one
      await manager.revokePermission(response1.permissionId);

      const active = manager.getActivePermissions(TEST_CHAIN, TEST_ACCOUNT);

      expect(active.length).toBe(1);
      expect(active[0].status).toBe('active');
    });
  });

  describe('Permission Context Validation', () => {
    it('should validate valid permissions context', async () => {
      const request = createTestRequest();
      const response = await manager.grantPermission(request);

      const validation = manager.validatePermissionsContext(response.permissionsContext);

      expect(validation.valid).toBe(true);
      expect(validation.permissionId).toBe(response.permissionId);
      expect(validation.error).toBeUndefined();
    });

    it('should reject context with wrong version', () => {
      // Create invalid context with version 0x02
      const invalidContext = '0x02' + '00'.repeat(68);

      const validation = manager.validatePermissionsContext(invalidContext as any);

      expect(validation.valid).toBe(false);
      expect(validation.error).toContain('Unsupported context version');
    });

    it('should reject context with unknown permission ID', () => {
      // Create context with valid version but unknown permission ID
      const unknownId = '00'.repeat(32);
      const signerBytes = '00'.repeat(20);
      const expiryBytes = '00'.repeat(8);
      const chainBytes = '00'.repeat(8);
      const invalidContext = `0x01${unknownId}${signerBytes}${expiryBytes}${chainBytes}`;

      const validation = manager.validatePermissionsContext(invalidContext as any);

      expect(validation.valid).toBe(false);
      expect(validation.error).toContain('Permission not found');
    });

    it('should reject context for revoked permission', async () => {
      const request = createTestRequest();
      const response = await manager.grantPermission(request);

      await manager.revokePermission(response.permissionId);

      const validation = manager.validatePermissionsContext(response.permissionsContext);

      expect(validation.valid).toBe(false);
      expect(validation.error).toContain('revoked');
    });

    it('should reject context for expired permission', async () => {
      const now = Math.floor(Date.now() / 1000);
      const request = createTestRequest({
        expiry: now + 60, // 1 minute
      });

      const response = await manager.grantPermission(request);

      // Fast forward past expiry
      vi.advanceTimersByTime(120 * 1000);

      const validation = manager.validatePermissionsContext(response.permissionsContext);

      expect(validation.valid).toBe(false);
      expect(validation.error).toContain('expired');
    });

    it('should reject too short context', () => {
      const shortContext = '0x0100000000';

      const validation = manager.validatePermissionsContext(shortContext as any);

      expect(validation.valid).toBe(false);
      expect(validation.error).toContain('too short');
    });
  });

  describe('Cleanup and Statistics', () => {
    it('should cleanup expired permissions', async () => {
      const now = Math.floor(Date.now() / 1000);

      // Grant expiring permission
      const request1 = createTestRequest({
        expiry: now + 60, // 1 minute
      });
      await manager.grantPermission(request1);

      // Grant long-lasting permission
      const request2 = createTestRequest({
        expiry: now + 3600, // 1 hour
      });
      await manager.grantPermission(request2);

      // Fast forward past first expiry
      vi.advanceTimersByTime(120 * 1000);

      const removed = manager.cleanup();

      expect(removed).toBe(1);

      // Check stats
      const stats = manager.getStats();
      expect(stats.total).toBe(1);
      expect(stats.active).toBe(1);
      expect(stats.expired).toBe(0);
    });

    it('should get statistics', async () => {
      const now = Math.floor(Date.now() / 1000);

      // Grant multiple permissions
      const request1 = createTestRequest();
      const request2 = createTestRequest({
        expiry: now + 60, // Short expiry
      });

      const response1 = await manager.grantPermission(request1);
      await manager.grantPermission(request2);

      // Revoke one
      await manager.revokePermission(response1.permissionId);

      // Fast forward to expire the second
      vi.advanceTimersByTime(120 * 1000);

      const stats = manager.getStats();

      expect(stats.total).toBe(2);
      expect(stats.revoked).toBe(1);
      expect(stats.expired).toBe(1);
      expect(stats.active).toBe(0);
    });

    it('should clear all permissions', async () => {
      await manager.grantPermission(createTestRequest());
      await manager.grantPermission(createTestRequest());

      expect(manager.getStats().total).toBe(2);

      manager.clear();

      expect(manager.getStats().total).toBe(0);
    });
  });

  describe('Policy Configuration', () => {
    it('should create PolicyConfig from permissions', () => {
      const permissions: Permission[] = [
        {
          type: 'erc20-token-transfer',
          data: {
            address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
            allowance: '0x100',
          },
          required: true,
        },
        {
          type: 'contract-call',
          data: {
            address: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
            calls: [],
          },
          required: true,
        },
      ];

      const policyConfig = PermissionManager.createPolicyFromPermissions(permissions);

      expect(policyConfig).toBeDefined();
      // PolicyConfig should have whitelist with both addresses
    });

    it('should apply spending-limit policy to config', () => {
      const permissions: Permission[] = [
        {
          type: 'native-token-transfer',
          data: { allowance: '0xDE0B6B3A7640000' },
          required: true,
        },
      ];

      const policies = [
        {
          type: 'spending-limit' as const,
          data: { allowance: '0x1000' },
        },
      ];

      const policyConfig = PermissionManager.createPolicyFromPermissions(
        permissions,
        policies
      );

      expect(policyConfig).toBeDefined();
    });
  });
});
