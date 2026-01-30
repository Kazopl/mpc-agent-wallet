/**
 * ERC-7715 RPC Handler Tests
 *
 * Unit tests for ERC-7715 JSON-RPC method handlers.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  createERC7715RpcRouter,
  createRequestExecutionPermissionsHandler,
  createRevokeExecutionPermissionHandler,
  createGetSupportedExecutionPermissionsHandler,
  createGetGrantedExecutionPermissionsHandler,
  isERC7715Method,
  ERC7715RpcError,
  createRpcErrorResponse,
  createRpcSuccessResponse,
  type ERC7715RpcRouterConfig,
} from '../../erc7715/rpc';
import { PermissionManager } from '../../erc7715/manager';
import { ERC7715ErrorCode, type ChainIdHex, type PermissionId } from '../../erc7715/types';

// Test constants
const TEST_CHAIN: ChainIdHex = '0x1' as ChainIdHex;
const TEST_ACCOUNT = '0x1234567890123456789012345678901234567890' as const;
const TEST_AGENT = '0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd' as const;

describe('ERC-7715 RPC Handlers', () => {
  let manager: PermissionManager;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-01-15T12:00:00Z'));

    manager = new PermissionManager({
      supportedChains: [TEST_CHAIN],
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('isERC7715Method', () => {
    it('should identify ERC-7715 methods', () => {
      expect(isERC7715Method('wallet_requestExecutionPermissions')).toBe(true);
      expect(isERC7715Method('wallet_revokeExecutionPermission')).toBe(true);
      expect(isERC7715Method('wallet_getSupportedExecutionPermissions')).toBe(true);
      expect(isERC7715Method('wallet_getGrantedExecutionPermissions')).toBe(true);
    });

    it('should reject non-ERC-7715 methods', () => {
      expect(isERC7715Method('eth_chainId')).toBe(false);
      expect(isERC7715Method('eth_sendTransaction')).toBe(false);
      expect(isERC7715Method('wallet_connect')).toBe(false);
      expect(isERC7715Method('')).toBe(false);
    });
  });

  describe('wallet_requestExecutionPermissions', () => {
    let handler: ReturnType<typeof createRequestExecutionPermissionsHandler>;

    beforeEach(() => {
      handler = createRequestExecutionPermissionsHandler(manager, {
        defaultAccount: TEST_ACCOUNT,
      });
    });

    it('should grant permission with valid request', async () => {
      const now = Math.floor(Date.now() / 1000);
      const params = [
        {
          chainId: TEST_CHAIN,
          expiry: now + 3600,
          signer: { type: 'account' as const, data: { id: TEST_AGENT } },
          permissions: [
            {
              type: 'native-token-transfer' as const,
              data: { allowance: '0xDE0B6B3A7640000' },
              required: true,
            },
          ],
        },
      ] as const;

      const response = await handler(params);

      expect(response.permissionId).toBeDefined();
      expect(response.expiry).toBe(params[0].expiry);
      expect(response.permissionsContext).toBeDefined();
    });

    it('should reject missing params', async () => {
      await expect(handler([] as any)).rejects.toThrow(ERC7715RpcError);
    });

    it('should reject invalid chain ID', async () => {
      const params = [
        {
          chainId: 'invalid',
          expiry: Math.floor(Date.now() / 1000) + 3600,
          signer: { type: 'account' as const, data: { id: TEST_AGENT } },
          permissions: [],
        },
      ] as const;

      await expect(handler(params as any)).rejects.toThrow(/Invalid chain ID/);
    });

    it('should reject past expiry', async () => {
      const params = [
        {
          chainId: TEST_CHAIN,
          expiry: Math.floor(Date.now() / 1000) - 60, // 1 minute ago
          signer: { type: 'account' as const, data: { id: TEST_AGENT } },
          permissions: [
            {
              type: 'native-token-transfer' as const,
              data: { allowance: '0x1' },
              required: true,
            },
          ],
        },
      ] as const;

      await expect(handler(params)).rejects.toThrow(/must be in the future/);
    });

    it('should reject empty permissions array', async () => {
      const params = [
        {
          chainId: TEST_CHAIN,
          expiry: Math.floor(Date.now() / 1000) + 3600,
          signer: { type: 'account' as const, data: { id: TEST_AGENT } },
          permissions: [],
        },
      ] as const;

      await expect(handler(params)).rejects.toThrow(/At least one permission/);
    });

    it('should reject unsupported chain', async () => {
      const params = [
        {
          chainId: '0xBAD' as ChainIdHex,
          expiry: Math.floor(Date.now() / 1000) + 3600,
          signer: { type: 'account' as const, data: { id: TEST_AGENT } },
          permissions: [
            {
              type: 'native-token-transfer' as const,
              data: { allowance: '0x1' },
              required: true,
            },
          ],
        },
      ] as const;

      await expect(handler(params)).rejects.toThrow(/not supported/);
    });

    it('should call approval callback', async () => {
      const onApprovalRequest = vi.fn().mockResolvedValue(true);
      const handlerWithApproval = createRequestExecutionPermissionsHandler(manager, {
        defaultAccount: TEST_ACCOUNT,
        onApprovalRequest,
      });

      const params = [
        {
          chainId: TEST_CHAIN,
          expiry: Math.floor(Date.now() / 1000) + 3600,
          signer: { type: 'account' as const, data: { id: TEST_AGENT } },
          permissions: [
            {
              type: 'native-token-transfer' as const,
              data: { allowance: '0x1' },
              required: true,
            },
          ],
        },
      ] as const;

      await handlerWithApproval(params);

      expect(onApprovalRequest).toHaveBeenCalled();
    });

    it('should reject when user denies approval', async () => {
      const onApprovalRequest = vi.fn().mockResolvedValue(false);
      const handlerWithApproval = createRequestExecutionPermissionsHandler(manager, {
        defaultAccount: TEST_ACCOUNT,
        onApprovalRequest,
      });

      const params = [
        {
          chainId: TEST_CHAIN,
          expiry: Math.floor(Date.now() / 1000) + 3600,
          signer: { type: 'account' as const, data: { id: TEST_AGENT } },
          permissions: [
            {
              type: 'native-token-transfer' as const,
              data: { allowance: '0x1' },
              required: true,
            },
          ],
        },
      ] as const;

      await expect(handlerWithApproval(params)).rejects.toThrow(/denied/);
    });
  });

  describe('wallet_revokeExecutionPermission', () => {
    let handler: ReturnType<typeof createRevokeExecutionPermissionHandler>;
    let permissionId: PermissionId;

    beforeEach(async () => {
      handler = createRevokeExecutionPermissionHandler(manager);

      // Create a permission first
      const response = await manager.grantPermission({
        chainId: TEST_CHAIN,
        address: TEST_ACCOUNT,
        expiry: Math.floor(Date.now() / 1000) + 3600,
        signer: { type: 'account', data: { id: TEST_AGENT } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0x1' },
            required: true,
          },
        ],
      });
      permissionId = response.permissionId;
    });

    it('should revoke existing permission', async () => {
      const params = [{ permissionId, chainId: TEST_CHAIN }] as const;

      const response = await handler(params);

      expect(response.success).toBe(true);
      expect(response.permissionId).toBe(permissionId);
      expect(response.revokedAt).toBeGreaterThan(0);
    });

    it('should reject missing params', async () => {
      await expect(handler([] as any)).rejects.toThrow(ERC7715RpcError);
    });

    it('should reject invalid permission ID', async () => {
      const params = [{ permissionId: '0x123', chainId: TEST_CHAIN }] as const;

      await expect(handler(params as any)).rejects.toThrow(/Invalid permission ID/);
    });

    it('should reject non-existent permission', async () => {
      const fakeId = ('0x' + 'a'.repeat(64)) as PermissionId;
      const params = [{ permissionId: fakeId, chainId: TEST_CHAIN }] as const;

      await expect(handler(params)).rejects.toThrow(/not found/);
    });

    it('should reject already revoked permission', async () => {
      // Revoke first time
      await handler([{ permissionId, chainId: TEST_CHAIN }]);

      // Try to revoke again
      await expect(
        handler([{ permissionId, chainId: TEST_CHAIN }])
      ).rejects.toThrow(/already been revoked/);
    });
  });

  describe('wallet_getSupportedExecutionPermissions', () => {
    let handler: ReturnType<typeof createGetSupportedExecutionPermissionsHandler>;

    beforeEach(() => {
      handler = createGetSupportedExecutionPermissionsHandler(manager);
    });

    it('should return supported permissions', async () => {
      const params = [{ chainId: TEST_CHAIN }] as const;

      const response = await handler(params);

      expect(response.chainId).toBe(TEST_CHAIN);
      expect(response.permissions.length).toBeGreaterThan(0);
    });

    it('should reject missing params', async () => {
      await expect(handler([] as any)).rejects.toThrow(ERC7715RpcError);
    });

    it('should reject invalid chain ID', async () => {
      const params = [{ chainId: 'bad' }] as const;

      await expect(handler(params as any)).rejects.toThrow(/Invalid chain ID/);
    });

    it('should reject unsupported chain', async () => {
      const params = [{ chainId: '0xBAD' as ChainIdHex }] as const;

      await expect(handler(params)).rejects.toThrow(/not supported/);
    });
  });

  describe('wallet_getGrantedExecutionPermissions', () => {
    let handler: ReturnType<typeof createGetGrantedExecutionPermissionsHandler>;

    beforeEach(async () => {
      handler = createGetGrantedExecutionPermissionsHandler(manager, {
        defaultAccount: TEST_ACCOUNT,
      });

      // Create some permissions
      await manager.grantPermission({
        chainId: TEST_CHAIN,
        address: TEST_ACCOUNT,
        expiry: Math.floor(Date.now() / 1000) + 3600,
        signer: { type: 'account', data: { id: TEST_AGENT } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0x1' },
            required: true,
          },
        ],
      });
    });

    it('should return granted permissions', async () => {
      const params = [{ chainId: TEST_CHAIN }] as const;

      const response = await handler(params);

      expect(response.chainId).toBe(TEST_CHAIN);
      expect(response.permissions.length).toBe(1);
    });

    it('should filter by address', async () => {
      const params = [
        {
          chainId: TEST_CHAIN,
          address: '0x0000000000000000000000000000000000000000',
        },
      ] as const;

      const response = await handler(params);

      expect(response.permissions.length).toBe(0);
    });

    it('should reject missing params', async () => {
      await expect(handler([] as any)).rejects.toThrow(ERC7715RpcError);
    });

    it('should reject invalid chain ID', async () => {
      const params = [{ chainId: 'bad' }] as const;

      await expect(handler(params as any)).rejects.toThrow(/Invalid chain ID/);
    });
  });

  describe('ERC7715RpcRouter', () => {
    let router: ReturnType<typeof createERC7715RpcRouter>;

    beforeEach(() => {
      const config: ERC7715RpcRouterConfig = {
        permissionManager: manager,
        defaultAccount: TEST_ACCOUNT,
      };
      router = createERC7715RpcRouter(config);
    });

    it('should route to correct handler', async () => {
      const response = await router.handleRequest({
        method: 'wallet_getSupportedExecutionPermissions',
        params: [{ chainId: TEST_CHAIN }],
      });

      expect(response).toBeDefined();
      expect((response as any).chainId).toBe(TEST_CHAIN);
    });

    it('should reject unknown method', async () => {
      await expect(
        router.handleRequest({
          method: 'unknown_method' as any,
          params: [],
        })
      ).rejects.toThrow(/Unknown method/);
    });
  });

  describe('RPC Response Helpers', () => {
    it('should create error response', () => {
      const error = new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        'Test error'
      );

      const response = createRpcErrorResponse('1', error);

      expect(response.jsonrpc).toBe('2.0');
      expect(response.id).toBe('1');
      expect(response.error.code).toBe(ERC7715ErrorCode.InvalidRequest);
      expect(response.error.message).toBe('Test error');
    });

    it('should create success response', () => {
      const result = { data: 'test' };

      const response = createRpcSuccessResponse('1', result);

      expect(response.jsonrpc).toBe('2.0');
      expect(response.id).toBe('1');
      expect(response.result).toEqual(result);
    });

    it('should handle null id', () => {
      const error = new ERC7715RpcError(ERC7715ErrorCode.InvalidRequest, 'Test');
      const errorResponse = createRpcErrorResponse(null, error);
      expect(errorResponse.id).toBeNull();

      const successResponse = createRpcSuccessResponse(null, {});
      expect(successResponse.id).toBeNull();
    });
  });

  describe('ERC7715RpcError', () => {
    it('should create error with code and message', () => {
      const error = new ERC7715RpcError(
        ERC7715ErrorCode.PermissionDenied,
        'Permission denied'
      );

      expect(error.code).toBe(ERC7715ErrorCode.PermissionDenied);
      expect(error.message).toBe('Permission denied');
      expect(error.name).toBe('ERC7715RpcError');
    });

    it('should create error with data', () => {
      const error = new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        'Invalid',
        { field: 'test' }
      );

      expect(error.data).toEqual({ field: 'test' });
    });

    it('should serialize to JSON', () => {
      const error = new ERC7715RpcError(
        ERC7715ErrorCode.ChainNotSupported,
        'Chain not supported',
        { chainId: '0xBAD' }
      );

      const json = error.toJSON();

      expect(json.code).toBe(ERC7715ErrorCode.ChainNotSupported);
      expect(json.message).toBe('Chain not supported');
      expect(json.data).toEqual({ chainId: '0xBAD' });
    });
  });
});
