/**
 * ERC-7715 Module Exports Tests
 *
 * Verify that all exports from the erc7715 module are correct.
 */

import { describe, it, expect } from 'vitest';
import * as erc7715 from '../../erc7715';

describe('ERC-7715 Module Exports', () => {
  describe('Type exports', () => {
    it('should export type guard functions', () => {
      expect(typeof erc7715.isAccountSigner).toBe('function');
      expect(typeof erc7715.isKeySigner).toBe('function');
      expect(typeof erc7715.isKeysSigner).toBe('function');
      expect(typeof erc7715.isNativeTokenTransferPermission).toBe('function');
      expect(typeof erc7715.isErc20TokenTransferPermission).toBe('function');
      expect(typeof erc7715.isContractCallPermission).toBe('function');
      expect(typeof erc7715.isRateLimitPermission).toBe('function');
      expect(typeof erc7715.isValidChainIdHex).toBe('function');
      expect(typeof erc7715.isValidPermissionId).toBe('function');
    });

    it('should export factory functions', () => {
      expect(typeof erc7715.createAccountSigner).toBe('function');
      expect(typeof erc7715.createKeySigner).toBe('function');
      expect(typeof erc7715.createKeysSigner).toBe('function');
      expect(typeof erc7715.createNativeTokenTransferPermission).toBe('function');
      expect(typeof erc7715.createErc20TokenTransferPermission).toBe('function');
      expect(typeof erc7715.createContractCallPermission).toBe('function');
      expect(typeof erc7715.createRateLimitPermission).toBe('function');
      expect(typeof erc7715.createGasLimitPolicy).toBe('function');
      expect(typeof erc7715.createCallLimitPolicy).toBe('function');
      expect(typeof erc7715.createRateLimitPolicy).toBe('function');
      expect(typeof erc7715.createSpendingLimitPolicy).toBe('function');
    });

    it('should export error codes', () => {
      expect(erc7715.ERC7715ErrorCode).toBeDefined();
      expect(erc7715.ERC7715ErrorCode.InvalidRequest).toBe(4100);
      expect(erc7715.ERC7715ErrorCode.UnsupportedPermission).toBe(4101);
      expect(erc7715.ERC7715ErrorCode.PermissionDenied).toBe(4102);
      expect(erc7715.ERC7715ErrorCode.PermissionExpired).toBe(4103);
      expect(erc7715.ERC7715ErrorCode.PermissionRevoked).toBe(4104);
    });
  });

  describe('PermissionManager exports', () => {
    it('should export PermissionManager class', () => {
      expect(erc7715.PermissionManager).toBeDefined();
      expect(typeof erc7715.PermissionManager).toBe('function');

      const manager = new erc7715.PermissionManager({
        supportedChains: ['0x1' as any],
      });
      expect(manager).toBeDefined();
    });
  });

  describe('RPC exports', () => {
    it('should export RPC utilities', () => {
      expect(typeof erc7715.ERC7715RpcError).toBe('function');
      expect(typeof erc7715.createERC7715RpcRouter).toBe('function');
      expect(typeof erc7715.createRequestExecutionPermissionsHandler).toBe('function');
      expect(typeof erc7715.createRevokeExecutionPermissionHandler).toBe('function');
      expect(typeof erc7715.createGetSupportedExecutionPermissionsHandler).toBe('function');
      expect(typeof erc7715.createGetGrantedExecutionPermissionsHandler).toBe('function');
      expect(typeof erc7715.isERC7715Method).toBe('function');
      expect(typeof erc7715.createRpcErrorResponse).toBe('function');
      expect(typeof erc7715.createRpcSuccessResponse).toBe('function');
    });
  });

  describe('Provider exports', () => {
    it('should export ERC7715Provider class', () => {
      expect(erc7715.ERC7715Provider).toBeDefined();
      expect(typeof erc7715.ERC7715Provider).toBe('function');
    });

    it('should export PermissionRequestBuilder class', () => {
      expect(erc7715.PermissionRequestBuilder).toBeDefined();
      expect(typeof erc7715.PermissionRequestBuilder).toBe('function');
    });

    it('should export createERC7715Provider factory', () => {
      expect(typeof erc7715.createERC7715Provider).toBe('function');
    });
  });

  describe('Module usage', () => {
    it('should be usable as a complete module', async () => {
      // Create provider
      const provider = erc7715.createERC7715Provider({
        accountAddress: '0x1234567890123456789012345678901234567890',
        chainId: '0x1' as any,
        onApprovalRequest: async () => true,
      });

      expect(provider).toBeDefined();
      expect(provider.getAccountAddress()).toBe(
        '0x1234567890123456789012345678901234567890'
      );
      expect(provider.getChainId()).toBe('0x1');

      // Query supported permissions
      const supported = await provider.getSupportedPermissions();
      expect(supported.permissions.length).toBeGreaterThan(0);
    });

    it('should allow building permission requests', () => {
      const builder = new erc7715.PermissionRequestBuilder('0x1' as any);

      const request = builder
        .expireIn(3600)
        .withSigner({
          type: 'account',
          data: { id: '0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd' },
        })
        .allowNativeTransfer('0xDE0B6B3A7640000')
        .build();

      expect(request.chainId).toBe('0x1');
      expect(request.permissions.length).toBe(1);
    });
  });
});
