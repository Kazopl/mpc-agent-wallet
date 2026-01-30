/**
 * ERC-7715 Types Tests
 *
 * Unit tests for ERC-7715 type definitions, type guards, and factory functions.
 */

import { describe, it, expect } from 'vitest';
import {
  // Type guards
  isAccountSigner,
  isKeySigner,
  isKeysSigner,
  isNativeTokenTransferPermission,
  isErc20TokenTransferPermission,
  isContractCallPermission,
  isRateLimitPermission,
  isValidChainIdHex,
  isValidPermissionId,
  // Factory functions
  createAccountSigner,
  createKeySigner,
  createKeysSigner,
  createNativeTokenTransferPermission,
  createErc20TokenTransferPermission,
  createContractCallPermission,
  createRateLimitPermission,
  createGasLimitPolicy,
  createCallLimitPolicy,
  createRateLimitPolicy,
  createSpendingLimitPolicy,
  // Types
  type SignerInfo,
  type Permission,
  type ChainIdHex,
  type PermissionId,
} from '../../erc7715/types';

describe('ERC-7715 Types', () => {
  describe('Type Guards - Signers', () => {
    it('should identify account signer', () => {
      const accountSigner: SignerInfo = {
        type: 'account',
        data: { id: '0x1234567890123456789012345678901234567890' },
      };

      expect(isAccountSigner(accountSigner)).toBe(true);
      expect(isKeySigner(accountSigner)).toBe(false);
      expect(isKeysSigner(accountSigner)).toBe(false);
    });

    it('should identify key signer', () => {
      const keySigner: SignerInfo = {
        type: 'key',
        data: { publicKey: '0x04abcd1234' },
      };

      expect(isAccountSigner(keySigner)).toBe(false);
      expect(isKeySigner(keySigner)).toBe(true);
      expect(isKeysSigner(keySigner)).toBe(false);
    });

    it('should identify keys signer', () => {
      const keysSigner: SignerInfo = {
        type: 'keys',
        data: { publicKeys: ['0x04abcd1234', '0x04efgh5678'] },
      };

      expect(isAccountSigner(keysSigner)).toBe(false);
      expect(isKeySigner(keysSigner)).toBe(false);
      expect(isKeysSigner(keysSigner)).toBe(true);
    });
  });

  describe('Type Guards - Permissions', () => {
    it('should identify native-token-transfer permission', () => {
      const permission: Permission = {
        type: 'native-token-transfer',
        data: { allowance: '0xDE0B6B3A7640000' },
        required: true,
      };

      expect(isNativeTokenTransferPermission(permission)).toBe(true);
      expect(isErc20TokenTransferPermission(permission)).toBe(false);
      expect(isContractCallPermission(permission)).toBe(false);
      expect(isRateLimitPermission(permission)).toBe(false);
    });

    it('should identify erc20-token-transfer permission', () => {
      const permission: Permission = {
        type: 'erc20-token-transfer',
        data: {
          address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
          allowance: '0x3B9ACA00',
        },
        required: true,
      };

      expect(isNativeTokenTransferPermission(permission)).toBe(false);
      expect(isErc20TokenTransferPermission(permission)).toBe(true);
      expect(isContractCallPermission(permission)).toBe(false);
      expect(isRateLimitPermission(permission)).toBe(false);
    });

    it('should identify contract-call permission', () => {
      const permission: Permission = {
        type: 'contract-call',
        data: {
          address: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
          calls: [{ selector: '0x5ae401dc' }],
        },
        required: true,
      };

      expect(isNativeTokenTransferPermission(permission)).toBe(false);
      expect(isErc20TokenTransferPermission(permission)).toBe(false);
      expect(isContractCallPermission(permission)).toBe(true);
      expect(isRateLimitPermission(permission)).toBe(false);
    });

    it('should identify rate-limit permission', () => {
      const permission: Permission = {
        type: 'rate-limit',
        data: { count: 10, interval: 3600 },
        required: false,
      };

      expect(isNativeTokenTransferPermission(permission)).toBe(false);
      expect(isErc20TokenTransferPermission(permission)).toBe(false);
      expect(isContractCallPermission(permission)).toBe(false);
      expect(isRateLimitPermission(permission)).toBe(true);
    });
  });

  describe('Validation Functions', () => {
    describe('isValidChainIdHex', () => {
      it('should accept valid chain IDs', () => {
        expect(isValidChainIdHex('0x1')).toBe(true);
        expect(isValidChainIdHex('0x89')).toBe(true);
        expect(isValidChainIdHex('0xa4b1')).toBe(true);
        expect(isValidChainIdHex('0x2105')).toBe(true);
        expect(isValidChainIdHex('0xABCDEF')).toBe(true);
      });

      it('should reject invalid chain IDs', () => {
        expect(isValidChainIdHex('1')).toBe(false);
        expect(isValidChainIdHex('0x')).toBe(false);
        expect(isValidChainIdHex('0xGGG')).toBe(false);
        expect(isValidChainIdHex('ethereum')).toBe(false);
        expect(isValidChainIdHex('')).toBe(false);
      });
    });

    describe('isValidPermissionId', () => {
      it('should accept valid permission IDs', () => {
        const validId = '0x' + 'a'.repeat(64);
        expect(isValidPermissionId(validId)).toBe(true);
      });

      it('should reject invalid permission IDs', () => {
        expect(isValidPermissionId('0x1234')).toBe(false);
        expect(isValidPermissionId('0x' + 'a'.repeat(63))).toBe(false);
        expect(isValidPermissionId('0x' + 'a'.repeat(65))).toBe(false);
        expect(isValidPermissionId('0x' + 'g'.repeat(64))).toBe(false);
        expect(isValidPermissionId('')).toBe(false);
      });
    });
  });

  describe('Factory Functions - Signers', () => {
    it('should create account signer', () => {
      const address = '0x1234567890123456789012345678901234567890';
      const signer = createAccountSigner(address);

      expect(signer.type).toBe('account');
      expect(signer.data.id).toBe(address);
      expect(isAccountSigner(signer)).toBe(true);
    });

    it('should create key signer', () => {
      const publicKey = '0x04abcd1234567890';
      const signer = createKeySigner(publicKey);

      expect(signer.type).toBe('key');
      expect(signer.data.publicKey).toBe(publicKey);
      expect(isKeySigner(signer)).toBe(true);
    });

    it('should create keys signer', () => {
      const publicKeys = ['0x04key1', '0x04key2'];
      const signer = createKeysSigner(publicKeys);

      expect(signer.type).toBe('keys');
      expect(signer.data.publicKeys).toEqual(publicKeys);
      expect(isKeysSigner(signer)).toBe(true);
    });
  });

  describe('Factory Functions - Permissions', () => {
    it('should create native token transfer permission', () => {
      const allowance = '0xDE0B6B3A7640000';
      const permission = createNativeTokenTransferPermission(allowance);

      expect(permission.type).toBe('native-token-transfer');
      expect(permission.data.allowance).toBe(allowance);
      expect(permission.required).toBe(true);
    });

    it('should create native token transfer permission with required=false', () => {
      const permission = createNativeTokenTransferPermission('0x1', false);

      expect(permission.required).toBe(false);
    });

    it('should create erc20 token transfer permission', () => {
      const tokenAddress = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
      const allowance = '0x3B9ACA00';
      const permission = createErc20TokenTransferPermission(tokenAddress, allowance);

      expect(permission.type).toBe('erc20-token-transfer');
      expect(permission.data.address).toBe(tokenAddress);
      expect(permission.data.allowance).toBe(allowance);
      expect(permission.required).toBe(true);
    });

    it('should create contract call permission', () => {
      const contractAddress = '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45';
      const calls = [
        { selector: '0x5ae401dc' },
        { selector: '0x04e45aaf', maxValue: '0x1000' },
      ];
      const permission = createContractCallPermission(contractAddress, calls);

      expect(permission.type).toBe('contract-call');
      expect(permission.data.address).toBe(contractAddress);
      expect(permission.data.calls).toEqual(calls);
      expect(permission.required).toBe(true);
    });

    it('should create rate limit permission', () => {
      const count = 10;
      const interval = 3600;
      const permission = createRateLimitPermission(count, interval);

      expect(permission.type).toBe('rate-limit');
      expect(permission.data.count).toBe(count);
      expect(permission.data.interval).toBe(interval);
      expect(permission.required).toBe(true);
    });
  });

  describe('Factory Functions - Policies', () => {
    it('should create gas limit policy', () => {
      const limit = '0x7A120';
      const policy = createGasLimitPolicy(limit);

      expect(policy.type).toBe('gas-limit');
      expect(policy.data.limit).toBe(limit);
    });

    it('should create call limit policy', () => {
      const count = 100;
      const policy = createCallLimitPolicy(count);

      expect(policy.type).toBe('call-limit');
      expect(policy.data.count).toBe(count);
    });

    it('should create rate limit policy', () => {
      const count = 10;
      const interval = 3600;
      const policy = createRateLimitPolicy(count, interval);

      expect(policy.type).toBe('rate-limit');
      expect(policy.data.count).toBe(count);
      expect(policy.data.interval).toBe(interval);
    });

    it('should create spending limit policy', () => {
      const allowance = '0xDE0B6B3A7640000';
      const period = 86400;
      const policy = createSpendingLimitPolicy(allowance, period);

      expect(policy.type).toBe('spending-limit');
      expect(policy.data.allowance).toBe(allowance);
      expect(policy.data.period).toBe(period);
    });

    it('should create spending limit policy without period', () => {
      const allowance = '0xDE0B6B3A7640000';
      const policy = createSpendingLimitPolicy(allowance);

      expect(policy.type).toBe('spending-limit');
      expect(policy.data.allowance).toBe(allowance);
      expect(policy.data.period).toBeUndefined();
    });
  });
});
