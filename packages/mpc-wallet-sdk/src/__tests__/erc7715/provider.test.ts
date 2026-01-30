/**
 * ERC-7715 Provider Tests
 *
 * Unit tests for ERC7715Provider including EIP-1193 interface,
 * permission management, and action execution.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  ERC7715Provider,
  PermissionRequestBuilder,
  createERC7715Provider,
  type ERC7715ProviderConfig,
} from '../../erc7715/provider';
import type { ChainIdHex, PermissionId, Action } from '../../erc7715/types';

// Test constants
const TEST_CHAIN: ChainIdHex = '0x1' as ChainIdHex;
const TEST_ACCOUNT = '0x1234567890123456789012345678901234567890' as const;
const TEST_AGENT = '0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd' as const;

describe('ERC7715Provider', () => {
  let provider: ERC7715Provider;
  let mockExecuteActions: ReturnType<typeof vi.fn>;
  let mockApprovalRequest: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-01-15T12:00:00Z'));

    mockExecuteActions = vi.fn().mockResolvedValue('0x' + 'a'.repeat(64));
    mockApprovalRequest = vi.fn().mockResolvedValue(true);

    const config: ERC7715ProviderConfig = {
      accountAddress: TEST_ACCOUNT,
      chainId: TEST_CHAIN,
      onApprovalRequest: mockApprovalRequest,
      onExecuteActions: mockExecuteActions,
    };

    provider = createERC7715Provider(config);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('EIP-1193 Interface', () => {
    it('should respond to eth_chainId', async () => {
      const chainId = await provider.request({ method: 'eth_chainId' });
      expect(chainId).toBe(TEST_CHAIN);
    });

    it('should respond to eth_accounts', async () => {
      const accounts = await provider.request({ method: 'eth_accounts' });
      expect(accounts).toEqual([TEST_ACCOUNT]);
    });

    it('should respond to eth_requestAccounts', async () => {
      const accounts = await provider.request({ method: 'eth_requestAccounts' });
      expect(accounts).toEqual([TEST_ACCOUNT]);
    });

    it('should respond to net_version', async () => {
      const version = await provider.request({ method: 'net_version' });
      expect(version).toBe('1'); // Chain ID 0x1 = 1
    });

    it('should reject unsupported methods', async () => {
      await expect(
        provider.request({ method: 'unsupported_method' })
      ).rejects.toThrow(/Unsupported method/);
    });
  });

  describe('Connection Management', () => {
    it('should be connected by default', () => {
      expect(provider.isConnected()).toBe(true);
    });

    it('should disconnect and reconnect', () => {
      provider.disconnect();
      expect(provider.isConnected()).toBe(false);

      provider.connect();
      expect(provider.isConnected()).toBe(true);
    });

    it('should emit connect event', () => {
      const listener = vi.fn();
      provider.on('connect', listener);

      provider.disconnect();
      provider.connect();

      expect(listener).toHaveBeenCalledWith({ chainId: TEST_CHAIN });
    });

    it('should emit disconnect event', () => {
      const listener = vi.fn();
      provider.on('disconnect', listener);

      provider.disconnect();

      expect(listener).toHaveBeenCalled();
    });

    it('should emit chainChanged event on switch', async () => {
      const listener = vi.fn();
      provider.on('chainChanged', listener);

      // Add support for new chain first
      provider.getPermissionManager().addChainSupport('0x89' as ChainIdHex);

      await provider.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: '0x89' }],
      });

      expect(listener).toHaveBeenCalledWith('0x89');
      expect(provider.getChainId()).toBe('0x89');
    });
  });

  describe('Permission Requests', () => {
    it('should request permissions', async () => {
      const response = await provider.requestPermissions({
        chainId: TEST_CHAIN,
        expiry: Math.floor(Date.now() / 1000) + 3600,
        signer: { type: 'account', data: { id: TEST_AGENT } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0xDE0B6B3A7640000' },
            required: true,
          },
        ],
      });

      expect(response.permissionId).toBeDefined();
      expect(response.permissionsContext).toBeDefined();
      expect(response.accountAddress).toBe(TEST_ACCOUNT);
      expect(mockApprovalRequest).toHaveBeenCalledTimes(1);
    });

    it('should call approval callback', async () => {
      await provider.requestPermissions({
        chainId: TEST_CHAIN,
        expiry: Math.floor(Date.now() / 1000) + 3600,
        signer: { type: 'account', data: { id: TEST_AGENT } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0xDE0B6B3A7640000' },
            required: true,
          },
        ],
      });

      expect(mockApprovalRequest).toHaveBeenCalled();
      const requestArg = mockApprovalRequest.mock.calls[0][0];
      expect(requestArg.permissions.length).toBe(1);
    });

    it('should reject if user denies', async () => {
      mockApprovalRequest.mockResolvedValueOnce(false);

      await expect(
        provider.requestPermissions({
          chainId: TEST_CHAIN,
          expiry: Math.floor(Date.now() / 1000) + 3600,
          signer: { type: 'account', data: { id: TEST_AGENT } },
          permissions: [
            {
              type: 'native-token-transfer',
              data: { allowance: '0xDE0B6B3A7640000' },
              required: true,
            },
          ],
        })
      ).rejects.toThrow(/denied/);
    });

    it('should emit permissionGranted event', async () => {
      const listener = vi.fn();
      provider.on('permissionGranted', listener);

      await provider.requestPermissions({
        chainId: TEST_CHAIN,
        expiry: Math.floor(Date.now() / 1000) + 3600,
        signer: { type: 'account', data: { id: TEST_AGENT } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0xDE0B6B3A7640000' },
            required: true,
          },
        ],
      });

      expect(listener).toHaveBeenCalled();
    });
  });

  describe('Permission Revocation', () => {
    it('should revoke permission', async () => {
      const permission = await provider.requestPermissions({
        chainId: TEST_CHAIN,
        expiry: Math.floor(Date.now() / 1000) + 3600,
        signer: { type: 'account', data: { id: TEST_AGENT } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0xDE0B6B3A7640000' },
            required: true,
          },
        ],
      });

      const revoked = await provider.revokePermission(permission.permissionId);

      expect(revoked.success).toBe(true);
      expect(revoked.permissionId).toBe(permission.permissionId);
      expect(provider.isPermissionValid(permission.permissionId)).toBe(false);
    });

    it('should emit permissionRevoked event', async () => {
      const listener = vi.fn();
      provider.on('permissionRevoked', listener);

      const permission = await provider.requestPermissions({
        chainId: TEST_CHAIN,
        expiry: Math.floor(Date.now() / 1000) + 3600,
        signer: { type: 'account', data: { id: TEST_AGENT } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0xDE0B6B3A7640000' },
            required: true,
          },
        ],
      });

      await provider.revokePermission(permission.permissionId);

      expect(listener).toHaveBeenCalled();
    });
  });

  describe('Permission Queries', () => {
    it('should get supported permissions', async () => {
      const supported = await provider.getSupportedPermissions();

      expect(supported.chainId).toBe(TEST_CHAIN);
      expect(supported.permissions.length).toBeGreaterThan(0);
    });

    it('should get granted permissions', async () => {
      await provider.requestPermissions({
        chainId: TEST_CHAIN,
        expiry: Math.floor(Date.now() / 1000) + 3600,
        signer: { type: 'account', data: { id: TEST_AGENT } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0xDE0B6B3A7640000' },
            required: true,
          },
        ],
      });

      const granted = await provider.getGrantedPermissions();

      expect(granted.permissions.length).toBe(1);
      expect(granted.accountAddress).toBe(TEST_ACCOUNT);
    });
  });

  describe('Action Execution', () => {
    let permission: Awaited<ReturnType<typeof provider.requestPermissions>>;

    beforeEach(async () => {
      permission = await provider.requestPermissions({
        chainId: TEST_CHAIN,
        expiry: Math.floor(Date.now() / 1000) + 3600,
        signer: { type: 'account', data: { id: TEST_AGENT } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0xDE0B6B3A7640000' }, // 1 ETH
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
        ],
      });
    });

    it('should execute simple transfer', async () => {
      const action: Action = {
        to: '0x9999999999999999999999999999999999999999',
        value: '0x38D7EA4C68000', // 0.001 ETH
        data: '0x',
      };

      const result = await provider.executeWithPermission(
        permission.permissionsContext,
        [action]
      );

      expect(result.success).toBe(true);
      expect(result.transactionHash).toBeDefined();
      expect(mockExecuteActions).toHaveBeenCalled();
    });

    it('should execute contract call', async () => {
      const action: Action = {
        to: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        value: '0x0',
        data: '0x5ae401dc00000000', // multicall selector + data
      };

      const result = await provider.executeWithPermission(
        permission.permissionsContext,
        [action]
      );

      expect(result.success).toBe(true);
    });

    it('should reject empty actions', async () => {
      await expect(
        provider.executeWithPermission(permission.permissionsContext, [])
      ).rejects.toThrow(/at least one action/i);
    });

    it('should reject transfer exceeding allowance', async () => {
      const action: Action = {
        to: '0x9999999999999999999999999999999999999999',
        value: '0x1BC16D674EC80000', // 2 ETH (exceeds 1 ETH allowance)
        data: '0x',
      };

      await expect(
        provider.executeWithPermission(permission.permissionsContext, [action])
      ).rejects.toThrow(/exceeds/i);
    });

    it('should reject non-whitelisted contract', async () => {
      const action: Action = {
        to: '0x0000000000000000000000000000000000000BAD',
        value: '0x0',
        data: '0xdeadbeef', // Some call data
      };

      await expect(
        provider.executeWithPermission(permission.permissionsContext, [action])
      ).rejects.toThrow(/not permitted/i);
    });

    it('should reject with invalid context', async () => {
      const invalidContext = '0x01' + '00'.repeat(68);

      await expect(
        provider.executeWithPermission(invalidContext as any, [
          { to: TEST_ACCOUNT, value: '0x0', data: '0x' },
        ])
      ).rejects.toThrow();
    });
  });

  describe('Permission Status', () => {
    it('should check permission validity', async () => {
      const permission = await provider.requestPermissions({
        chainId: TEST_CHAIN,
        expiry: Math.floor(Date.now() / 1000) + 3600,
        signer: { type: 'account', data: { id: TEST_AGENT } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0xDE0B6B3A7640000' },
            required: true,
          },
        ],
      });

      expect(provider.isPermissionValid(permission.permissionId)).toBe(true);

      // Revoke and check again
      await provider.revokePermission(permission.permissionId);
      expect(provider.isPermissionValid(permission.permissionId)).toBe(false);
    });

    it('should get time remaining', async () => {
      const permission = await provider.requestPermissions({
        chainId: TEST_CHAIN,
        expiry: Math.floor(Date.now() / 1000) + 3600, // 1 hour
        signer: { type: 'account', data: { id: TEST_AGENT } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0xDE0B6B3A7640000' },
            required: true,
          },
        ],
      });

      const remaining = provider.getPermissionTimeRemaining(permission.permissionId);

      // Should be approximately 3600 seconds
      expect(remaining).toBeGreaterThan(3500);
      expect(remaining).toBeLessThanOrEqual(3600);
    });

    it('should return 0 for expired permission', async () => {
      const permission = await provider.requestPermissions({
        chainId: TEST_CHAIN,
        expiry: Math.floor(Date.now() / 1000) + 60, // 1 minute
        signer: { type: 'account', data: { id: TEST_AGENT } },
        permissions: [
          {
            type: 'native-token-transfer',
            data: { allowance: '0xDE0B6B3A7640000' },
            required: true,
          },
        ],
      });

      // Fast forward past expiry
      vi.advanceTimersByTime(120 * 1000);

      const remaining = provider.getPermissionTimeRemaining(permission.permissionId);
      expect(remaining).toBe(0);
    });
  });

  describe('Utility Methods', () => {
    it('should get account address', () => {
      expect(provider.getAccountAddress()).toBe(TEST_ACCOUNT);
    });

    it('should get chain ID', () => {
      expect(provider.getChainId()).toBe(TEST_CHAIN);
    });

    it('should get permission manager', () => {
      const manager = provider.getPermissionManager();
      expect(manager).toBeDefined();
    });
  });
});

describe('PermissionRequestBuilder', () => {
  let builder: PermissionRequestBuilder;
  const TEST_CHAIN: ChainIdHex = '0x1' as ChainIdHex;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-01-15T12:00:00Z'));
    builder = new PermissionRequestBuilder(TEST_CHAIN);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should set chain ID', () => {
    const request = builder
      .forChain('0x89' as ChainIdHex)
      .expireIn(3600)
      .withSigner({ type: 'account', data: { id: TEST_AGENT } })
      .allowNativeTransfer('0x1')
      .build();

    expect(request.chainId).toBe('0x89');
  });

  it('should set expiry timestamp', () => {
    const timestamp = Math.floor(Date.now() / 1000) + 7200;
    const request = builder
      .expireAt(timestamp)
      .withSigner({ type: 'account', data: { id: TEST_AGENT } })
      .allowNativeTransfer('0x1')
      .build();

    expect(request.expiry).toBe(timestamp);
  });

  it('should set expiry duration', () => {
    const request = builder
      .expireIn(3600)
      .withSigner({ type: 'account', data: { id: TEST_AGENT } })
      .allowNativeTransfer('0x1')
      .build();

    const expectedExpiry = Math.floor(Date.now() / 1000) + 3600;
    expect(request.expiry).toBe(expectedExpiry);
  });

  it('should add native transfer permission', () => {
    const request = builder
      .expireIn(3600)
      .withSigner({ type: 'account', data: { id: TEST_AGENT } })
      .allowNativeTransfer('0xDE0B6B3A7640000')
      .build();

    expect(request.permissions.length).toBe(1);
    expect(request.permissions[0].type).toBe('native-token-transfer');
  });

  it('should add ERC20 transfer permission', () => {
    const request = builder
      .expireIn(3600)
      .withSigner({ type: 'account', data: { id: TEST_AGENT } })
      .allowErc20Transfer(
        '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
        '0x3B9ACA00'
      )
      .build();

    expect(request.permissions.length).toBe(1);
    expect(request.permissions[0].type).toBe('erc20-token-transfer');
  });

  it('should add contract call permission', () => {
    const request = builder
      .expireIn(3600)
      .withSigner({ type: 'account', data: { id: TEST_AGENT } })
      .allowContractCall(
        '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        ['0x5ae401dc', '0x04e45aaf']
      )
      .build();

    expect(request.permissions.length).toBe(1);
    expect(request.permissions[0].type).toBe('contract-call');
  });

  it('should add rate limit permission', () => {
    const request = builder
      .expireIn(3600)
      .withSigner({ type: 'account', data: { id: TEST_AGENT } })
      .allowNativeTransfer('0x1')
      .allowRateLimit(10, 3600)
      .build();

    const rateLimit = request.permissions.find((p) => p.type === 'rate-limit');
    expect(rateLimit).toBeDefined();
    expect(rateLimit?.data).toEqual({ count: 10, interval: 3600 });
  });

  it('should add policies', () => {
    const request = builder
      .expireIn(3600)
      .withSigner({ type: 'account', data: { id: TEST_AGENT } })
      .allowNativeTransfer('0x1')
      .withGasLimit('0x7A120')
      .withCallLimit(100)
      .withRateLimit(10, 3600)
      .withSpendingLimit('0xDE0B6B3A7640000', 86400)
      .build();

    expect(request.policies?.length).toBe(4);
  });

  it('should throw without signer', () => {
    expect(() =>
      builder.expireIn(3600).allowNativeTransfer('0x1').build()
    ).toThrow(/Signer is required/);
  });

  it('should throw without expiry', () => {
    expect(() =>
      builder
        .withSigner({ type: 'account', data: { id: TEST_AGENT } })
        .allowNativeTransfer('0x1')
        .build()
    ).toThrow(/Expiry is required/);
  });

  it('should throw without permissions', () => {
    expect(() =>
      builder
        .expireIn(3600)
        .withSigner({ type: 'account', data: { id: TEST_AGENT } })
        .build()
    ).toThrow(/at least one permission/i);
  });

  it('should chain fluently', () => {
    const request = builder
      .forChain(TEST_CHAIN)
      .expireIn(3600)
      .withSigner({ type: 'account', data: { id: TEST_AGENT } })
      .allowNativeTransfer('0xDE0B6B3A7640000')
      .allowErc20Transfer('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', '0x1000')
      .allowContractCall('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45', ['0x5ae401dc'])
      .allowRateLimit(10, 3600)
      .withSpendingLimit('0xDE0B6B3A7640000')
      .build();

    expect(request.chainId).toBe(TEST_CHAIN);
    expect(request.permissions.length).toBe(4);
    expect(request.policies?.length).toBe(1);
  });
});
