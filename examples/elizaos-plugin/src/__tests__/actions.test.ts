/**
 * MPC Wallet Plugin Action Tests
 *
 * Uses Bun test runner for ElizaOS v2 compatibility.
 */

import { describe, it, expect, beforeEach, mock } from 'bun:test';
import { mpcWalletPlugin, type ActionResult } from '../plugin';
import {
  createMockRuntime,
  createMockMessage,
  createMockCallback,
  createMockWallet,
  createMockService,
} from './test-utils';
import type { Action, IAgentRuntime, UUID } from '@elizaos/core';

// Extract actions from plugin for testing
const balanceAction = mpcWalletPlugin.actions?.find((a: Action) => a.name === 'WALLET_BALANCE') as Action;
const sendAction = mpcWalletPlugin.actions?.find((a: Action) => a.name === 'WALLET_SEND') as Action;
const policyAction = mpcWalletPlugin.actions?.find((a: Action) => a.name === 'WALLET_POLICY') as Action;
const addressAction = mpcWalletPlugin.actions?.find((a: Action) => a.name === 'WALLET_ADDRESS') as Action;

describe('MPC Wallet Plugin', () => {
  it('should export a valid plugin', () => {
    expect(mpcWalletPlugin).toBeDefined();
    expect(mpcWalletPlugin.name).toBe('mpc-wallet');
    expect(mpcWalletPlugin.actions).toBeDefined();
    expect(mpcWalletPlugin.actions?.length).toBeGreaterThan(0);
  });

  it('should have event handlers', () => {
    expect(mpcWalletPlugin.events).toBeDefined();
    expect(mpcWalletPlugin.events?.MESSAGE_RECEIVED).toBeDefined();
    expect(mpcWalletPlugin.events?.ACTION_COMPLETED).toBeDefined();
  });

  it('should have services registered', () => {
    expect(mpcWalletPlugin.services).toBeDefined();
    expect(mpcWalletPlugin.services?.length).toBeGreaterThan(0);
  });
});

describe('Balance Action', () => {
  let mockRuntime: IAgentRuntime;

  beforeEach(() => {
    mockRuntime = createMockRuntime();
  });

  it('should validate balance queries', async () => {
    const message = createMockMessage("What's my balance?");
    const isValid = await balanceAction.validate(mockRuntime, message);
    expect(isValid).toBe(true);
  });

  it('should validate "how much" queries', async () => {
    const message = createMockMessage('How much ETH do I have?');
    const isValid = await balanceAction.validate(mockRuntime, message);
    expect(isValid).toBe(true);
  });

  it('should validate wallet queries', async () => {
    const message = createMockMessage('Check my wallet');
    const isValid = await balanceAction.validate(mockRuntime, message);
    expect(isValid).toBe(true);
  });

  it('should not validate unrelated queries', async () => {
    const message = createMockMessage('What is the weather today?');
    const isValid = await balanceAction.validate(mockRuntime, message);
    expect(isValid).toBe(false);
  });

  it('should return ActionResult with success field', async () => {
    const message = createMockMessage('Check balance');
    const { callback } = createMockCallback();

    const result = await balanceAction.handler(
      mockRuntime,
      message,
      undefined,
      {},
      callback
    ) as ActionResult;

    expect(result).toHaveProperty('success');
    expect(result.success).toBe(true);
    expect(callback).toHaveBeenCalled();
  });

  it('should include balance data in result', async () => {
    const message = createMockMessage('Check balance');
    const { callback } = createMockCallback();

    const result = await balanceAction.handler(
      mockRuntime,
      message,
      undefined,
      {},
      callback
    ) as ActionResult;

    expect(result.success).toBe(true);
    expect(result.data).toBeDefined();
    expect(result.data?.actionName).toBe('WALLET_BALANCE');
    expect(result.values?.address).toBeDefined();
  });

  it('should fail when no key share is loaded', async () => {
    const mockRuntime = createMockRuntime({ hasKeyShare: false });
    const message = createMockMessage('Check balance');
    const { callback, getLastCall } = createMockCallback();

    const result = await balanceAction.handler(
      mockRuntime,
      message,
      undefined,
      {},
      callback
    ) as ActionResult;

    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
    expect(getLastCall()?.text).toContain('not initialized');
  });
});

describe('Send Action', () => {
  let mockRuntime: IAgentRuntime;

  beforeEach(() => {
    mockRuntime = createMockRuntime();
  });

  it('should validate send queries', async () => {
    const message = createMockMessage('Send 1 ETH to 0x123');
    const isValid = await sendAction.validate(mockRuntime, message);
    expect(isValid).toBe(true);
  });

  it('should validate transfer queries', async () => {
    const message = createMockMessage('Transfer some tokens');
    const isValid = await sendAction.validate(mockRuntime, message);
    expect(isValid).toBe(true);
  });

  it('should validate pay queries', async () => {
    const message = createMockMessage('Pay 100 USDC to Bob');
    const isValid = await sendAction.validate(mockRuntime, message);
    expect(isValid).toBe(true);
  });

  it('should return ActionResult with success field', async () => {
    const message = createMockMessage('Send 1 ETH');
    const { callback } = createMockCallback();

    const result = await sendAction.handler(
      mockRuntime,
      message,
      undefined,
      {},
      callback
    ) as ActionResult;

    expect(result).toHaveProperty('success');
    expect(result.success).toBe(true);
    expect(result.data?.actionName).toBe('WALLET_SEND');
  });

  it('should return request ID for pending transaction', async () => {
    const message = createMockMessage('Send 1 ETH');
    const { callback } = createMockCallback();

    const result = await sendAction.handler(
      mockRuntime,
      message,
      undefined,
      {},
      callback
    ) as ActionResult;

    expect(result.success).toBe(true);
    expect(result.values?.requestId).toBeDefined();
    expect(result.data?.status).toBe('pending');
  });

  it('should fail when no key share is loaded', async () => {
    const mockRuntime = createMockRuntime({ hasKeyShare: false });
    const message = createMockMessage('Send 1 ETH');
    const { callback } = createMockCallback();

    const result = await sendAction.handler(
      mockRuntime,
      message,
      undefined,
      {},
      callback
    ) as ActionResult;

    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('should reject transactions that violate policy', async () => {
    const mockWallet = createMockWallet({
      evaluatePolicy: () => ({ approved: false, reason: 'Exceeds daily limit' }),
    });
    const mockService = createMockService(mockWallet);
    const mockRuntime = createMockRuntime();
    (mockRuntime.getService as any) = mock(() => mockService);

    const message = createMockMessage('Send 1000 ETH');
    const { callback } = createMockCallback();

    const result = await sendAction.handler(
      mockRuntime,
      message,
      undefined,
      {},
      callback
    ) as ActionResult;

    expect(result.success).toBe(false);
    expect(result.data?.reason).toBe('Exceeds daily limit');
  });
});

describe('Policy Action', () => {
  let mockRuntime: IAgentRuntime;

  beforeEach(() => {
    mockRuntime = createMockRuntime();
  });

  it('should validate limit queries', async () => {
    const message = createMockMessage('What are my limits?');
    const isValid = await policyAction.validate(mockRuntime, message);
    expect(isValid).toBe(true);
  });

  it('should validate "can I" queries', async () => {
    const message = createMockMessage('Can I send 5 ETH?');
    const isValid = await policyAction.validate(mockRuntime, message);
    expect(isValid).toBe(true);
  });

  it('should validate policy queries', async () => {
    const message = createMockMessage('Check my spending policy');
    const isValid = await policyAction.validate(mockRuntime, message);
    expect(isValid).toBe(true);
  });

  it('should return ActionResult with success field', async () => {
    const message = createMockMessage('What are my limits?');
    const { callback } = createMockCallback();

    const result = await policyAction.handler(
      mockRuntime,
      message,
      undefined,
      {},
      callback
    ) as ActionResult;

    expect(result).toHaveProperty('success');
    expect(result.success).toBe(true);
    expect(result.data?.actionName).toBe('WALLET_POLICY');
  });

  it('should handle policy configured', async () => {
    const mockWallet = createMockWallet({
      getPolicy: () => ({
        perTransaction: '1000000000000000000',
        daily: '10000000000000000000',
      }),
    });
    const mockService = createMockService(mockWallet);
    const mockRuntime = createMockRuntime();
    (mockRuntime.getService as any) = mock(() => mockService);

    const message = createMockMessage('What are my limits?');
    const { callback, getLastCall } = createMockCallback();

    const result = await policyAction.handler(
      mockRuntime,
      message,
      undefined,
      {},
      callback
    ) as ActionResult;

    expect(result.success).toBe(true);
    expect(result.data?.hasPolicy).toBe(true);
    expect(getLastCall()?.text).toContain('Spending Policy');
  });
});

describe('Address Action', () => {
  let mockRuntime: IAgentRuntime;

  beforeEach(() => {
    mockRuntime = createMockRuntime();
  });

  it('should validate address queries', async () => {
    const message = createMockMessage("What's my address?");
    const isValid = await addressAction.validate(mockRuntime, message);
    expect(isValid).toBe(true);
  });

  it('should validate "my wallet" queries', async () => {
    const message = createMockMessage('Show me my wallet');
    const isValid = await addressAction.validate(mockRuntime, message);
    expect(isValid).toBe(true);
  });

  it('should return ActionResult with success field', async () => {
    const message = createMockMessage("What's my address?");
    const { callback } = createMockCallback();

    const result = await addressAction.handler(
      mockRuntime,
      message,
      undefined,
      {},
      callback
    ) as ActionResult;

    expect(result).toHaveProperty('success');
    expect(result.success).toBe(true);
    expect(result.data?.actionName).toBe('WALLET_ADDRESS');
  });

  it('should return wallet address', async () => {
    const message = createMockMessage("What's my address?");
    const { callback } = createMockCallback();

    const result = await addressAction.handler(
      mockRuntime,
      message,
      undefined,
      {},
      callback
    ) as ActionResult;

    expect(result.success).toBe(true);
    expect(result.values?.address).toBeDefined();
    expect(result.values?.address).toMatch(/^0x[a-fA-F0-9]+$/);
  });

  it('should fail when no key share is loaded', async () => {
    const mockRuntime = createMockRuntime({ hasKeyShare: false });
    const message = createMockMessage("What's my address?");
    const { callback } = createMockCallback();

    const result = await addressAction.handler(
      mockRuntime,
      message,
      undefined,
      {},
      callback
    ) as ActionResult;

    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });
});

describe('Event Handlers', () => {
  it('should have MESSAGE_RECEIVED handler', () => {
    const handlers = mpcWalletPlugin.events?.MESSAGE_RECEIVED;
    expect(handlers).toBeDefined();
    expect(handlers?.length).toBeGreaterThan(0);
  });

  it('should have ACTION_COMPLETED handler', () => {
    const handlers = mpcWalletPlugin.events?.ACTION_COMPLETED;
    expect(handlers).toBeDefined();
    expect(handlers?.length).toBeGreaterThan(0);
  });

  it('MESSAGE_RECEIVED handler should execute without error', async () => {
    const handler = mpcWalletPlugin.events?.MESSAGE_RECEIVED?.[0];
    expect(handler).toBeDefined();
    
    const mockRuntime = createMockRuntime();
    const message = createMockMessage('Check my wallet balance');

    // Should complete without throwing - use proper MessagePayload shape
    const result = await handler?.({
      runtime: mockRuntime,
      message,
      source: 'test',
    } as any);
    expect(result).toBeUndefined(); // Handler returns void
  });

  it('ACTION_COMPLETED handler should execute without error', async () => {
    const handler = mpcWalletPlugin.events?.ACTION_COMPLETED?.[0];
    expect(handler).toBeDefined();
    
    const mockRuntime = createMockRuntime();

    // Should complete without throwing - use proper ActionEventPayload shape
    const result = await handler?.({
      runtime: mockRuntime,
      source: 'test',
      actionId: 'action-123' as UUID,
      actionName: 'WALLET_BALANCE',
      completed: true,
    } as any);
    expect(result).toBeUndefined(); // Handler returns void
  });
});
