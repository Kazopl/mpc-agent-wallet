/**
 * Test utilities for MPC Wallet Plugin
 *
 * Provides mock implementations for ElizaOS runtime and message objects
 * for use with Bun test runner.
 */

import { mock } from 'bun:test';
import type { IAgentRuntime, Memory, State, UUID } from '@elizaos/core';

export interface MockWallet {
  hasKeyShare: () => boolean;
  getAddress: () => string;
  evaluatePolicy: (tx: any) => { approved: boolean; reason?: string };
  getPolicy: () => any | null;
  loadKeyShare: (path: string, password: string) => Promise<void>;
}

export interface MockRuntimeOptions {
  settings?: Record<string, string>;
  wallet?: Partial<MockWallet>;
  hasKeyShare?: boolean;
}

/**
 * Creates a mock wallet for testing
 */
export function createMockWallet(overrides?: Partial<MockWallet>): MockWallet {
  return {
    hasKeyShare: mock(() => overrides?.hasKeyShare?.() ?? true),
    getAddress: mock(() => overrides?.getAddress?.() ?? '0x1234567890abcdef1234567890abcdef12345678'),
    evaluatePolicy: mock((tx: any) =>
      overrides?.evaluatePolicy?.(tx) ?? { approved: true }
    ),
    getPolicy: mock(() => overrides?.getPolicy?.() ?? {
      perTransaction: '1000000000000000000', // 1 ETH
      daily: '10000000000000000000', // 10 ETH
      weekly: '50000000000000000000', // 50 ETH
    }),
    loadKeyShare: mock(async () => {}),
  };
}

/**
 * Creates a mock MpcWalletService for testing
 */
export function createMockService(wallet?: MockWallet) {
  const mockWallet = wallet ?? createMockWallet();
  return {
    getWallet: mock(() => mockWallet),
    wallet: mockWallet,
    chains: {
      ethereum: 'https://eth.llamarpc.com',
      polygon: 'https://polygon-rpc.com',
      arbitrum: 'https://arb1.arbitrum.io/rpc',
    },
  };
}

/**
 * Creates a mock ElizaOS runtime for testing
 */
export function createMockRuntime(options?: MockRuntimeOptions): IAgentRuntime {
  const settings: Record<string, string> = {
    MPC_WALLET_PASSWORD: 'test-password',
    MPC_WALLET_KEY_PATH: '/tmp/test-key.json',
    MPC_WALLET_RELAY_URL: 'https://relay.example.com',
    ...options?.settings,
  };

  const mockWallet = createMockWallet({
    hasKeyShare: () => options?.hasKeyShare ?? true,
    ...options?.wallet,
  });

  const mockService = createMockService(mockWallet);

  return {
    agentId: 'test-agent-123' as UUID,
    getSetting: mock((key: string) => settings[key] ?? null),
    getService: mock((_name: string) => mockService),
    composeState: mock(async (_message: Memory) => ({
      values: {},
      text: '',
    } as unknown as State)),
    // Add other runtime methods as needed for tests
    updateRecentMessageState: mock(async () => ({})),
  } as unknown as IAgentRuntime;
}

/**
 * Creates a mock Memory (message) object for testing
 */
export function createMockMessage(text: string, overrides?: Partial<Memory>): Memory {
  return {
    id: `msg-${Date.now()}` as UUID,
    entityId: 'entity-test-123' as UUID,
    roomId: 'room-test-123' as UUID,
    agentId: 'test-agent-123' as UUID,
    content: { text },
    createdAt: Date.now(),
    ...overrides,
  } as Memory;
}

/**
 * Creates a mock callback function for testing action handlers
 * Returns Memory[] to match HandlerCallback type signature
 */
export function createMockCallback() {
  const calls: any[] = [];
  const callback = mock(async (response: any): Promise<Memory[]> => {
    calls.push(response);
    // Return empty array to satisfy HandlerCallback return type
    return [];
  });
  return {
    callback,
    getCalls: () => calls,
    getLastCall: () => calls[calls.length - 1],
  };
}

/**
 * Creates a mock State object for testing
 */
export function createMockState(overrides?: Partial<State>): State {
  return {
    values: {},
    text: '',
    ...overrides,
  } as State;
}
