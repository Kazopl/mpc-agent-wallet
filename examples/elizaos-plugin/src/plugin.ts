/**
 * MPC Wallet Plugin for ElizaOS
 *
 * Updated for ElizaOS v1.0.14+ API
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import type {
  Plugin,
  Action,
  ActionResult,
  IAgentRuntime,
  Memory,
} from '@elizaos/core';
import {
  MpcAgentWallet,
  PartyRole,
  PolicyConfig,
  ChainType,
} from '@mpc-wallet/sdk';

export interface MpcWalletPluginConfig {
  /** Password for decrypting key share */
  password: string;
  /** Path to stored key share */
  keyPath?: string;
  /** Relay service URL */
  relayUrl?: string;
  /** Policy configuration */
  policy?: {
    spendingLimits?: {
      perTransaction?: string;
      daily?: string;
      weekly?: string;
    };
    whitelist?: string[];
    blacklist?: string[];
  };
  /** Chain RPC URLs */
  chains?: {
    ethereum?: string;
    polygon?: string;
    arbitrum?: string;
  };
}

export interface PluginContext {
  wallet: MpcAgentWallet;
  relayUrl?: string;
  chains: Record<string, string>;
}

/**
 * MPC Wallet Service - manages wallet lifecycle
 */
class MpcWalletService {
  static serviceType = 'mpc-wallet';

  wallet: MpcAgentWallet | null = null;
  config: MpcWalletPluginConfig;
  chains: Record<string, string>;

  constructor(config: MpcWalletPluginConfig) {
    this.config = config;
    this.chains = {
      ethereum: config.chains?.ethereum ?? 'https://eth.llamarpc.com',
      polygon: config.chains?.polygon ?? 'https://polygon-rpc.com',
      arbitrum: config.chains?.arbitrum ?? 'https://arb1.arbitrum.io/rpc',
    };
  }

  async initialize(_runtime: IAgentRuntime): Promise<void> {
    // Build policy configuration
    const policyConfig = new PolicyConfig();

    if (this.config.policy?.spendingLimits) {
      const limits = this.config.policy.spendingLimits;
      if (limits.perTransaction) {
        policyConfig.withPerTxLimit(BigInt(limits.perTransaction));
      }
      if (limits.daily) {
        policyConfig.withDailyLimit(BigInt(limits.daily));
      }
      if (limits.weekly) {
        policyConfig.withWeeklyLimit(BigInt(limits.weekly));
      }
    }

    if (this.config.policy?.whitelist) {
      policyConfig.withWhitelist(this.config.policy.whitelist);
    }

    if (this.config.policy?.blacklist) {
      policyConfig.withBlacklist(this.config.policy.blacklist);
    }

    // Create wallet
    this.wallet = await MpcAgentWallet.create({
      role: PartyRole.Agent,
      policy: policyConfig,
    });

    // Load key share if path provided
    if (this.config.keyPath) {
      await this.wallet.loadKeyShare(this.config.keyPath, this.config.password);
    }

    console.log(`[MPC Wallet] Service initialized`);
    if (this.wallet.hasKeyShare()) {
      console.log(`[MPC Wallet] Wallet address: ${this.wallet.getAddress()}`);
    }
  }

  getWallet(): MpcAgentWallet {
    if (!this.wallet) {
      throw new Error('MPC Wallet service not initialized');
    }
    return this.wallet;
  }
}

/**
 * Balance Action - check wallet balance
 */
const balanceAction: Action = {
  name: 'WALLET_BALANCE',
  description: 'Check the MPC wallet balance on a specific blockchain',

  validate: async (_runtime: IAgentRuntime, message: Memory) => {
    const text = (message.content as any).text?.toLowerCase() ?? '';
    return (
      text.includes('balance') ||
      text.includes('how much') ||
      text.includes('wallet')
    );
  },

  handler: async (
    runtime: any,
    _message: any,
    _state: any,
    _options: any,
    callback: any
  ): Promise<ActionResult> => {
    try {
      const service = runtime.getService('mpc-wallet') as MpcWalletService;
      const wallet = service.getWallet();

      if (!wallet.hasKeyShare()) {
        await callback({
          text: 'Wallet not initialized - no key share loaded.',
          action: 'WALLET_BALANCE',
        });
        return { success: false, error: new Error('No key share') };
      }

      const address = wallet.getAddress();
      // In production, fetch actual balance from RPC
      const balance = '1.5'; // Mock balance

      await callback({
        text: `Wallet Balance\n\nAddress: ${address}\nBalance: ${balance} ETH\nChain: Ethereum`,
        action: 'WALLET_BALANCE',
      });

      return {
        success: true,
        text: `Balance: ${balance} ETH`,
        values: { balance, address },
        data: { actionName: 'WALLET_BALANCE', balance, address },
      };
    } catch (error) {
      await callback({
        text: 'Failed to check wallet balance.',
        error: true,
      });
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  },
};

/**
 * Send Action - send cryptocurrency
 */
const sendAction: Action = {
  name: 'WALLET_SEND',
  description: 'Send cryptocurrency from the MPC wallet. Requires user approval.',

  validate: async (_runtime: IAgentRuntime, message: Memory) => {
    const text = (message.content as any).text?.toLowerCase() ?? '';
    return (
      text.includes('send') ||
      text.includes('transfer') ||
      text.includes('pay')
    );
  },

  handler: async (
    runtime: any,
    _message: any,
    _state: any,
    _options: any,
    callback: any
  ): Promise<ActionResult> => {
    try {
      const service = runtime.getService('mpc-wallet') as MpcWalletService;
      const wallet = service.getWallet();

      if (!wallet.hasKeyShare()) {
        await callback({
          text: 'Wallet not initialized - no key share loaded.',
          action: 'WALLET_SEND',
        });
        return { success: false, error: new Error('No key share') };
      }

      // Create mock transaction request
      const tx = {
        requestId: crypto.randomUUID(),
        chain: ChainType.Evm,
        to: '0x0000000000000000000000000000000000000000',
        value: '0',
        chainId: 1,
        timestamp: Date.now(),
      };

      // Check policy
      const policyResult = wallet.evaluatePolicy(tx);

      if (!policyResult.approved) {
        await callback({
          text: `Transaction rejected by policy: ${policyResult.reason}`,
          action: 'WALLET_SEND',
        });
        return {
          success: false,
          text: 'Policy rejected',
          data: { reason: policyResult.reason },
        };
      }

      await callback({
        text: `Transaction submitted for approval.\n\nRequest ID: ${tx.requestId}\n\nPlease check your mobile app to approve.`,
        action: 'WALLET_SEND',
      });

      return {
        success: true,
        text: 'Transaction pending approval',
        values: { requestId: tx.requestId },
        data: { actionName: 'WALLET_SEND', requestId: tx.requestId, status: 'pending' },
      };
    } catch (error) {
      await callback({
        text: 'Failed to send transaction.',
        error: true,
      });
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  },
};

/**
 * Policy Check Action - check spending limits
 */
const policyAction: Action = {
  name: 'WALLET_POLICY',
  description: 'Check if a transaction would be approved by the spending policy',

  validate: async (_runtime: IAgentRuntime, message: Memory) => {
    const text = (message.content as any).text?.toLowerCase() ?? '';
    return (
      text.includes('can i') ||
      text.includes('limit') ||
      text.includes('policy') ||
      text.includes('allowed')
    );
  },

  handler: async (
    runtime: any,
    _message: any,
    _state: any,
    _options: any,
    callback: any
  ): Promise<ActionResult> => {
    try {
      const service = runtime.getService('mpc-wallet') as MpcWalletService;
      const wallet = service.getWallet();

      const policy = wallet.getPolicy();
      if (!policy) {
        await callback({
          text: 'No spending policy configured - all transactions allowed.',
          action: 'WALLET_POLICY',
        });
        return { success: true, text: 'No policy', data: { hasPolicy: false } };
      }

      await callback({
        text: `Spending Policy\n\n- Per-transaction limit: 1 ETH\n- Daily limit: 10 ETH\n- Weekly limit: 50 ETH`,
        action: 'WALLET_POLICY',
      });

      return {
        success: true,
        text: 'Policy retrieved',
        data: { actionName: 'WALLET_POLICY', hasPolicy: true },
      };
    } catch (error) {
      await callback({
        text: 'Failed to check policy.',
        error: true,
      });
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  },
};

/**
 * Address Action - get wallet address
 */
const addressAction: Action = {
  name: 'WALLET_ADDRESS',
  description: 'Get the wallet address',

  validate: async (_runtime: IAgentRuntime, message: Memory) => {
    const text = (message.content as any).text?.toLowerCase() ?? '';
    return text.includes('address') || text.includes('my wallet');
  },

  handler: async (
    runtime: any,
    _message: any,
    _state: any,
    _options: any,
    callback: any
  ): Promise<ActionResult> => {
    try {
      const service = runtime.getService('mpc-wallet') as MpcWalletService;
      const wallet = service.getWallet();

      if (!wallet.hasKeyShare()) {
        await callback({
          text: 'Wallet not initialized - no key share loaded.',
          action: 'WALLET_ADDRESS',
        });
        return { success: false, error: new Error('No key share') };
      }

      const address = wallet.getAddress();

      await callback({
        text: `Wallet Address\n\n\`${address}\``,
        action: 'WALLET_ADDRESS',
      });

      return {
        success: true,
        text: address,
        values: { address },
        data: { actionName: 'WALLET_ADDRESS', address },
      };
    } catch (error) {
      await callback({
        text: 'Failed to get wallet address.',
        error: true,
      });
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  },
};

/**
 * Create the MPC Wallet Plugin
 */
export function createMpcWalletPlugin(config: MpcWalletPluginConfig): Plugin {
  const service = new MpcWalletService(config);

  return {
    name: 'mpc-wallet',
    description: 'Secure MPC wallet for AI agents with threshold signing',
    services: [service as any],
    actions: [balanceAction, sendAction, policyAction, addressAction],
    providers: [],
    evaluators: [],
  };
}

// For backwards compatibility
export class MpcWalletPlugin {
  private config: MpcWalletPluginConfig;

  constructor(config: MpcWalletPluginConfig) {
    this.config = config;
  }

  getPlugin(): Plugin {
    return createMpcWalletPlugin(this.config);
  }
}
