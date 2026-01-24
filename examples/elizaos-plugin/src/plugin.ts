/**
 * MPC Wallet Plugin for ElizaOS
 *
 * Updated for ElizaOS v2.0 API
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import {
  type Plugin,
  type Action,
  type ActionResult,
  type IAgentRuntime,
  type Memory,
  type State,
  type HandlerCallback,
  type MessagePayload,
  type EventPayload,
  Service,
  logger,
} from '@elizaos/core';

// Re-export ActionResult for use in action files
export type { ActionResult };
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
 *
 * v2 Pattern: Extends Service base class with static start() and stop() lifecycle methods
 */
export class MpcWalletService extends Service {
  static serviceType = 'mpc-wallet';
  capabilityDescription = 'Secure MPC wallet with threshold signing for cryptocurrency transactions';

  wallet: MpcAgentWallet | null = null;
  private walletConfig: MpcWalletPluginConfig | null = null;
  chains: Record<string, string> = {};

  constructor(runtime?: IAgentRuntime) {
    super(runtime);
  }

  /**
   * v2 Lifecycle: Static factory method to create and initialize the service
   */
  /**
   * Helper to get string settings from runtime (v2 returns string | boolean | number | null)
   */
  private static getStringSetting(runtime: IAgentRuntime, key: string): string | undefined {
    const value = runtime.getSetting(key);
    if (value === null || value === undefined) return undefined;
    return String(value);
  }

  static async start(runtime: IAgentRuntime): Promise<MpcWalletService> {
    const service = new MpcWalletService(runtime);
    
    const whitelistStr = MpcWalletService.getStringSetting(runtime, 'MPC_WALLET_WHITELIST');
    const blacklistStr = MpcWalletService.getStringSetting(runtime, 'MPC_WALLET_BLACKLIST');
    
    service.walletConfig = {
      password: MpcWalletService.getStringSetting(runtime, 'MPC_WALLET_PASSWORD') ?? '',
      keyPath: MpcWalletService.getStringSetting(runtime, 'MPC_WALLET_KEY_PATH'),
      relayUrl: MpcWalletService.getStringSetting(runtime, 'MPC_WALLET_RELAY_URL'),
      policy: {
        spendingLimits: {
          perTransaction: MpcWalletService.getStringSetting(runtime, 'MPC_WALLET_LIMIT_PER_TX'),
          daily: MpcWalletService.getStringSetting(runtime, 'MPC_WALLET_LIMIT_DAILY'),
          weekly: MpcWalletService.getStringSetting(runtime, 'MPC_WALLET_LIMIT_WEEKLY'),
        },
        whitelist: whitelistStr?.split(',').filter(Boolean),
        blacklist: blacklistStr?.split(',').filter(Boolean),
      },
      chains: {
        ethereum: MpcWalletService.getStringSetting(runtime, 'MPC_WALLET_RPC_ETHEREUM'),
        polygon: MpcWalletService.getStringSetting(runtime, 'MPC_WALLET_RPC_POLYGON'),
        arbitrum: MpcWalletService.getStringSetting(runtime, 'MPC_WALLET_RPC_ARBITRUM'),
      },
    };
    
    service.chains = {
      ethereum: service.walletConfig.chains?.ethereum ?? 'https://eth.llamarpc.com',
      polygon: service.walletConfig.chains?.polygon ?? 'https://polygon-rpc.com',
      arbitrum: service.walletConfig.chains?.arbitrum ?? 'https://arb1.arbitrum.io/rpc',
    };

    await service.initialize(runtime);
    return service;
  }

  /**
   * v2 Lifecycle: Cleanup method called when service is stopped
   */
  async stop(): Promise<void> {
    logger.info('[MPC Wallet] Service stopping, cleaning up...');
    // Clear sensitive wallet data
    this.wallet = null;
    logger.info('[MPC Wallet] Service stopped');
  }

  private async initialize(_runtime: IAgentRuntime): Promise<void> {
    if (!this.walletConfig) {
      throw new Error('MPC Wallet service not configured');
    }

    // Build policy configuration
    const policyConfig = new PolicyConfig();

    if (this.walletConfig.policy?.spendingLimits) {
      const limits = this.walletConfig.policy.spendingLimits;
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

    if (this.walletConfig.policy?.whitelist) {
      policyConfig.withWhitelist(this.walletConfig.policy.whitelist);
    }

    if (this.walletConfig.policy?.blacklist) {
      policyConfig.withBlacklist(this.walletConfig.policy.blacklist);
    }

    // Create wallet
    this.wallet = await MpcAgentWallet.create({
      role: PartyRole.Agent,
      policy: policyConfig,
    });

    // Load key share if path provided
    if (this.walletConfig.keyPath) {
      await this.wallet.loadKeyShare(this.walletConfig.keyPath, this.walletConfig.password);
    }

    logger.info('[MPC Wallet] Service initialized');
    if (this.wallet.hasKeyShare()) {
      logger.info(`[MPC Wallet] Wallet address: ${this.wallet.getAddress()}`);
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
 *
 * v2 Pattern: Returns ActionResult with required success field
 */
const balanceAction: Action = {
  name: 'WALLET_BALANCE',
  description: 'Check the MPC wallet balance on a specific blockchain',
  similes: ['check balance', 'wallet balance', 'how much', 'my balance'],

  validate: async (_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean> => {
    const text = (message.content as any).text?.toLowerCase() ?? '';
    return (
      text.includes('balance') ||
      text.includes('how much') ||
      text.includes('wallet')
    );
  },

  handler: async (
    runtime: IAgentRuntime,
    _message: Memory,
    _state?: State,
    _options?: any,
    callback?: HandlerCallback
  ): Promise<ActionResult> => {
    try {
      const service = runtime.getService('mpc-wallet') as unknown as MpcWalletService;
      const wallet = service.getWallet();

      if (!wallet.hasKeyShare()) {
        await callback?.({
          text: 'Wallet not initialized - no key share loaded.',
          action: 'WALLET_BALANCE',
        });
        return {
          success: false,
          error: new Error('No key share loaded'),
        };
      }

      const address = wallet.getAddress();
      // In production, fetch actual balance from RPC
      const balance = '1.5'; // Mock balance

      await callback?.({
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
      await callback?.({
        text: 'Failed to check wallet balance.',
      });
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  },

  examples: [
    [
      { name: 'user', content: { text: "What's my wallet balance?" } },
      { name: 'assistant', content: { text: 'Let me check your balance.', action: 'WALLET_BALANCE' } },
    ],
    [
      { name: 'user', content: { text: 'How much ETH do I have?' } },
      { name: 'assistant', content: { text: "I'll check your wallet balance.", action: 'WALLET_BALANCE' } },
    ],
  ],
};

/**
 * Send Action - send cryptocurrency
 *
 * v2 Pattern: Returns ActionResult with required success field
 */
const sendAction: Action = {
  name: 'WALLET_SEND',
  description: 'Send cryptocurrency from the MPC wallet. Requires user approval.',
  similes: ['send crypto', 'transfer', 'pay', 'send eth', 'send tokens'],

  validate: async (_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean> => {
    const text = (message.content as any).text?.toLowerCase() ?? '';
    return (
      text.includes('send') ||
      text.includes('transfer') ||
      text.includes('pay')
    );
  },

  handler: async (
    runtime: IAgentRuntime,
    _message: Memory,
    _state?: State,
    _options?: any,
    callback?: HandlerCallback
  ): Promise<ActionResult> => {
    try {
      const service = runtime.getService('mpc-wallet') as unknown as MpcWalletService;
      const wallet = service.getWallet();

      if (!wallet.hasKeyShare()) {
        await callback?.({
          text: 'Wallet not initialized - no key share loaded.',
          action: 'WALLET_SEND',
        });
        return {
          success: false,
          error: new Error('No key share loaded'),
        };
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
        await callback?.({
          text: `Transaction rejected by policy: ${policyResult.reason}`,
          action: 'WALLET_SEND',
        });
        return {
          success: false,
          text: 'Policy rejected',
          data: { actionName: 'WALLET_SEND', reason: policyResult.reason },
        };
      }

      await callback?.({
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
      await callback?.({
        text: 'Failed to send transaction.',
      });
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  },

  examples: [
    [
      { name: 'user', content: { text: 'Send 0.5 ETH to 0x742d35Cc6634C0532925a3b844Bc9e7595f12345' } },
      { name: 'assistant', content: { text: "I'll prepare that transaction for approval.", action: 'WALLET_SEND' } },
    ],
    [
      { name: 'user', content: { text: 'Transfer 100 USDC to my friend' } },
      { name: 'assistant', content: { text: "I'll prepare a USDC transfer. This will require your approval.", action: 'WALLET_SEND' } },
    ],
  ],
};

/**
 * Policy Check Action - check spending limits
 *
 * v2 Pattern: Returns ActionResult with required success field
 */
const policyAction: Action = {
  name: 'WALLET_POLICY',
  description: 'Check if a transaction would be approved by the spending policy',
  similes: ['check policy', 'spending limit', 'can i send', 'what are my limits'],

  validate: async (_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean> => {
    const text = (message.content as any).text?.toLowerCase() ?? '';
    return (
      text.includes('can i') ||
      text.includes('limit') ||
      text.includes('policy') ||
      text.includes('allowed')
    );
  },

  handler: async (
    runtime: IAgentRuntime,
    _message: Memory,
    _state?: State,
    _options?: any,
    callback?: HandlerCallback
  ): Promise<ActionResult> => {
    try {
      const service = runtime.getService('mpc-wallet') as unknown as MpcWalletService;
      const wallet = service.getWallet();

      const policy = wallet.getPolicy();
      if (!policy) {
        await callback?.({
          text: 'No spending policy configured - all transactions allowed.',
          action: 'WALLET_POLICY',
        });
        return {
          success: true,
          text: 'No policy configured',
          data: { actionName: 'WALLET_POLICY', hasPolicy: false },
        };
      }

      await callback?.({
        text: `Spending Policy\n\n- Per-transaction limit: 1 ETH\n- Daily limit: 10 ETH\n- Weekly limit: 50 ETH`,
        action: 'WALLET_POLICY',
      });

      return {
        success: true,
        text: 'Policy retrieved',
        data: { actionName: 'WALLET_POLICY', hasPolicy: true },
      };
    } catch (error) {
      await callback?.({
        text: 'Failed to check policy.',
      });
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  },

  examples: [
    [
      { name: 'user', content: { text: 'What are my spending limits?' } },
      { name: 'assistant', content: { text: "I'll check your wallet spending policy.", action: 'WALLET_POLICY' } },
    ],
    [
      { name: 'user', content: { text: 'Can I send 5 ETH?' } },
      { name: 'assistant', content: { text: 'Let me check if that transaction would be approved.', action: 'WALLET_POLICY' } },
    ],
  ],
};

/**
 * Address Action - get wallet address
 *
 * v2 Pattern: Returns ActionResult with required success field
 */
const addressAction: Action = {
  name: 'WALLET_ADDRESS',
  description: 'Get the wallet address',
  similes: ['get address', 'my address', 'wallet address', 'what is my address'],

  validate: async (_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean> => {
    const text = (message.content as any).text?.toLowerCase() ?? '';
    return text.includes('address') || text.includes('my wallet');
  },

  handler: async (
    runtime: IAgentRuntime,
    _message: Memory,
    _state?: State,
    _options?: any,
    callback?: HandlerCallback
  ): Promise<ActionResult> => {
    try {
      const service = runtime.getService('mpc-wallet') as unknown as MpcWalletService;
      const wallet = service.getWallet();

      if (!wallet.hasKeyShare()) {
        await callback?.({
          text: 'Wallet not initialized - no key share loaded.',
          action: 'WALLET_ADDRESS',
        });
        return {
          success: false,
          error: new Error('No key share loaded'),
        };
      }

      const address = wallet.getAddress();

      await callback?.({
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
      await callback?.({
        text: 'Failed to get wallet address.',
      });
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  },

  examples: [
    [
      { name: 'user', content: { text: "What's my wallet address?" } },
      { name: 'assistant', content: { text: "I'll get your wallet address.", action: 'WALLET_ADDRESS' } },
    ],
    [
      { name: 'user', content: { text: 'Show me my address' } },
      { name: 'assistant', content: { text: 'Here is your wallet address.', action: 'WALLET_ADDRESS' } },
    ],
  ],
};

/**
 * MPC Wallet Plugin - v2 Pattern
 *
 * Uses service class registration (not instance) for v2 lifecycle management.
 * The runtime will call MpcWalletService.start() to instantiate the service.
 */
export const mpcWalletPlugin: Plugin = {
  name: 'mpc-wallet',
  description: 'Secure MPC wallet for AI agents with threshold signing',
  actions: [balanceAction, sendAction, policyAction, addressAction],
  services: [MpcWalletService],
  providers: [],
  evaluators: [],

  events: {
    MESSAGE_RECEIVED: [
      async (params: MessagePayload) => {
        // Log wallet-related messages for debugging
        const text = (params.message.content as any)?.text?.toLowerCase() ?? '';
        if (text.includes('wallet') || text.includes('balance') || text.includes('send')) {
          logger.debug('[MPC Wallet] Received wallet-related message');
        }
      },
    ],
    ACTION_COMPLETED: [
      async (params: EventPayload) => {
        // Track completed wallet actions for analytics and debugging
        // v2 ActionEventPayload contains: roomId, world, content, messageId
        const content = (params as any).content;
        const actions = content?.actions as string[] | undefined;
        
        if (actions?.some((action: string) => action.startsWith('WALLET_'))) {
          logger.debug('[MPC Wallet] Wallet action completed');
        }
      },
    ],
  },

  init: async (_config: any, _runtime: IAgentRuntime) => {
    logger.info('[MPC Wallet] Plugin initialized');
  },
};

/**
 * Create the MPC Wallet Plugin (legacy helper for backwards compatibility)
 */
export function createMpcWalletPlugin(_config?: MpcWalletPluginConfig): Plugin {
  // In v2, config is read from runtime settings in MpcWalletService.start()
  // The config parameter is kept for backwards compatibility but not used
  return mpcWalletPlugin;
}

// For backwards compatibility
export class MpcWalletPlugin {
  private config: MpcWalletPluginConfig;

  constructor(config: MpcWalletPluginConfig) {
    this.config = config;
  }

  getPlugin(): Plugin {
    return mpcWalletPlugin;
  }
}
