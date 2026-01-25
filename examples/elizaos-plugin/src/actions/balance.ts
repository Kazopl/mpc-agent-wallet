/**
 * Balance Action
 *
 * Check wallet balance on various chains
 *
 * Updated for ElizaOS v2.0 - Returns ActionResult with required success field
 */

import type {
  Action,
  ActionResult,
  IAgentRuntime,
  Memory,
  State,
  HandlerCallback,
} from '@elizaos/core';
import type { PluginContext } from '../plugin.js';
import { createPublicClient, http, formatEther, type Chain } from 'viem';
import { mainnet, polygon, arbitrum } from 'viem/chains';

const CHAINS: Record<string, Chain> = {
  ethereum: mainnet,
  polygon: polygon,
  arbitrum: arbitrum,
};

/**
 * Factory function for creating a balance action with a specific context
 * (Legacy pattern - use for custom implementations)
 */
export function balanceAction(context: PluginContext): Action {
  return {
    name: 'WALLET_BALANCE_CHAIN',
    description: 'Check the wallet balance on a specific blockchain',
    similes: ['check balance', 'wallet balance', 'how much', 'balance on chain'],

    validate: async (_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean> => {
      const text = (message.content as any).text?.toLowerCase() ?? '';
      return (
        text.includes('balance') ||
        text.includes('how much') ||
        text.includes('wallet')
      );
    },

    handler: async (
      _runtime: IAgentRuntime,
      message: Memory,
      _state?: State,
      _options?: any,
      callback?: HandlerCallback
    ): Promise<ActionResult> => {
      try {
        // Extract chain from message or default to ethereum
        const text = (message.content as any).text?.toLowerCase() ?? '';
        let chainName = 'ethereum';
        if (text.includes('polygon') || text.includes('matic')) chainName = 'polygon';
        if (text.includes('arbitrum') || text.includes('arb')) chainName = 'arbitrum';

        const chain = CHAINS[chainName];
        if (!chain) {
          await callback?.({
            text: `Unsupported chain: ${chainName}`,
            action: 'WALLET_BALANCE_CHAIN',
          });
          return {
            success: false,
            error: new Error(`Unsupported chain: ${chainName}`),
          };
        }

        if (!context.wallet.hasKeyShare()) {
          await callback?.({
            text: 'Wallet not initialized - no key share loaded.',
            action: 'WALLET_BALANCE_CHAIN',
          });
          return {
            success: false,
            error: new Error('No key share loaded'),
          };
        }

        const address = context.wallet.getAddress();
        const rpcUrl = context.chains[chainName];

        // Create public client
        const client = createPublicClient({
          chain,
          transport: http(rpcUrl),
        });

        // Get balance
        const balance = await client.getBalance({
          address: address as `0x${string}`,
        });

        const formattedBalance = formatEther(balance);
        const symbol = chain.nativeCurrency.symbol;

        await callback?.({
          text: `Wallet Balance on ${chainName}\n\nAddress: ${address}\nBalance: ${formattedBalance} ${symbol}`,
          action: 'WALLET_BALANCE_CHAIN',
        });

        return {
          success: true,
          text: `Balance: ${formattedBalance} ${symbol}`,
          values: {
            balance: formattedBalance,
            address,
            chain: chainName,
            symbol,
          },
          data: {
            actionName: 'WALLET_BALANCE_CHAIN',
            address,
            balance: {
              raw: balance.toString(),
              formatted: formattedBalance,
              symbol,
            },
            chain: chainName,
          },
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
        { name: 'assistant', content: { text: 'Let me check your Ethereum wallet balance.', action: 'WALLET_BALANCE_CHAIN' } },
      ],
      [
        { name: 'user', content: { text: 'How much ETH do I have on Polygon?' } },
        { name: 'assistant', content: { text: "I'll check your balance on Polygon.", action: 'WALLET_BALANCE_CHAIN' } },
      ],
    ],
  };
}
