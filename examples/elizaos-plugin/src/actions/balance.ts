/**
 * Balance Action
 *
 * Check wallet balance on various chains
 */

import type { PluginContext } from '../plugin.js';
import { createPublicClient, http, formatEther, type Chain } from 'viem';
import { mainnet, polygon, arbitrum } from 'viem/chains';

interface BalanceParams {
  chain?: string;
}

interface BalanceResult {
  address: string;
  balance: {
    raw: string;
    formatted: string;
    symbol: string;
  };
  chain: string;
}

const CHAINS: Record<string, Chain> = {
  ethereum: mainnet,
  polygon: polygon,
  arbitrum: arbitrum,
};

export function balanceAction(context: PluginContext) {
  return {
    name: 'wallet:balance',
    description: 'Check the wallet balance on a specific blockchain',
    parameters: {
      type: 'object',
      properties: {
        chain: {
          type: 'string',
          description: 'Blockchain to check (ethereum, polygon, arbitrum)',
          default: 'ethereum',
        },
      },
    },

    async handler(params: BalanceParams): Promise<BalanceResult> {
      const chainName = params.chain ?? 'ethereum';
      const chain = CHAINS[chainName];

      if (!chain) {
        throw new Error(`Unsupported chain: ${chainName}`);
      }

      if (!context.wallet.hasKeyShare()) {
        throw new Error('Wallet not initialized - no key share loaded');
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

      return {
        address,
        balance: {
          raw: balance.toString(),
          formatted: formatEther(balance),
          symbol: chain.nativeCurrency.symbol,
        },
        chain: chainName,
      };
    },

    examples: [
      {
        user: "What's my wallet balance?",
        assistant: "Let me check your Ethereum wallet balance.",
        action: { chain: 'ethereum' },
      },
      {
        user: 'How much ETH do I have on Polygon?',
        assistant: "I'll check your balance on Polygon.",
        action: { chain: 'polygon' },
      },
    ],
  };
}
