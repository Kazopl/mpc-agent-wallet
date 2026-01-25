/**
 * Swap Action
 *
 * Swap tokens via DEX (Uniswap)
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
import { ChainType, type TransactionRequest } from '@mpc-wallet/sdk';
import { parseUnits } from 'viem';

// Well-known token addresses
const TOKENS: Record<string, Record<string, string>> = {
  ethereum: {
    ETH: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE',
    WETH: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
    USDC: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
    USDT: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
    DAI: '0x6B175474E89094C44Da98b954EesdedeafCBB7dC',
  },
};

// Uniswap V3 Router
const UNISWAP_ROUTER: Record<string, string> = {
  ethereum: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
  polygon: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
  arbitrum: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
};

function resolveToken(token: string, chain: string): string {
  // Check if it's already an address
  if (token.startsWith('0x') && token.length === 42) {
    return token;
  }

  // Look up by symbol
  const tokens = TOKENS[chain] ?? {};
  const address = tokens[token.toUpperCase()];

  if (!address) {
    throw new Error(`Unknown token: ${token}`);
  }

  return address;
}

function getChainId(chain: string): number {
  const chainIds: Record<string, number> = {
    ethereum: 1,
    polygon: 137,
    arbitrum: 42161,
  };
  return chainIds[chain] ?? 1;
}

/**
 * Factory function for creating a swap action with a specific context
 * (Legacy pattern - use for custom implementations)
 */
export function swapAction(context: PluginContext): Action {
  return {
    name: 'WALLET_SWAP',
    description: 'Swap tokens via Uniswap. Requires user approval.',
    similes: ['swap tokens', 'exchange', 'trade', 'swap eth', 'swap usdc'],

    validate: async (_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean> => {
      const text = (message.content as any).text?.toLowerCase() ?? '';
      return (
        text.includes('swap') ||
        text.includes('exchange') ||
        text.includes('trade')
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
        // Extract parameters from message (in production, use NLP extraction)
        const text = (message.content as any).text?.toLowerCase() ?? '';

        // Simple extraction (production should use proper NLP)
        const amountMatch = text.match(/(\d+\.?\d*)/);
        const amountIn = amountMatch?.[1] ?? '1';

        // Default tokens - in production, extract from message
        let tokenIn = 'ETH';
        let tokenOut = 'USDC';
        const slippage = 0.5;
        let chain = 'ethereum';

        // Simple token detection
        if (text.includes('usdc') && text.includes('dai')) {
          tokenIn = 'USDC';
          tokenOut = 'DAI';
        } else if (text.includes('eth') && text.includes('usdc')) {
          tokenIn = 'WETH';
          tokenOut = 'USDC';
        }

        // Chain detection
        if (text.includes('polygon')) chain = 'polygon';
        if (text.includes('arbitrum')) chain = 'arbitrum';

        if (!context.wallet.hasKeyShare()) {
          await callback?.({
            text: 'Wallet not initialized - no key share loaded.',
            action: 'WALLET_SWAP',
          });
          return {
            success: false,
            error: new Error('No key share loaded'),
          };
        }

        // Resolve token addresses
        let tokenInAddress: string;
        let tokenOutAddress: string;
        try {
          tokenInAddress = resolveToken(tokenIn, chain);
          tokenOutAddress = resolveToken(tokenOut, chain);
        } catch (error) {
          await callback?.({
            text: `Unknown token: ${error instanceof Error ? error.message : 'Invalid token'}`,
            action: 'WALLET_SWAP',
          });
          return {
            success: false,
            error: error instanceof Error ? error : new Error(String(error)),
          };
        }

        // Get router address
        const routerAddress = UNISWAP_ROUTER[chain];
        if (!routerAddress) {
          await callback?.({
            text: `Uniswap not supported on ${chain}`,
            action: 'WALLET_SWAP',
          });
          return {
            success: false,
            error: new Error(`Uniswap not supported on ${chain}`),
          };
        }

        const amountInWei = parseUnits(amountIn, 18); // Assume 18 decimals

        // Simulated quote (in production, fetch from Uniswap API)
        const quote = {
          amountIn: amountInWei.toString(),
          amountOutMin: (amountInWei * BigInt(100 - Math.floor(slippage * 100)) / BigInt(100)).toString(),
          priceImpact: '0.1%',
        };

        // Create transaction request
        const tx: TransactionRequest = {
          requestId: crypto.randomUUID(),
          chain: ChainType.Evm,
          to: routerAddress,
          value: tokenInAddress.toLowerCase() === '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
            ? amountInWei.toString()
            : '0',
          data: '0x...', // In production, encode actual swap calldata
          chainId: getChainId(chain),
          timestamp: Date.now(),
          metadata: {
            type: 'swap',
            tokenIn: tokenInAddress,
            tokenOut: tokenOutAddress,
            amountIn,
            slippage,
          },
        };

        // Check policy
        const policyResult = context.wallet.evaluatePolicy(tx);

        if (!policyResult.approved) {
          await callback?.({
            text: `Swap rejected by policy: ${policyResult.reason}`,
            action: 'WALLET_SWAP',
          });
          return {
            success: false,
            text: 'Policy rejected',
            data: {
              actionName: 'WALLET_SWAP',
              status: 'rejected',
              requestId: tx.requestId,
              reason: policyResult.reason,
            },
          };
        }

        await callback?.({
          text: `Swap prepared.\n\nFrom: ${amountIn} ${tokenIn}\nTo: ${tokenOut}\nSlippage: ${slippage}%\nChain: ${chain}\nRequest ID: ${tx.requestId}\n\nPlease check your mobile app to approve.`,
          action: 'WALLET_SWAP',
        });

        return {
          success: true,
          text: 'Swap pending approval',
          values: {
            requestId: tx.requestId,
            tokenIn,
            tokenOut,
            amountIn,
            chain,
            status: 'pending_approval',
          },
          data: {
            actionName: 'WALLET_SWAP',
            status: 'pending_approval',
            requestId: tx.requestId,
            quote,
          },
        };
      } catch (error) {
        await callback?.({
          text: 'Failed to prepare swap.',
        });
        return {
          success: false,
          error: error instanceof Error ? error : new Error(String(error)),
        };
      }
    },

    examples: [
      [
        { name: 'user', content: { text: 'Swap 1 ETH for USDC' } },
        { name: 'assistant', content: { text: "I'll prepare a swap of 1 ETH for USDC via Uniswap.", action: 'WALLET_SWAP' } },
      ],
      [
        { name: 'user', content: { text: 'Exchange 500 USDC for DAI' } },
        { name: 'assistant', content: { text: "I'll swap 500 USDC to DAI.", action: 'WALLET_SWAP' } },
      ],
    ],
  };
}
