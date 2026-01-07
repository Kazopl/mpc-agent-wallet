/**
 * Swap Action
 *
 * Swap tokens via DEX (Uniswap)
 */

import type { PluginContext } from '../plugin.js';
import { ChainType, type TransactionRequest } from '@mpc-wallet/sdk';
import { parseUnits, encodeFunctionData } from 'viem';

interface SwapParams {
  tokenIn: string;
  tokenOut: string;
  amountIn: string;
  slippage?: number;
  chain?: string;
}

interface SwapResult {
  status: 'pending_approval' | 'rejected';
  requestId: string;
  quote?: {
    amountIn: string;
    amountOutMin: string;
    priceImpact: string;
  };
  reason?: string;
}

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

export function swapAction(context: PluginContext) {
  return {
    name: 'wallet:swap',
    description: 'Swap tokens via Uniswap. Requires user approval.',
    parameters: {
      type: 'object',
      properties: {
        tokenIn: {
          type: 'string',
          description: 'Token to swap from (address or symbol like WETH, USDC)',
        },
        tokenOut: {
          type: 'string',
          description: 'Token to swap to (address or symbol)',
        },
        amountIn: {
          type: 'string',
          description: 'Amount of tokenIn to swap',
        },
        slippage: {
          type: 'number',
          description: 'Maximum slippage percentage (default: 0.5)',
          default: 0.5,
        },
        chain: {
          type: 'string',
          description: 'Blockchain (ethereum, polygon, arbitrum)',
          default: 'ethereum',
        },
      },
      required: ['tokenIn', 'tokenOut', 'amountIn'],
    },

    async handler(params: SwapParams): Promise<SwapResult> {
      const {
        tokenIn,
        tokenOut,
        amountIn,
        slippage = 0.5,
        chain = 'ethereum',
      } = params;

      if (!context.wallet.hasKeyShare()) {
        throw new Error('Wallet not initialized - no key share loaded');
      }

      // Resolve token addresses
      const tokenInAddress = resolveToken(tokenIn, chain);
      const tokenOutAddress = resolveToken(tokenOut, chain);

      // Get router address
      const routerAddress = UNISWAP_ROUTER[chain];
      if (!routerAddress) {
        throw new Error(`Uniswap not supported on ${chain}`);
      }

      // Build swap transaction
      // In production, this would:
      // 1. Get quote from Uniswap
      // 2. Build proper swap calldata
      // 3. Include deadline and slippage protection

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
        return {
          status: 'rejected',
          requestId: tx.requestId,
          reason: policyResult.reason,
        };
      }

      // Return pending approval with quote
      return {
        status: 'pending_approval',
        requestId: tx.requestId,
        quote,
      };
    },

    examples: [
      {
        user: 'Swap 1 ETH for USDC',
        assistant: "I'll prepare a swap of 1 ETH for USDC via Uniswap.",
        action: {
          tokenIn: 'WETH',
          tokenOut: 'USDC',
          amountIn: '1',
          slippage: 0.5,
          chain: 'ethereum',
        },
      },
      {
        user: 'Exchange 500 USDC for DAI with 0.1% slippage',
        assistant: "I'll swap 500 USDC to DAI with minimal slippage.",
        action: {
          tokenIn: 'USDC',
          tokenOut: 'DAI',
          amountIn: '500',
          slippage: 0.1,
        },
      },
    ],
  };
}

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
