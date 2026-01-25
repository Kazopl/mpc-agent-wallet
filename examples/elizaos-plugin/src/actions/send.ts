/**
 * Send Action
 *
 * Send cryptocurrency from the MPC wallet
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
import { parseEther, isAddress } from 'viem';

function getChainId(chain: string): number {
  const chainIds: Record<string, number> = {
    ethereum: 1,
    polygon: 137,
    arbitrum: 42161,
  };
  return chainIds[chain] ?? 1;
}

/**
 * Factory function for creating a send action with a specific context
 * (Legacy pattern - use for custom implementations)
 */
export function sendAction(context: PluginContext): Action {
  return {
    name: 'WALLET_SEND_TX',
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
      _runtime: IAgentRuntime,
      message: Memory,
      _state?: State,
      _options?: any,
      callback?: HandlerCallback
    ): Promise<ActionResult> => {
      try {
        // Extract parameters from message (in production, use NLP extraction)
        const text = (message.content as any).text ?? '';

        // Simple regex to extract address and amount (production should use proper NLP)
        const addressMatch = text.match(/0x[a-fA-F0-9]{40}/);
        const amountMatch = text.match(/(\d+\.?\d*)\s*(ETH|MATIC|eth|matic)?/i);

        const to = addressMatch?.[0];
        const value = amountMatch?.[1] ?? '0';

        // Determine chain from context
        let chain = 'ethereum';
        if (text.toLowerCase().includes('polygon') || text.toLowerCase().includes('matic')) {
          chain = 'polygon';
        } else if (text.toLowerCase().includes('arbitrum')) {
          chain = 'arbitrum';
        }

        if (!to) {
          await callback?.({
            text: 'Please provide a valid recipient address (0x...).',
            action: 'WALLET_SEND_TX',
          });
          return {
            success: false,
            error: new Error('No recipient address provided'),
          };
        }

        if (!context.wallet.hasKeyShare()) {
          await callback?.({
            text: 'Wallet not initialized - no key share loaded.',
            action: 'WALLET_SEND_TX',
          });
          return {
            success: false,
            error: new Error('No key share loaded'),
          };
        }

        // Validate address
        if (!isAddress(to)) {
          await callback?.({
            text: `Invalid address: ${to}`,
            action: 'WALLET_SEND_TX',
          });
          return {
            success: false,
            error: new Error(`Invalid address: ${to}`),
          };
        }

        // Get chain ID
        const chainId = getChainId(chain);

        // Parse value to wei
        const valueWei = parseEther(value);

        // Create transaction request
        const tx: TransactionRequest = {
          requestId: crypto.randomUUID(),
          chain: ChainType.Evm,
          to,
          value: valueWei.toString(),
          chainId,
          timestamp: Date.now(),
        };

        // Check policy
        const policyResult = context.wallet.evaluatePolicy(tx);

        if (!policyResult.approved) {
          await callback?.({
            text: `Transaction rejected by policy: ${policyResult.reason}`,
            action: 'WALLET_SEND_TX',
          });
          return {
            success: false,
            text: 'Policy rejected',
            data: {
              actionName: 'WALLET_SEND_TX',
              status: 'rejected',
              requestId: tx.requestId,
              reason: policyResult.reason,
            },
          };
        }

        const status = policyResult.requiresAdditionalApproval
          ? 'pending_approval'
          : 'pending_approval'; // Always requires user approval for MPC

        await callback?.({
          text: `Transaction prepared.\n\nTo: ${to}\nAmount: ${value} ETH\nChain: ${chain}\nRequest ID: ${tx.requestId}\n\nPlease check your mobile app to approve.`,
          action: 'WALLET_SEND_TX',
        });

        return {
          success: true,
          text: `Transaction ${status}`,
          values: {
            requestId: tx.requestId,
            to,
            value,
            chain,
            status,
          },
          data: {
            actionName: 'WALLET_SEND_TX',
            status,
            requestId: tx.requestId,
            to,
            value,
            chain,
          },
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
        { name: 'assistant', content: { text: "I'll prepare a transaction to send 0.5 ETH. This will require your approval.", action: 'WALLET_SEND_TX' } },
      ],
      [
        { name: 'user', content: { text: 'Transfer 100 MATIC on Polygon to 0x742d35Cc6634C0532925a3b844Bc9e7595f12345' } },
        { name: 'assistant', content: { text: "I'll send 100 MATIC on Polygon.", action: 'WALLET_SEND_TX' } },
      ],
    ],
  };
}
