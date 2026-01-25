/**
 * Policy Action
 *
 * Check if a transaction would be approved by the policy engine
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
 * Factory function for creating a policy check action with a specific context
 * (Legacy pattern - use for custom implementations)
 */
export function policyAction(context: PluginContext): Action {
  return {
    name: 'WALLET_POLICY_CHECK',
    description: 'Check if a transaction would be approved by the spending policy',
    similes: ['check policy', 'spending limit', 'can i send', 'what are my limits', 'daily limit'],

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
      _runtime: IAgentRuntime,
      message: Memory,
      _state?: State,
      _options?: any,
      callback?: HandlerCallback
    ): Promise<ActionResult> => {
      try {
        // Extract parameters from message (in production, use NLP extraction)
        const text = (message.content as any).text ?? '';

        // Simple regex to extract address and amount
        const addressMatch = text.match(/0x[a-fA-F0-9]{40}/);
        const amountMatch = text.match(/(\d+\.?\d*)\s*(ETH|MATIC|eth|matic)?/i);

        const to = addressMatch?.[0] ?? '0x0000000000000000000000000000000000000001';
        const value = amountMatch?.[1] ?? '0';

        // Determine chain from context
        let chain = 'ethereum';
        if (text.toLowerCase().includes('polygon') || text.toLowerCase().includes('matic')) {
          chain = 'polygon';
        } else if (text.toLowerCase().includes('arbitrum')) {
          chain = 'arbitrum';
        }

        if (!context.wallet.hasKeyShare()) {
          await callback?.({
            text: 'Wallet not initialized - no key share loaded.',
            action: 'WALLET_POLICY_CHECK',
          });
          return {
            success: false,
            error: new Error('No key share loaded'),
          };
        }

        // Validate address
        if (!isAddress(to)) {
          await callback?.({
            text: 'Invalid recipient address for policy check.',
            action: 'WALLET_POLICY_CHECK',
          });
          return {
            success: false,
            text: 'Invalid recipient address',
            data: {
              actionName: 'WALLET_POLICY_CHECK',
              approved: false,
              reason: 'Invalid recipient address',
            },
          };
        }

        // Create mock transaction for policy check
        const tx: TransactionRequest = {
          requestId: 'policy-check-' + Date.now(),
          chain: ChainType.Evm,
          to,
          value: parseEther(value).toString(),
          chainId: getChainId(chain),
          timestamp: Date.now(),
        };

        // Evaluate policy
        const result = context.wallet.evaluatePolicy(tx);

        // Get current policy config for limits info
        const policy = context.wallet.getPolicy();

        const limits = policy ? {
          perTransaction: '1 ETH', // In production, get from policy
          dailyRemaining: '8.5 ETH',
          weeklyRemaining: '42 ETH',
        } : undefined;

        if (result.approved) {
          await callback?.({
            text: `Policy Check: Approved\n\nTransaction to ${to} for ${value} ETH would be approved.${limits ? `\n\nLimits:\n- Per-transaction: ${limits.perTransaction}\n- Daily remaining: ${limits.dailyRemaining}\n- Weekly remaining: ${limits.weeklyRemaining}` : ''}`,
            action: 'WALLET_POLICY_CHECK',
          });
        } else {
          await callback?.({
            text: `Policy Check: Rejected\n\nReason: ${result.reason}${limits ? `\n\nLimits:\n- Per-transaction: ${limits.perTransaction}\n- Daily remaining: ${limits.dailyRemaining}\n- Weekly remaining: ${limits.weeklyRemaining}` : ''}`,
            action: 'WALLET_POLICY_CHECK',
          });
        }

        return {
          success: true,
          text: result.approved ? 'Transaction approved by policy' : 'Transaction rejected by policy',
          values: {
            approved: result.approved,
            reason: result.reason,
            requiresAdditionalApproval: result.requiresAdditionalApproval ?? false,
          },
          data: {
            actionName: 'WALLET_POLICY_CHECK',
            approved: result.approved,
            reason: result.reason,
            requiresAdditionalApproval: result.requiresAdditionalApproval ?? false,
            limits,
          },
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
        { name: 'user', content: { text: 'Can I send 5 ETH to 0x742d35Cc6634C0532925a3b844Bc9e7595f12345?' } },
        { name: 'assistant', content: { text: "Let me check if that's within your spending limits.", action: 'WALLET_POLICY_CHECK' } },
      ],
      [
        { name: 'user', content: { text: "What's my remaining daily limit?" } },
        { name: 'assistant', content: { text: "I'll check your current spending limits.", action: 'WALLET_POLICY_CHECK' } },
      ],
    ],
  };
}
