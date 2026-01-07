/**
 * Policy Action
 *
 * Check if a transaction would be approved by the policy engine
 */

import type { PluginContext } from '../plugin.js';
import { ChainType, type TransactionRequest } from '@mpc-wallet/sdk';
import { parseEther, isAddress } from 'viem';

interface PolicyCheckParams {
  to: string;
  value: string;
  chain?: string;
  data?: string;
}

interface PolicyCheckResult {
  approved: boolean;
  reason?: string;
  requiresAdditionalApproval: boolean;
  limits?: {
    perTransaction: string;
    dailyRemaining: string;
    weeklyRemaining: string;
  };
}

export function policyAction(context: PluginContext) {
  return {
    name: 'wallet:checkPolicy',
    description: 'Check if a transaction would be approved by the spending policy',
    parameters: {
      type: 'object',
      properties: {
        to: {
          type: 'string',
          description: 'Recipient address',
        },
        value: {
          type: 'string',
          description: 'Amount in ETH',
        },
        chain: {
          type: 'string',
          description: 'Blockchain (ethereum, polygon, arbitrum)',
          default: 'ethereum',
        },
        data: {
          type: 'string',
          description: 'Optional transaction data (hex)',
        },
      },
      required: ['to', 'value'],
    },

    async handler(params: PolicyCheckParams): Promise<PolicyCheckResult> {
      const { to, value, chain = 'ethereum', data } = params;

      if (!context.wallet.hasKeyShare()) {
        throw new Error('Wallet not initialized - no key share loaded');
      }

      // Validate address
      if (!isAddress(to)) {
        return {
          approved: false,
          reason: 'Invalid recipient address',
          requiresAdditionalApproval: false,
        };
      }

      // Create mock transaction for policy check
      const tx: TransactionRequest = {
        requestId: 'policy-check-' + Date.now(),
        chain: ChainType.Evm,
        to,
        value: parseEther(value).toString(),
        data,
        chainId: getChainId(chain),
        timestamp: Date.now(),
      };

      // Evaluate policy
      const result = context.wallet.evaluatePolicy(tx);

      // Get current policy config for limits info
      const policy = context.wallet.getPolicy();

      return {
        approved: result.approved,
        reason: result.reason,
        requiresAdditionalApproval: result.requiresAdditionalApproval ?? false,
        limits: policy ? {
          perTransaction: '1 ETH', // In production, get from policy
          dailyRemaining: '8.5 ETH',
          weeklyRemaining: '42 ETH',
        } : undefined,
      };
    },

    examples: [
      {
        user: 'Can I send 5 ETH to this address?',
        assistant: "Let me check if that's within your spending limits.",
        action: {
          to: '0x742d35Cc6634C0532925a3b844Bc9e7595f12345',
          value: '5',
        },
      },
      {
        user: "What's my remaining daily limit?",
        assistant: "I'll check your current spending limits.",
        action: {
          to: '0x0000000000000000000000000000000000000001',
          value: '0',
        },
      },
    ],
  };
}

function getChainId(chain: string): number {
  const chainIds: Record<string, number> = {
    ethereum: 1,
    polygon: 137,
    arbitrum: 42161,
  };
  return chainIds[chain] ?? 1;
}
