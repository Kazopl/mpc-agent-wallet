/**
 * Send Action
 *
 * Send cryptocurrency from the MPC wallet
 */

import type { PluginContext } from '../plugin.js';
import { ChainType, type TransactionRequest } from '@mpc-wallet/sdk';
import { parseEther, isAddress } from 'viem';

interface SendParams {
  to: string;
  value: string;
  chain?: string;
  data?: string;
}

interface SendResult {
  status: 'pending_approval' | 'approved' | 'rejected' | 'sent';
  requestId: string;
  txHash?: string;
  reason?: string;
}

export function sendAction(context: PluginContext) {
  return {
    name: 'wallet:send',
    description: 'Send cryptocurrency from the MPC wallet. Requires user approval.',
    parameters: {
      type: 'object',
      properties: {
        to: {
          type: 'string',
          description: 'Recipient address (0x...) or ENS name',
        },
        value: {
          type: 'string',
          description: 'Amount to send in ETH (e.g., "0.5")',
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

    async handler(params: SendParams): Promise<SendResult> {
      const { to, value, chain = 'ethereum', data } = params;

      if (!context.wallet.hasKeyShare()) {
        throw new Error('Wallet not initialized - no key share loaded');
      }

      // Validate address
      if (!isAddress(to)) {
        // In production, resolve ENS names here
        throw new Error(`Invalid address: ${to}`);
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
        data,
        chainId,
        timestamp: Date.now(),
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

      if (policyResult.requiresAdditionalApproval) {
        return {
          status: 'pending_approval',
          requestId: tx.requestId,
          reason: 'High-value transaction requires additional approval',
        };
      }

      // In production, send to relay for user approval
      // For now, return pending status
      return {
        status: 'pending_approval',
        requestId: tx.requestId,
      };
    },

    examples: [
      {
        user: 'Send 0.5 ETH to 0x742d35Cc6634C0532925a3b844Bc9e7595f12345',
        assistant: "I'll prepare a transaction to send 0.5 ETH. This will require your approval.",
        action: {
          to: '0x742d35Cc6634C0532925a3b844Bc9e7595f12345',
          value: '0.5',
          chain: 'ethereum',
        },
      },
      {
        user: 'Transfer 100 MATIC on Polygon to vitalik.eth',
        assistant: "I'll send 100 MATIC on Polygon. Let me resolve the ENS name first.",
        action: {
          to: 'vitalik.eth',
          value: '100',
          chain: 'polygon',
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
