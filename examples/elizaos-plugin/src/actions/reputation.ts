import type {
  Action,
  ActionResult,
  IAgentRuntime,
  Memory,
  State,
  HandlerCallback,
} from '@elizaos/core';
import type { MpcWalletService } from '../plugin.js';
import {
  ReputationAPI,
  FeedbackBuilder,
  SummaryQueryBuilder,
  REPUTATION_REGISTRY_ADDRESS,
} from '@mpc-wallet/sdk';

function extractFeedbackParams(text: string): {
  agentId: bigint | null;
  value: number | null;
  isPositive: boolean;
  tag1: string | null;
  tag2: string | null;
  proofOfPayment: string | null;
} {
  const agentIdMatch = text.match(/(?:agent\s*(?:id)?)\s*[:=]?\s*(\d+)/i);
  const agentId = agentIdMatch ? BigInt(agentIdMatch[1]) : null;

  const valueMatch = text.match(/(?:rating|value|score)\s*[:=]?\s*(\d+(?:\.\d+)?)/i);
  const value = valueMatch ? parseFloat(valueMatch[1]) : null;

  const isPositive = !text.toLowerCase().includes('negative') && 
                     !text.toLowerCase().includes('bad') &&
                     !text.toLowerCase().includes('poor');

  const tag1Match = text.match(/(?:tag1|category|type)\s*[:=]?\s*["']?(\w+)["']?/i);
  const tag1 = tag1Match ? tag1Match[1] : null;

  const tag2Match = text.match(/(?:tag2|subcategory)\s*[:=]?\s*["']?(\w+)["']?/i);
  const tag2 = tag2Match ? tag2Match[1] : null;

  const txHashMatch = text.match(/(?:tx|transaction|proof)\s*[:=]?\s*(0x[a-fA-F0-9]{64})/i);
  const proofOfPayment = txHashMatch ? txHashMatch[1] : null;

  return { agentId, value, isPositive, tag1, tag2, proofOfPayment };
}

export const checkReputationAction: Action = {
  name: 'CHECK_REPUTATION',
  description: 'Check the reputation score and feedback summary for an agent',
  similes: ['check reputation', 'get reputation', 'reputation score', 'agent rating', 'how trusted'],

  validate: async (_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean> => {
    const text = (message.content as unknown as { text?: string }).text?.toLowerCase() ?? '';
    return (
      text.includes('reputation') ||
      text.includes('rating') ||
      text.includes('trust') ||
      text.includes('feedback')
    );
  },

  handler: async (
    _runtime: IAgentRuntime,
    message: Memory,
    _state?: State,
    _options?: unknown,
    callback?: HandlerCallback
  ): Promise<ActionResult> => {
    try {
      const text = (message.content as unknown as { text?: string }).text ?? '';

      const agentIdMatch = text.match(/(?:agent\s*(?:id)?)\s*[:=]?\s*(\d+)/i);

      if (!agentIdMatch) {
        await callback?.({
          text: 'Please provide an agent ID to check reputation. Example: "Check reputation for agent 42"',
          action: 'CHECK_REPUTATION',
        });
        return {
          success: false,
          error: new Error('Agent ID not provided'),
        };
      }

      const agentId = BigInt(agentIdMatch[1]);
      const reputationApi = new ReputationAPI();

      const tag1Match = text.match(/(?:tag|category|type)\s*[:=]?\s*["']?(\w+)["']?/i);
      const tag1 = tag1Match ? tag1Match[1] : undefined;

      const queryBuilder = new SummaryQueryBuilder(agentId);
      if (tag1) {
        queryBuilder.tag1(tag1);
      }
      const queryParams = queryBuilder.build();

      const summaryCalldata = reputationApi.encodeGetSummaryCalldata(queryParams);
      const countCalldata = reputationApi.encodeGetFeedbackCountCalldata(agentId);

      await callback?.({
        text: `Reputation Query Prepared\n\nAgent ID: ${agentId}\nRegistry: ${REPUTATION_REGISTRY_ADDRESS}${tag1 ? `\nFilter by tag: ${tag1}` : ''}\n\nTo get full reputation data, query the Reputation Registry contract.\n\nThe reputation score is calculated from:\n- Total feedback count\n- Aggregate value (positive/negative signals)\n- Weighted by proof of payment`,
        action: 'CHECK_REPUTATION',
      });

      return {
        success: true,
        text: `Reputation query prepared for agent ${agentId}`,
        values: {
          agentId: agentId.toString(),
          registryAddress: REPUTATION_REGISTRY_ADDRESS,
          tag1: tag1 ?? null,
        },
        data: {
          actionName: 'CHECK_REPUTATION',
          agentId: agentId.toString(),
          registryAddress: REPUTATION_REGISTRY_ADDRESS,
          summaryCalldata,
          countCalldata,
          queryParams,
        },
      };
    } catch (error) {
      await callback?.({
        text: 'Failed to prepare reputation query.',
      });
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  },

  examples: [
    [
      { name: 'user', content: { text: 'Check reputation for agent 42' } },
      { name: 'assistant', content: { text: "I'll look up the reputation score for agent 42.", action: 'CHECK_REPUTATION' } },
    ],
    [
      { name: 'user', content: { text: "What's the trust rating of agent ID: 100?" } },
      { name: 'assistant', content: { text: "I'll check the reputation data for agent 100.", action: 'CHECK_REPUTATION' } },
    ],
    [
      { name: 'user', content: { text: 'Get reputation for agent 15 filtered by tag: quality' } },
      { name: 'assistant', content: { text: "I'll query reputation filtered by the 'quality' tag.", action: 'CHECK_REPUTATION' } },
    ],
  ],
};

export const giveFeedbackAction: Action = {
  name: 'GIVE_FEEDBACK',
  description: 'Submit feedback for an agent to the ERC-8004 Reputation Registry',
  similes: ['give feedback', 'rate agent', 'submit rating', 'leave review', 'review agent'],

  validate: async (_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean> => {
    const text = (message.content as unknown as { text?: string }).text?.toLowerCase() ?? '';
    return (
      (text.includes('feedback') || text.includes('rate') || text.includes('review')) &&
      text.includes('agent')
    );
  },

  handler: async (
    runtime: IAgentRuntime,
    message: Memory,
    _state?: State,
    _options?: unknown,
    callback?: HandlerCallback
  ): Promise<ActionResult> => {
    try {
      const text = (message.content as unknown as { text?: string }).text ?? '';

      const service = runtime.getService('mpc-wallet') as unknown as MpcWalletService;
      const wallet = service.getWallet();

      if (!wallet.hasKeyShare()) {
        await callback?.({
          text: 'Wallet not initialized - no key share loaded. Cannot submit feedback.',
          action: 'GIVE_FEEDBACK',
        });
        return {
          success: false,
          error: new Error('No key share loaded'),
        };
      }

      const params = extractFeedbackParams(text);

      if (!params.agentId) {
        await callback?.({
          text: 'Please provide an agent ID to give feedback. Example: "Give feedback to agent 42 rating: 85"',
          action: 'GIVE_FEEDBACK',
        });
        return {
          success: false,
          error: new Error('Agent ID not provided'),
        };
      }

      const reputationApi = new ReputationAPI();
      const walletAddress = wallet.getAddress();

      const feedbackValue = params.value ?? 100;
      const normalizedValue = Math.min(Math.max(feedbackValue, 0), 1000);
      const decimals = 2;

      const feedbackBuilder = new FeedbackBuilder(params.agentId);

      if (params.isPositive) {
        feedbackBuilder.positive(BigInt(normalizedValue), decimals);
      } else {
        feedbackBuilder.negative(BigInt(normalizedValue), decimals);
      }

      if (params.tag1) {
        feedbackBuilder.tag1(params.tag1);
      }
      if (params.tag2) {
        feedbackBuilder.tag2(params.tag2);
      }
      if (params.proofOfPayment) {
        feedbackBuilder.proofOfPaymentFromHex(params.proofOfPayment);
      }

      const feedbackParams = feedbackBuilder.build();
      const calldata = reputationApi.encodeGiveFeedbackCalldata(feedbackParams);

      await callback?.({
        text: `Feedback Submission Prepared\n\nTarget Agent ID: ${params.agentId}\nRating: ${params.isPositive ? '+' : '-'}${normalizedValue / 100} (${params.isPositive ? 'positive' : 'negative'})\nDecimals: ${decimals}${params.tag1 ? `\nTag 1: ${params.tag1}` : ''}${params.tag2 ? `\nTag 2: ${params.tag2}` : ''}${params.proofOfPayment ? `\nProof of Payment: ${params.proofOfPayment.slice(0, 18)}...` : ''}\nFrom: ${walletAddress}\nRegistry: ${REPUTATION_REGISTRY_ADDRESS}\n\nCalldata generated. Submit transaction to record feedback on-chain.`,
        action: 'GIVE_FEEDBACK',
      });

      return {
        success: true,
        text: 'Feedback submission prepared',
        values: {
          agentId: params.agentId.toString(),
          value: normalizedValue,
          isPositive: params.isPositive,
          tag1: params.tag1,
          tag2: params.tag2,
        },
        data: {
          actionName: 'GIVE_FEEDBACK',
          agentId: params.agentId.toString(),
          feedbackParams,
          calldata,
          registryAddress: REPUTATION_REGISTRY_ADDRESS,
          reviewerAddress: walletAddress,
          status: 'prepared',
        },
      };
    } catch (error) {
      await callback?.({
        text: 'Failed to prepare feedback submission.',
      });
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  },

  examples: [
    [
      { name: 'user', content: { text: 'Give feedback to agent 42 rating: 95' } },
      { name: 'assistant', content: { text: "I'll prepare positive feedback with a rating of 95 for agent 42.", action: 'GIVE_FEEDBACK' } },
    ],
    [
      { name: 'user', content: { text: 'Rate agent ID: 15 with negative feedback value: 30 tag: reliability' } },
      { name: 'assistant', content: { text: "I'll prepare negative feedback for agent 15 tagged as reliability.", action: 'GIVE_FEEDBACK' } },
    ],
    [
      { name: 'user', content: { text: 'Submit review for agent 100 with proof tx: 0x123...' } },
      { name: 'assistant', content: { text: "I'll prepare feedback with the transaction as proof of payment.", action: 'GIVE_FEEDBACK' } },
    ],
  ],
};

export const revokeFeedbackAction: Action = {
  name: 'REVOKE_FEEDBACK',
  description: 'Revoke previously submitted feedback for an agent',
  similes: ['revoke feedback', 'remove rating', 'delete review', 'cancel feedback'],

  validate: async (_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean> => {
    const text = (message.content as unknown as { text?: string }).text?.toLowerCase() ?? '';
    return (
      text.includes('revoke') ||
      text.includes('remove') ||
      text.includes('delete') ||
      text.includes('cancel')
    ) && text.includes('feedback');
  },

  handler: async (
    runtime: IAgentRuntime,
    message: Memory,
    _state?: State,
    _options?: unknown,
    callback?: HandlerCallback
  ): Promise<ActionResult> => {
    try {
      const text = (message.content as unknown as { text?: string }).text ?? '';

      const service = runtime.getService('mpc-wallet') as unknown as MpcWalletService;
      const wallet = service.getWallet();

      if (!wallet.hasKeyShare()) {
        await callback?.({
          text: 'Wallet not initialized - no key share loaded.',
          action: 'REVOKE_FEEDBACK',
        });
        return {
          success: false,
          error: new Error('No key share loaded'),
        };
      }

      const agentIdMatch = text.match(/(?:agent\s*(?:id)?)\s*[:=]?\s*(\d+)/i);
      const indexMatch = text.match(/(?:feedback\s*)?(?:index|id)\s*[:=]?\s*(\d+)/i);

      if (!agentIdMatch) {
        await callback?.({
          text: 'Please provide an agent ID. Example: "Revoke feedback for agent 42 index: 5"',
          action: 'REVOKE_FEEDBACK',
        });
        return {
          success: false,
          error: new Error('Agent ID not provided'),
        };
      }

      if (!indexMatch) {
        await callback?.({
          text: 'Please provide the feedback index to revoke. Example: "Revoke feedback for agent 42 index: 5"',
          action: 'REVOKE_FEEDBACK',
        });
        return {
          success: false,
          error: new Error('Feedback index not provided'),
        };
      }

      const agentId = BigInt(agentIdMatch[1]);
      const feedbackIndex = BigInt(indexMatch[1]);

      const reputationApi = new ReputationAPI();
      const calldata = reputationApi.encodeRevokeFeedbackCalldata(agentId, feedbackIndex);

      await callback?.({
        text: `Feedback Revocation Prepared\n\nAgent ID: ${agentId}\nFeedback Index: ${feedbackIndex}\nRegistry: ${REPUTATION_REGISTRY_ADDRESS}\n\nCalldata generated. Submit transaction to revoke feedback.`,
        action: 'REVOKE_FEEDBACK',
      });

      return {
        success: true,
        text: 'Feedback revocation prepared',
        values: {
          agentId: agentId.toString(),
          feedbackIndex: feedbackIndex.toString(),
        },
        data: {
          actionName: 'REVOKE_FEEDBACK',
          agentId: agentId.toString(),
          feedbackIndex: feedbackIndex.toString(),
          calldata,
          registryAddress: REPUTATION_REGISTRY_ADDRESS,
          status: 'prepared',
        },
      };
    } catch (error) {
      await callback?.({
        text: 'Failed to prepare feedback revocation.',
      });
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  },

  examples: [
    [
      { name: 'user', content: { text: 'Revoke feedback for agent 42 index: 5' } },
      { name: 'assistant', content: { text: "I'll prepare the revocation for feedback #5 on agent 42.", action: 'REVOKE_FEEDBACK' } },
    ],
    [
      { name: 'user', content: { text: 'Remove my review from agent ID: 100 feedback index: 2' } },
      { name: 'assistant', content: { text: "I'll prepare to remove feedback #2 from agent 100.", action: 'REVOKE_FEEDBACK' } },
    ],
  ],
};
