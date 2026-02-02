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
  ValidationAPI,
  ValidationRequestBuilder,
  VALIDATION_REGISTRY_ADDRESS,
} from '@mpc-wallet/sdk';
import type { Address, Hash } from '@mpc-wallet/sdk';
import { isAddress } from 'viem';

function extractValidationParams(text: string): {
  agentId: bigint | null;
  validator: string | null;
  requestURI: string | null;
  contentHash: string | null;
  requestHash: string | null;
} {
  const agentIdMatch = text.match(/(?:agent\s*(?:id)?)\s*[:=]?\s*(\d+)/i);
  const agentId = agentIdMatch ? BigInt(agentIdMatch[1]) : null;

  const validatorMatch = text.match(/(?:validator)\s*[:=]?\s*(0x[a-fA-F0-9]{40})/i);
  const validator = validatorMatch ? validatorMatch[1] : null;

  const uriMatch = text.match(/(?:uri|url)\s*[:=]?\s*["']?(ipfs:\/\/[^\s"']+|https?:\/\/[^\s"']+|tee:\/\/[^\s"']+|zkml:\/\/[^\s"']+)["']?/i);
  const requestURI = uriMatch ? uriMatch[1] : null;

  const contentHashMatch = text.match(/(?:content\s*hash|hash)\s*[:=]?\s*(0x[a-fA-F0-9]{64})/i);
  const contentHash = contentHashMatch ? contentHashMatch[1] : null;

  const requestHashMatch = text.match(/(?:request\s*hash)\s*[:=]?\s*(0x[a-fA-F0-9]{64})/i);
  const requestHash = requestHashMatch ? requestHashMatch[1] : null;

  return { agentId, validator, requestURI, contentHash, requestHash };
}

export const requestValidationAction: Action = {
  name: 'REQUEST_VALIDATION',
  description: 'Request validation/attestation for an agent from a validator in the ERC-8004 Validation Registry',
  similes: ['request validation', 'get validated', 'request attestation', 'validate agent', 'get certified'],

  validate: async (_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean> => {
    const text = (message.content as unknown as { text?: string }).text?.toLowerCase() ?? '';
    return (
      text.includes('validation') ||
      text.includes('validate') ||
      text.includes('attestation') ||
      text.includes('certify')
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
          text: 'Wallet not initialized - no key share loaded. Cannot request validation.',
          action: 'REQUEST_VALIDATION',
        });
        return {
          success: false,
          error: new Error('No key share loaded'),
        };
      }

      const params = extractValidationParams(text);

      if (!params.agentId) {
        await callback?.({
          text: 'Please provide an agent ID for validation. Example: "Request validation for agent 42 validator: 0x..."',
          action: 'REQUEST_VALIDATION',
        });
        return {
          success: false,
          error: new Error('Agent ID not provided'),
        };
      }

      if (!params.validator) {
        await callback?.({
          text: 'Please provide a validator address. Example: "Request validation for agent 42 validator: 0x..."',
          action: 'REQUEST_VALIDATION',
        });
        return {
          success: false,
          error: new Error('Validator address not provided'),
        };
      }

      if (!isAddress(params.validator)) {
        await callback?.({
          text: `Invalid validator address: ${params.validator}`,
          action: 'REQUEST_VALIDATION',
        });
        return {
          success: false,
          error: new Error('Invalid validator address'),
        };
      }

      const validationApi = new ValidationAPI();
      const walletAddress = wallet.getAddress();

      const requestURI = params.requestURI ?? `ipfs://pending-upload/agent-${params.agentId}`;
      const contentHash = params.contentHash ?? ('0x' + '0'.repeat(64)) as Hash;

      const requestBuilder = new ValidationRequestBuilder()
        .forAgent(params.agentId)
        .withValidator(params.validator as Address)
        .withRequestURI(requestURI)
        .withContentHash(contentHash as Hash);

      const requestParams = requestBuilder.build();
      const calldata = validationApi.encodeValidationRequestCalldata(requestParams);

      await callback?.({
        text: `Validation Request Prepared\n\nAgent ID: ${params.agentId}\nValidator: ${params.validator}\nRequest URI: ${requestURI}\nContent Hash: ${contentHash.slice(0, 18)}...\nRequester: ${walletAddress}\nRegistry: ${VALIDATION_REGISTRY_ADDRESS}\n\nCalldata generated. Submit transaction to request validation.\n\nThe validator will respond with:\n- Approved: Agent meets validation criteria\n- Rejected: Agent does not meet criteria\n- Expired: Request not processed in time`,
        action: 'REQUEST_VALIDATION',
      });

      return {
        success: true,
        text: 'Validation request prepared',
        values: {
          agentId: params.agentId.toString(),
          validator: params.validator,
          requestURI,
        },
        data: {
          actionName: 'REQUEST_VALIDATION',
          agentId: params.agentId.toString(),
          validator: params.validator,
          requestURI,
          contentHash,
          calldata,
          registryAddress: VALIDATION_REGISTRY_ADDRESS,
          requesterAddress: walletAddress,
          status: 'prepared',
        },
      };
    } catch (error) {
      await callback?.({
        text: 'Failed to prepare validation request.',
      });
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  },

  examples: [
    [
      { name: 'user', content: { text: 'Request validation for agent 42 validator: 0x1234567890123456789012345678901234567890' } },
      { name: 'assistant', content: { text: "I'll prepare a validation request for agent 42.", action: 'REQUEST_VALIDATION' } },
    ],
    [
      { name: 'user', content: { text: 'Get agent 15 validated by TEE attestation validator: 0xAbCd...' } },
      { name: 'assistant', content: { text: "I'll prepare the TEE attestation request.", action: 'REQUEST_VALIDATION' } },
    ],
  ],
};

export const checkValidationStatusAction: Action = {
  name: 'CHECK_VALIDATION_STATUS',
  description: 'Check the status of a validation request in the ERC-8004 Validation Registry',
  similes: ['check validation', 'validation status', 'is validated', 'attestation status'],

  validate: async (_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean> => {
    const text = (message.content as unknown as { text?: string }).text?.toLowerCase() ?? '';
    return (
      (text.includes('check') || text.includes('status') || text.includes('is')) &&
      (text.includes('validation') || text.includes('validated') || text.includes('attestation'))
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
      const params = extractValidationParams(text);

      if (params.requestHash) {
        const validationApi = new ValidationAPI();
        const calldata = validationApi.encodeGetValidationStatusCalldata(params.requestHash as Hash);

        await callback?.({
          text: `Validation Status Query\n\nRequest Hash: ${params.requestHash}\nRegistry: ${VALIDATION_REGISTRY_ADDRESS}\n\nQuery the Validation Registry to get current status:\n- Pending: Awaiting validator response\n- Approved: Validation successful\n- Rejected: Validation failed\n- Expired: Request timed out`,
          action: 'CHECK_VALIDATION_STATUS',
        });

        return {
          success: true,
          text: 'Validation status query prepared',
          values: {
            requestHash: params.requestHash,
          },
          data: {
            actionName: 'CHECK_VALIDATION_STATUS',
            requestHash: params.requestHash,
            calldata,
            registryAddress: VALIDATION_REGISTRY_ADDRESS,
          },
        };
      }

      if (params.agentId) {
        const validationApi = new ValidationAPI();
        const calldata = validationApi.encodeGetAgentValidationsCalldata(params.agentId);

        await callback?.({
          text: `Agent Validations Query\n\nAgent ID: ${params.agentId}\nRegistry: ${VALIDATION_REGISTRY_ADDRESS}\n\nQuery the Validation Registry to get all validation requests for this agent.`,
          action: 'CHECK_VALIDATION_STATUS',
        });

        return {
          success: true,
          text: `Validation query prepared for agent ${params.agentId}`,
          values: {
            agentId: params.agentId.toString(),
          },
          data: {
            actionName: 'CHECK_VALIDATION_STATUS',
            agentId: params.agentId.toString(),
            calldata,
            registryAddress: VALIDATION_REGISTRY_ADDRESS,
          },
        };
      }

      await callback?.({
        text: 'Please provide either a request hash or agent ID. Example: "Check validation status for request hash: 0x..." or "Check validations for agent 42"',
        action: 'CHECK_VALIDATION_STATUS',
      });

      return {
        success: false,
        error: new Error('Request hash or agent ID not provided'),
      };
    } catch (error) {
      await callback?.({
        text: 'Failed to prepare validation status query.',
      });
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  },

  examples: [
    [
      { name: 'user', content: { text: 'Check validation status for request hash: 0x1234...' } },
      { name: 'assistant', content: { text: "I'll check the status of that validation request.", action: 'CHECK_VALIDATION_STATUS' } },
    ],
    [
      { name: 'user', content: { text: 'Is agent 42 validated?' } },
      { name: 'assistant', content: { text: "I'll check the validation status for agent 42.", action: 'CHECK_VALIDATION_STATUS' } },
    ],
    [
      { name: 'user', content: { text: 'Get all validations for agent ID: 100' } },
      { name: 'assistant', content: { text: "I'll fetch all validation requests for agent 100.", action: 'CHECK_VALIDATION_STATUS' } },
    ],
  ],
};

export const listValidatorRequestsAction: Action = {
  name: 'LIST_VALIDATOR_REQUESTS',
  description: 'List all validation requests assigned to a specific validator',
  similes: ['validator requests', 'pending validations', 'validator queue'],

  validate: async (_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean> => {
    const text = (message.content as unknown as { text?: string }).text?.toLowerCase() ?? '';
    return (
      text.includes('validator') &&
      (text.includes('requests') || text.includes('pending') || text.includes('queue'))
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

      const validatorMatch = text.match(/(?:validator)\s*[:=]?\s*(0x[a-fA-F0-9]{40})/i);

      if (!validatorMatch) {
        await callback?.({
          text: 'Please provide a validator address. Example: "List requests for validator: 0x..."',
          action: 'LIST_VALIDATOR_REQUESTS',
        });
        return {
          success: false,
          error: new Error('Validator address not provided'),
        };
      }

      const validator = validatorMatch[1];

      if (!isAddress(validator)) {
        await callback?.({
          text: `Invalid validator address: ${validator}`,
          action: 'LIST_VALIDATOR_REQUESTS',
        });
        return {
          success: false,
          error: new Error('Invalid validator address'),
        };
      }

      const validationApi = new ValidationAPI();
      const calldata = validationApi.encodeGetValidatorRequestsCalldata(validator as Address);

      await callback?.({
        text: `Validator Requests Query\n\nValidator: ${validator}\nRegistry: ${VALIDATION_REGISTRY_ADDRESS}\n\nQuery the Validation Registry to get all pending requests assigned to this validator.`,
        action: 'LIST_VALIDATOR_REQUESTS',
      });

      return {
        success: true,
        text: `Validator requests query prepared for ${validator}`,
        values: {
          validator,
        },
        data: {
          actionName: 'LIST_VALIDATOR_REQUESTS',
          validator,
          calldata,
          registryAddress: VALIDATION_REGISTRY_ADDRESS,
        },
      };
    } catch (error) {
      await callback?.({
        text: 'Failed to prepare validator requests query.',
      });
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  },

  examples: [
    [
      { name: 'user', content: { text: 'List requests for validator: 0x1234567890123456789012345678901234567890' } },
      { name: 'assistant', content: { text: "I'll fetch all pending validation requests for that validator.", action: 'LIST_VALIDATOR_REQUESTS' } },
    ],
    [
      { name: 'user', content: { text: 'Show pending validations for validator 0xAbCd...' } },
      { name: 'assistant', content: { text: "I'll list all validation requests in the validator's queue.", action: 'LIST_VALIDATOR_REQUESTS' } },
    ],
  ],
};
