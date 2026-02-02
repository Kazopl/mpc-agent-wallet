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
  AgentIdentityAPI,
  AgentRegistrationBuilder,
  TrustModel,
  trustModelToString,
  IDENTITY_REGISTRY_ADDRESS,
} from '@mpc-wallet/sdk';

interface RegisterAgentOptions {
  name: string;
  description: string;
  version?: string;
  services?: Array<{ name: string; endpoint: string; description?: string }>;
  trustModels?: TrustModel[];
  website?: string;
  iconUrl?: string;
}

function extractRegistrationConfig(text: string): Partial<RegisterAgentOptions> {
  const config: Partial<RegisterAgentOptions> = {};

  const nameMatch = text.match(/(?:name|called|named)\s*[:=]?\s*["']?([^"'\n,]+)["']?/i);
  if (nameMatch) {
    config.name = nameMatch[1].trim();
  }

  const descMatch = text.match(/(?:description|desc)\s*[:=]?\s*["']?([^"'\n]+)["']?/i);
  if (descMatch) {
    config.description = descMatch[1].trim();
  }

  const versionMatch = text.match(/(?:version|v)\s*[:=]?\s*["']?(\d+\.\d+\.\d+)["']?/i);
  if (versionMatch) {
    config.version = versionMatch[1];
  }

  const websiteMatch = text.match(/(?:website|url)\s*[:=]?\s*["']?(https?:\/\/[^\s"']+)["']?/i);
  if (websiteMatch) {
    config.website = websiteMatch[1];
  }

  return config;
}

export const registerAgentAction: Action = {
  name: 'REGISTER_AGENT',
  description: 'Register this AI agent in the ERC-8004 Identity Registry',
  similes: ['register agent', 'create agent identity', 'register on chain', 'get agent id'],

  validate: async (_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean> => {
    const text = (message.content as unknown as { text?: string }).text?.toLowerCase() ?? '';
    return (
      text.includes('register') &&
      (text.includes('agent') || text.includes('identity'))
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
      const extractedConfig = extractRegistrationConfig(text);

      const service = runtime.getService('mpc-wallet') as unknown as MpcWalletService;
      const wallet = service.getWallet();

      if (!wallet.hasKeyShare()) {
        await callback?.({
          text: 'Wallet not initialized - no key share loaded. Cannot register agent.',
          action: 'REGISTER_AGENT',
        });
        return {
          success: false,
          error: new Error('No key share loaded'),
        };
      }

      const identityApi = new AgentIdentityAPI();

      const agentName = extractedConfig.name ?? 'MPC Wallet Agent';
      const agentDescription = extractedConfig.description ?? 'An AI agent powered by MPC wallet infrastructure';

      const builder = new AgentRegistrationBuilder(agentName)
        .description(agentDescription)
        .version(extractedConfig.version ?? '1.0.0')
        .trustModel(TrustModel.Reputation);

      if (extractedConfig.website) {
        builder.website(extractedConfig.website);
      }

      const registrationConfig = builder.build();
      const registrationFile = identityApi.generateRegistrationFile(registrationConfig);

      const registrationJson = identityApi.registrationFileToJson(registrationFile);

      const walletAddress = wallet.getAddress();
      const registryAddress = identityApi.getRegistryAddress();

      await callback?.({
        text: `Agent Registration Prepared\n\nAgent Name: ${agentName}\nDescription: ${agentDescription}\nVersion: ${registrationFile.version}\nTrust Models: ${registrationFile.trustModels.map((m: TrustModel) => trustModelToString(m)).join(', ')}\nWallet Address: ${walletAddress}\nRegistry: ${registryAddress}\n\nRegistration File Generated:\n\`\`\`json\n${registrationJson.slice(0, 500)}${registrationJson.length > 500 ? '...' : ''}\n\`\`\`\n\nTo complete registration:\n1. Upload the registration file to IPFS\n2. Call the register function with the IPFS URI`,
        action: 'REGISTER_AGENT',
      });

      return {
        success: true,
        text: 'Agent registration prepared',
        values: {
          name: agentName,
          description: agentDescription,
          version: registrationFile.version,
          walletAddress,
          registryAddress,
        },
        data: {
          actionName: 'REGISTER_AGENT',
          registrationFile,
          walletAddress,
          registryAddress,
          status: 'prepared',
        },
      };
    } catch (error) {
      await callback?.({
        text: 'Failed to prepare agent registration.',
      });
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  },

  examples: [
    [
      { name: 'user', content: { text: 'Register my agent in the identity registry' } },
      { name: 'assistant', content: { text: "I'll prepare the agent registration for the ERC-8004 Identity Registry.", action: 'REGISTER_AGENT' } },
    ],
    [
      { name: 'user', content: { text: 'Create an agent identity with name: MyHelper and description: A helpful trading assistant' } },
      { name: 'assistant', content: { text: "I'll set up your agent identity with those details.", action: 'REGISTER_AGENT' } },
    ],
  ],
};

export const updateAgentProfileAction: Action = {
  name: 'UPDATE_AGENT_PROFILE',
  description: 'Update the agent profile URI in the ERC-8004 Identity Registry',
  similes: ['update profile', 'change agent uri', 'update agent info', 'modify agent'],

  validate: async (_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean> => {
    const text = (message.content as unknown as { text?: string }).text?.toLowerCase() ?? '';
    return (
      text.includes('update') &&
      (text.includes('profile') || text.includes('agent') || text.includes('uri'))
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
          text: 'Wallet not initialized - no key share loaded.',
          action: 'UPDATE_AGENT_PROFILE',
        });
        return {
          success: false,
          error: new Error('No key share loaded'),
        };
      }

      const agentIdMatch = text.match(/(?:agent\s*id|agentid)\s*[:=]?\s*(\d+)/i);
      const uriMatch = text.match(/(?:uri|url)\s*[:=]?\s*["']?(ipfs:\/\/[^\s"']+|https?:\/\/[^\s"']+)["']?/i);

      if (!agentIdMatch) {
        await callback?.({
          text: 'Please provide an agent ID to update. Example: "Update agent ID: 123 with URI: ipfs://Qm..."',
          action: 'UPDATE_AGENT_PROFILE',
        });
        return {
          success: false,
          error: new Error('Agent ID not provided'),
        };
      }

      if (!uriMatch) {
        await callback?.({
          text: 'Please provide a new URI for the agent profile. Example: "Update agent ID: 123 with URI: ipfs://Qm..."',
          action: 'UPDATE_AGENT_PROFILE',
        });
        return {
          success: false,
          error: new Error('New URI not provided'),
        };
      }

      const agentId = BigInt(agentIdMatch[1]);
      const newURI = uriMatch[1];

      const identityApi = new AgentIdentityAPI();
      const calldata = identityApi.encodeSetAgentURICalldata(agentId, newURI);

      await callback?.({
        text: `Agent Profile Update Prepared\n\nAgent ID: ${agentId}\nNew URI: ${newURI}\nRegistry: ${IDENTITY_REGISTRY_ADDRESS}\n\nCalldata generated. Submit transaction to complete update.`,
        action: 'UPDATE_AGENT_PROFILE',
      });

      return {
        success: true,
        text: 'Agent profile update prepared',
        values: {
          agentId: agentId.toString(),
          newURI,
        },
        data: {
          actionName: 'UPDATE_AGENT_PROFILE',
          agentId: agentId.toString(),
          newURI,
          calldata,
          registryAddress: IDENTITY_REGISTRY_ADDRESS,
          status: 'prepared',
        },
      };
    } catch (error) {
      await callback?.({
        text: 'Failed to prepare agent profile update.',
      });
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  },

  examples: [
    [
      { name: 'user', content: { text: 'Update agent ID: 42 with URI: ipfs://QmXyz123...' } },
      { name: 'assistant', content: { text: "I'll prepare the transaction to update the agent profile.", action: 'UPDATE_AGENT_PROFILE' } },
    ],
    [
      { name: 'user', content: { text: 'Change my agent profile to point to the new metadata' } },
      { name: 'assistant', content: { text: 'Please provide the agent ID and new URI to update.', action: 'UPDATE_AGENT_PROFILE' } },
    ],
  ],
};

export const getAgentIdentityAction: Action = {
  name: 'GET_AGENT_IDENTITY',
  description: 'Look up an agent identity from the ERC-8004 Identity Registry',
  similes: ['get agent', 'lookup agent', 'find agent', 'agent info', 'who is agent'],

  validate: async (_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean> => {
    const text = (message.content as unknown as { text?: string }).text?.toLowerCase() ?? '';
    return (
      (text.includes('get') || text.includes('lookup') || text.includes('find') || text.includes('who')) &&
      text.includes('agent')
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
          text: 'Please provide an agent ID to look up. Example: "Get agent 42" or "Who is agent ID: 123"',
          action: 'GET_AGENT_IDENTITY',
        });
        return {
          success: false,
          error: new Error('Agent ID not provided'),
        };
      }

      const agentId = BigInt(agentIdMatch[1]);

      await callback?.({
        text: `Agent Identity Lookup\n\nAgent ID: ${agentId}\nRegistry: ${IDENTITY_REGISTRY_ADDRESS}\n\nTo fetch full details, query the Identity Registry contract with agent ID ${agentId}.`,
        action: 'GET_AGENT_IDENTITY',
      });

      return {
        success: true,
        text: `Agent ${agentId} lookup prepared`,
        values: {
          agentId: agentId.toString(),
          registryAddress: IDENTITY_REGISTRY_ADDRESS,
        },
        data: {
          actionName: 'GET_AGENT_IDENTITY',
          agentId: agentId.toString(),
          registryAddress: IDENTITY_REGISTRY_ADDRESS,
        },
      };
    } catch (error) {
      await callback?.({
        text: 'Failed to look up agent identity.',
      });
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  },

  examples: [
    [
      { name: 'user', content: { text: 'Get agent 42' } },
      { name: 'assistant', content: { text: "I'll look up the identity for agent 42.", action: 'GET_AGENT_IDENTITY' } },
    ],
    [
      { name: 'user', content: { text: 'Who is agent ID: 100?' } },
      { name: 'assistant', content: { text: "I'll fetch the details for agent 100.", action: 'GET_AGENT_IDENTITY' } },
    ],
  ],
};
