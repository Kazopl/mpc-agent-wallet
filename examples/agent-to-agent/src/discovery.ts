import {
  AgentIdentityAPI,
  IDENTITY_REGISTRY_ADDRESS,
  type AgentIdentity,
  type AgentRegistrationFile,
  type Address,
} from '@mpc-wallet/sdk';
import { AgentClient } from './agent.js';

export interface DiscoveredAgent {
  agentId: bigint;
  name: string;
  description: string;
  version: string;
  services: Array<{ name: string; endpoint: string; description?: string }>;
  walletAddress: Address | null;
  registrationFile: AgentRegistrationFile;
}

const simulatedRegistry = new Map<string, {
  agent: AgentClient;
  registrationFile: AgentRegistrationFile;
}>();

export function registerInSimulatedRegistry(agent: AgentClient): void {
  const agentId = agent.getAgentId().toString();
  simulatedRegistry.set(agentId, {
    agent,
    registrationFile: agent.getRegistrationFile(),
  });
  console.log(`[Registry] Agent ${agent.getName()} registered with ID ${agentId}`);
}

export async function discoverAgent(agentId: bigint): Promise<DiscoveredAgent> {
  console.log(`[Discovery] Looking up agent ${agentId}...`);

  const entry = simulatedRegistry.get(agentId.toString());

  if (!entry) {
    throw new Error(`Agent ${agentId} not found in registry`);
  }

  const { agent, registrationFile } = entry;

  console.log(`[Discovery] Found agent: ${registrationFile.name}`);

  return {
    agentId,
    name: registrationFile.name,
    description: registrationFile.description,
    version: registrationFile.version,
    services: [...registrationFile.services],
    walletAddress: agent.getWalletAddress(),
    registrationFile,
  };
}

export async function discoverAgentByName(name: string): Promise<DiscoveredAgent | null> {
  console.log(`[Discovery] Searching for agent by name: ${name}...`);

  for (const [agentIdStr, entry] of simulatedRegistry.entries()) {
    if (entry.registrationFile.name.toLowerCase().includes(name.toLowerCase())) {
      const agentId = BigInt(agentIdStr);
      console.log(`[Discovery] Found match: ${entry.registrationFile.name} (ID: ${agentId})`);
      return discoverAgent(agentId);
    }
  }

  console.log(`[Discovery] No agent found matching "${name}"`);
  return null;
}

export async function listAllAgents(): Promise<DiscoveredAgent[]> {
  console.log(`[Discovery] Listing all registered agents...`);

  const agents: DiscoveredAgent[] = [];

  for (const [agentIdStr, entry] of simulatedRegistry.entries()) {
    agents.push({
      agentId: BigInt(agentIdStr),
      name: entry.registrationFile.name,
      description: entry.registrationFile.description,
      version: entry.registrationFile.version,
      services: [...entry.registrationFile.services],
      walletAddress: entry.agent.getWalletAddress(),
      registrationFile: entry.registrationFile,
    });
  }

  console.log(`[Discovery] Found ${agents.length} agents`);
  return agents;
}

export function getAgentServices(agent: DiscoveredAgent): string[] {
  return agent.services.map(s => s.name);
}

export function hasService(agent: DiscoveredAgent, serviceName: string): boolean {
  return agent.services.some(s => s.name.toLowerCase() === serviceName.toLowerCase());
}

export function getServiceEndpoint(agent: DiscoveredAgent, serviceName: string): string | null {
  const service = agent.services.find(s => s.name.toLowerCase() === serviceName.toLowerCase());
  return service?.endpoint ?? null;
}

export async function resolveAgentProfile(agentURI: string): Promise<AgentRegistrationFile> {
  const identityApi = new AgentIdentityAPI();
  return identityApi.resolveAgentURI(agentURI);
}

export function formatAgentInfo(agent: DiscoveredAgent): string {
  const lines = [
    `Agent: ${agent.name} (ID: ${agent.agentId})`,
    `Description: ${agent.description}`,
    `Version: ${agent.version}`,
    `Wallet: ${agent.walletAddress ?? 'Not linked'}`,
    `Services: ${agent.services.map(s => s.name).join(', ') || 'None'}`,
  ];
  return lines.join('\n');
}

export function clearSimulatedRegistry(): void {
  simulatedRegistry.clear();
  console.log('[Registry] Cleared all registered agents');
}
