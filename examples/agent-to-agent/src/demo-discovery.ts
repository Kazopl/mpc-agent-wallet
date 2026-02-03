/**
 * Discovery Demo
 *
 * Demonstrates agent discovery features:
 * - Register multiple agents
 * - Search by agent ID
 * - Search by name
 * - List all agents
 * - Check service availability
 */

import { AgentClient } from './agent.js';
import {
  registerInSimulatedRegistry,
  discoverAgent,
  discoverAgentByName,
  listAllAgents,
  formatAgentInfo,
  hasService,
  getServiceEndpoint,
  clearSimulatedRegistry,
} from './discovery.js';

async function main() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('               Agent Discovery Demo (ERC-8004)                  ');
  console.log('═══════════════════════════════════════════════════════════════\n');

  clearSimulatedRegistry();

  // ============================================================================
  // Create and register multiple agents
  // ============================================================================
  console.log('[Setup] Creating and registering agents...\n');

  const agents = [
    new AgentClient('trading', {
      name: 'SuperTrader',
      description: 'High-frequency trading agent',
      services: [
        { name: 'trade', endpoint: 'https://supertrader.ai/trade' },
        { name: 'analyze', endpoint: 'https://supertrader.ai/analyze' },
      ],
    }),
    new AgentClient('lending', {
      name: 'LendMaster',
      description: 'DeFi lending optimization agent',
      services: [
        { name: 'borrow', endpoint: 'https://lendmaster.ai/borrow' },
        { name: 'supply', endpoint: 'https://lendmaster.ai/supply' },
      ],
    }),
    new AgentClient('nft', {
      name: 'NFTHunter',
      description: 'NFT discovery and trading agent',
      services: [
        { name: 'discover', endpoint: 'https://nfthunter.ai/discover' },
        { name: 'bid', endpoint: 'https://nfthunter.ai/bid' },
      ],
    }),
    new AgentClient('bridge', {
      name: 'BridgeBot',
      description: 'Cross-chain bridging assistant',
      services: [
        { name: 'bridge', endpoint: 'https://bridgebot.ai/bridge' },
        { name: 'quote', endpoint: 'https://bridgebot.ai/quote' },
      ],
    }),
  ];

  for (const agent of agents) {
    await agent.initialize();
    await agent.register();
    registerInSimulatedRegistry(agent);
  }

  console.log('');

  // ============================================================================
  // Demo 1: List all registered agents
  // ============================================================================
  console.log('[Demo 1] Listing all registered agents...\n');

  const allAgents = await listAllAgents();

  console.log('\n--- All Registered Agents ---');
  for (const agent of allAgents) {
    console.log(`  - ${agent.name} (ID: ${agent.agentId})`);
    console.log(`    Services: ${agent.services.map(s => s.name).join(', ')}`);
  }
  console.log('');

  // ============================================================================
  // Demo 2: Discover agent by ID
  // ============================================================================
  console.log('[Demo 2] Discovering agent by ID...\n');

  const tradingAgentId = agents[0].getAgentId();
  const discovered = await discoverAgent(tradingAgentId);

  console.log('\n--- Discovered by ID ---');
  console.log(formatAgentInfo(discovered));
  console.log('');

  // ============================================================================
  // Demo 3: Search by name
  // ============================================================================
  console.log('[Demo 3] Searching for agent by name...\n');

  const searchResult = await discoverAgentByName('Lend');

  if (searchResult) {
    console.log('\n--- Found by Name Search ---');
    console.log(formatAgentInfo(searchResult));
  } else {
    console.log('No agent found matching search term');
  }
  console.log('');

  // ============================================================================
  // Demo 4: Check service availability
  // ============================================================================
  console.log('[Demo 4] Checking service availability...\n');

  const nftAgent = await discoverAgentByName('NFT');

  if (nftAgent) {
    console.log(`Agent: ${nftAgent.name}`);
    console.log(`  Has 'discover' service: ${hasService(nftAgent, 'discover')}`);
    console.log(`  Has 'trade' service: ${hasService(nftAgent, 'trade')}`);
    console.log(`  'bid' endpoint: ${getServiceEndpoint(nftAgent, 'bid')}`);
  }
  console.log('');

  // ============================================================================
  // Demo 5: Find agents by capability
  // ============================================================================
  console.log('[Demo 5] Finding agents with specific service...\n');

  const agentsWithQuote = allAgents.filter(a => hasService(a, 'quote'));

  console.log('Agents with "quote" service:');
  for (const agent of agentsWithQuote) {
    const endpoint = getServiceEndpoint(agent, 'quote');
    console.log(`  - ${agent.name}: ${endpoint}`);
  }
  console.log('');

  // ============================================================================
  // Summary
  // ============================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('                    Discovery Demo Complete                     ');
  console.log('═══════════════════════════════════════════════════════════════\n');

  console.log('Demonstrated:');
  console.log('  1. Registered 4 agents in simulated Identity Registry');
  console.log('  2. Listed all registered agents');
  console.log('  3. Discovered agent by ID');
  console.log('  4. Searched for agent by name');
  console.log('  5. Checked service availability and endpoints');
  console.log('  6. Found agents offering specific services\n');
}

main().catch(console.error);
