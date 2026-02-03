# Agent-to-Agent Example

Demonstrates how two MPC wallet agents can discover each other, verify reputation, and transact using ERC-8004 registries.

## Features

- Agent registration and identity management
- Cross-agent discovery via Identity Registry
- Reputation verification before transactions
- Post-transaction feedback submission
- Validation request workflow

## Installation

```bash
npm install
```

## Running the Example

```bash
# Run the full agent-to-agent demo
npm start

# Run only the discovery demo
npm run demo:discovery

# Run only the reputation demo
npm run demo:reputation
```

## Architecture

```
┌─────────────────┐                    ┌─────────────────┐
│   Agent Alice   │                    │    Agent Bob    │
│   (ID: 1)       │                    │    (ID: 2)      │
└────────┬────────┘                    └────────┬────────┘
         │                                      │
         │  1. Discover Bob's identity          │
         │─────────────────────────────────────►│
         │                                      │
         │  2. Check Bob's reputation           │
         │─────────────────────────────────────►│
         │                                      │
         │  3. Execute transaction              │
         │─────────────────────────────────────►│
         │                                      │
         │  4. Submit feedback                  │
         │─────────────────────────────────────►│
         │                                      │
```

## Code Walkthrough

### 1. Register Both Agents

```typescript
import { AgentClient } from './agent.js';

// Create Alice (a trading agent)
const alice = new AgentClient('alice', {
  name: 'AliceTradingAgent',
  description: 'Automated DeFi trading assistant',
  services: [
    { name: 'swap', endpoint: 'https://alice.agent/swap' },
  ],
});

// Create Bob (a liquidity provider)
const bob = new AgentClient('bob', {
  name: 'BobLiquidityAgent',
  description: 'Liquidity provision across AMMs',
  services: [
    { name: 'provide', endpoint: 'https://bob.agent/provide' },
  ],
});

// Register both on-chain
await alice.register();
await bob.register();
```

### 2. Agent Discovery

```typescript
import { discoverAgent, resolveAgentProfile } from './discovery.js';

// Alice discovers Bob by agent ID
const bobIdentity = await discoverAgent(bob.getAgentId());

console.log('Found agent:', bobIdentity.name);
console.log('Services:', bobIdentity.services.map(s => s.name));
console.log('Wallet:', bobIdentity.walletAddress);
```

### 3. Reputation Check

```typescript
import { checkReputation, meetsReputationThreshold } from './reputation.js';

// Check Bob's reputation before transacting
const bobReputation = await checkReputation(bob.getAgentId());

console.log('Feedback count:', bobReputation.feedbackCount);
console.log('Score:', bobReputation.score.toFixed(2));

// Verify minimum threshold
if (!meetsReputationThreshold(bobReputation, 0.7)) {
  throw new Error('Agent reputation below threshold');
}
```

### 4. Cross-Agent Transaction

```typescript
// Alice sends payment to Bob
const txHash = await alice.sendTo(bob.getWalletAddress(), parseEther('0.1'));

console.log('Transaction:', txHash);
```

### 5. Submit Feedback

```typescript
import { submitFeedback } from './reputation.js';

// Alice gives Bob positive feedback with proof of payment
await submitFeedback({
  fromAgent: alice,
  toAgentId: bob.getAgentId(),
  value: 100n, // +1.00
  decimals: 2,
  tags: ['reliability', 'speed'],
  proofOfPayment: txHash,
});

console.log('Feedback submitted');
```

## Project Structure

```
agent-to-agent/
├── src/
│   ├── index.ts           # Main demo entry point
│   ├── agent.ts           # AgentClient class
│   ├── discovery.ts       # Agent discovery helpers
│   ├── reputation.ts      # Reputation management
│   ├── demo-discovery.ts  # Discovery-only demo
│   └── demo-reputation.ts # Reputation-only demo
├── package.json
├── tsconfig.json
└── README.md
```

## Environment Variables

```bash
# Optional: Use specific RPC endpoint
RPC_URL=https://eth.llamarpc.com

# Optional: Use testnet
CHAIN_ID=11155111  # Sepolia
```

## ERC-8004 Registry Addresses

All networks use the same deterministic addresses:

| Registry | Address |
|----------|---------|
| Identity | `0x7177a6867296406881E20d6647232314736Dd09A` |
| Reputation | `0xB5048e3ef1DA4E04deB6f7d0423D06F63869e322` |
| Validation | `0x662b40A526cb4017d947e71eAF6753BF3eeE66d8` |

## Next Steps

- See [ERC-8004 Integration Guide](../../docs/erc-8004-integration.md) for detailed documentation
- See [ElizaOS Plugin](../elizaos-plugin/) for AI framework integration
- See [Basic Wallet](../basic-wallet/) for core wallet operations
