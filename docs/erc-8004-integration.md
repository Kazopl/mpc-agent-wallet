# ERC-8004 Integration Guide

This guide covers integrating AI agents with the ERC-8004 standard for trustless agent economies.

## Table of Contents

- [Overview](#overview)
- [Registry Addresses](#registry-addresses)
- [Agent Registration](#agent-registration)
- [Reputation Management](#reputation-management)
- [Validation Workflow](#validation-workflow)
- [Agent-to-Agent Transactions](#agent-to-agent-transactions)
- [ElizaOS Integration](#elizaos-integration)
- [Best Practices](#best-practices)

---

## Overview

ERC-8004 provides three on-chain registries for trustless agent economies:

| Registry                | Purpose                                                 | Token Standard |
|-------------------------|---------------------------------------------------------|----------------|
| **Identity Registry**   | Portable agent handles pointing to registration files   | ERC-721        |
| **Reputation Registry** | Feedback signals with on-chain composability            | Native         |
| **Validation Registry** | Independent validator attestations                      | Native         |

### Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                           MPC Agent Wallet                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐           │
│  │  AgentIdentityAPI │  │   ReputationAPI  │  │   ValidationAPI  │          │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘          │
│           │                     │                     │                     │
└───────────┼─────────────────────┼─────────────────────┼─────────────────────┘
            │                     │                     │
            ▼                     ▼                     ▼
┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐
│ Identity Registry │  │Reputation Registry│  │Validation Registry│
│  (ERC-721 NFT)    │  │                   │  │                   │
└───────────────────┘  └───────────────────┘  └───────────────────┘
```

---

## Registry Addresses

ERC-8004 registries are deployed at deterministic addresses across all networks:

```typescript
import {
  IDENTITY_REGISTRY_ADDRESS,
  REPUTATION_REGISTRY_ADDRESS,
  VALIDATION_REGISTRY_ADDRESS,
} from '@mpc-wallet/sdk';

// Deployed on Ethereum, Base, Polygon, Arbitrum, Optimism, etc.
// Identity:   0x7177a6867296406881E20d6647232314736Dd09A
// Reputation: 0xB5048e3ef1DA4E04deB6f7d0423D06F63869e322
// Validation: 0x662b40A526cb4017d947e71eAF6753BF3eeE66d8
```

---

## Agent Registration

### Step 1: Create Registration File

The registration file describes your agent's capabilities, services, and trust models.

```typescript
import {
  AgentIdentityAPI,
  AgentRegistrationBuilder,
  TrustModel,
} from '@mpc-wallet/sdk';

const identityApi = new AgentIdentityAPI();

// Using the builder pattern
const config = new AgentRegistrationBuilder('MyTradingAgent')
  .description('An AI agent for automated DeFi trading')
  .version('1.0.0')
  .addService({
    name: 'swap',
    endpoint: 'https://api.myagent.ai/swap',
    description: 'Execute token swaps across DEXs',
    methods: ['GET', 'POST'],
    rateLimit: { requestsPerMinute: 60 },
  })
  .addService({
    name: 'portfolio',
    endpoint: 'https://api.myagent.ai/portfolio',
    description: 'View and manage portfolio positions',
  })
  .addCapability({
    name: 'erc20-trading',
    version: '1.0.0',
    parameters: { maxSlippage: 0.5 },
  })
  .trustModel(TrustModel.Reputation)
  .trustModel(TrustModel.CryptoEconomic)
  .website('https://myagent.ai')
  .icon('https://myagent.ai/icon.png')
  .build();

const registrationFile = identityApi.generateRegistrationFile(config);
console.log(identityApi.registrationFileToJson(registrationFile));
```

### Step 2: Upload to IPFS

Upload the registration file to IPFS or Arweave for permanent storage.

```typescript
import { create } from '@web3-storage/w3up-client';

const client = await create();
await client.login('you@example.com');

// Configure the IPFS uploader
identityApi.setIpfsUploader(async (content) => {
  const blob = new Blob([content], { type: 'application/json' });
  const cid = await client.uploadFile(blob);
  return `ipfs://${cid}`;
});

// Upload and get URI
const { uri, contentHash } = await identityApi.uploadRegistrationFile(registrationFile);
console.log('Agent URI:', uri); // ipfs://Qm...
```

### Step 3: Register On-Chain

Call the Identity Registry to mint your agent NFT.

```typescript
import { createPublicClient, createWalletClient, http } from 'viem';
import { mainnet } from 'viem/chains';

const publicClient = createPublicClient({
  chain: mainnet,
  transport: http(),
});

const walletClient = createWalletClient({
  chain: mainnet,
  transport: http(),
  account: '0x...', // Your account
});

// Encode the registration call
const calldata = identityApi.encodeRegisterCalldata(uri);

// Send the transaction
const hash = await walletClient.sendTransaction({
  to: identityApi.getRegistryAddress(),
  data: calldata,
});

// Wait for confirmation and get agent ID
const receipt = await publicClient.waitForTransactionReceipt({ hash });
console.log('Agent registered! Transaction:', hash);
```

### Linking a Wallet to Your Agent

Associate an MPC smart account with your agent identity:

```typescript
const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600); // 1 hour

// Sign the wallet linking message (EIP-712)
const signature = await walletClient.signTypedData({
  domain: {
    name: 'ERC8004Identity',
    version: '1',
    chainId: 1,
    verifyingContract: identityApi.getRegistryAddress(),
  },
  types: {
    SetWallet: [
      { name: 'agentId', type: 'uint256' },
      { name: 'wallet', type: 'address' },
      { name: 'deadline', type: 'uint256' },
    ],
  },
  primaryType: 'SetWallet',
  message: {
    agentId: 42n,
    wallet: '0x...',
    deadline,
  },
});

// Link the wallet
const linkCalldata = identityApi.encodeSetAgentWalletCalldata({
  agentId: 42n,
  wallet: '0x...',
  deadline,
  signature,
});
```

---

## Reputation Management

### Submitting Feedback

After completing a transaction with an agent, submit feedback to the Reputation Registry.

```typescript
import {
  ReputationAPI,
  FeedbackBuilder,
} from '@mpc-wallet/sdk';

const reputationApi = new ReputationAPI();

// Build feedback signal
const feedback = new FeedbackBuilder(42n) // Agent ID
  .positive(100n, 2) // Value: 1.00 (100 with 2 decimals)
  .tags('quality', 'speed')
  .proofOfPaymentFromHex('0x...') // Transaction hash as proof
  .build();

// Encode the feedback call
const calldata = reputationApi.encodeGiveFeedbackCalldata(feedback);

// Submit on-chain
await walletClient.sendTransaction({
  to: reputationApi.getRegistryAddress(),
  data: calldata,
});
```

### Feedback Values

Feedback values are signed integers with configurable decimals:

| Value | Decimals | Meaning           |
|-------|----------|-------------------|
| +500  | 2        | Excellent (+5.00) |
| +100  | 2        | Good (+1.00)      |
| 0     | 2        | Neutral           |
| -100  | 2        | Poor (-1.00)      |
| -500  | 2        | Terrible (-5.00)  |

### Querying Reputation

```typescript
import { SummaryQueryBuilder } from '@mpc-wallet/sdk';

// Build query with filters
const query = new SummaryQueryBuilder(42n) // Agent ID
  .reviewer('0x...') // Filter by specific reviewer
  .tag1('quality')   // Filter by tag
  .build();

// Encode the query
const queryCalldata = reputationApi.encodeGetSummaryCalldata(query);

// Call the contract (read-only)
const result = await publicClient.call({
  to: reputationApi.getRegistryAddress(),
  data: queryCalldata,
});

// Parse the summary
const summary = reputationApi.parseSummaryFromContractData({
  feedbackCount: 42n,
  aggregateValue: 3500n,
  decimals: 2,
}, query);

// Calculate normalized score
const score = reputationApi.calculateReputationScore(summary);
console.log(`Agent 42 reputation: ${score.toFixed(2)}`); // e.g., "83.33"
```

### Reputation Filtering Best Practices

1. **Filter by trusted reviewers** - Only consider feedback from known, trusted addresses
2. **Require proof of payment** - Weight feedback with transaction proofs higher
3. **Time-decay** - Recent feedback should matter more
4. **Tag-specific** - Evaluate reputation per service/capability

```typescript
// Example: Filter by trusted protocol addresses
const trustedReviewers = [
  '0x1111111254fb6c44bAC0beD2854e76F90643097d', // 1inch
  '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45', // Uniswap
];

const trustedQuery = new SummaryQueryBuilder(agentId)
  .reviewers(trustedReviewers)
  .tag1('execution')
  .build();
```

---

## Validation Workflow

### Trust Models

ERC-8004 supports multiple validation methods:

| Trust Model      | Description                  | Use Case             |
|------------------|------------------------------|----------------------|
| `Reputation`     | Community feedback signals   | General trust        |
| `CryptoEconomic` | Stake-based security         | High-value operations|
| `TeeAttestation` | TEE hardware attestation     | Code integrity       |
| `ZkMl`           | Zero-knowledge ML proofs     | Model verification   |

### Requesting Validation

```typescript
import {
  ValidationAPI,
  ValidationRequestBuilder,
} from '@mpc-wallet/sdk';

const validationApi = new ValidationAPI();

// Build validation request
const request = new ValidationRequestBuilder()
  .forAgent(42n)
  .withValidator('0x...') // Trusted validator address
  .withRequestURI('ipfs://Qm...') // Attestation request details
  .withContentFromString('attestation-data')
  .build();

// Encode and submit
const calldata = validationApi.encodeValidationRequestCalldata(request);
await walletClient.sendTransaction({
  to: validationApi.getRegistryAddress(),
  data: calldata,
});
```

### TEE Validation

For agents running in Trusted Execution Environments:

```typescript
const teeRequest = validationApi.createTeeValidationRequest(
  '0x...', // TEE validator
  42n,     // Agent ID
  {
    quote: '0x...', // SGX/TDX quote
    reportData: '0x...',
    mrEnclave: '0x...',
    mrSigner: '0x...',
    timestamp: BigInt(Date.now()),
  }
);

const teeCalldata = validationApi.encodeValidationRequestCalldata(teeRequest);
```

### Checking Validation Status

```typescript
// Get validation status
const statusCalldata = validationApi.encodeGetValidationStatusCalldata(requestHash);

const statusResult = await publicClient.call({
  to: validationApi.getRegistryAddress(),
  data: statusCalldata,
});

// Parse and check
const request = validationApi.parseValidationRequestFromContractData(statusResult);
const status = validationApi.getValidationStatus(request);

if (status.isApproved) {
  console.log('Agent validated!');
} else if (status.isPending) {
  console.log('Waiting for validator response...');
} else if (status.isExpired) {
  console.log('Validation request expired');
}
```

---

## Agent-to-Agent Transactions

### Discovery Flow

Two agents can discover each other through the Identity Registry.

```typescript
async function discoverAgent(agentId: bigint): Promise<AgentRegistrationFile> {
  // 1. Get agent URI from registry
  const uriResult = await publicClient.readContract({
    address: identityApi.getRegistryAddress(),
    abi: identityApi.getAbi(),
    functionName: 'agentURI',
    args: [agentId],
  });

  // 2. Resolve the registration file
  const registrationFile = await identityApi.resolveAgentURI(uriResult);

  // 3. Get linked wallet
  const walletResult = await publicClient.readContract({
    address: identityApi.getRegistryAddress(),
    abi: identityApi.getAbi(),
    functionName: 'getAgentWallet',
    args: [agentId],
  });

  return {
    ...registrationFile,
    walletAddress: walletResult,
  };
}
```

### Cross-Agent Transaction with Reputation

```typescript
async function transactWithAgent(targetAgentId: bigint, amount: bigint) {
  // 1. Discover target agent
  const targetAgent = await discoverAgent(targetAgentId);

  // 2. Check reputation before transacting
  const reputation = await getAgentReputation(targetAgentId);
  if (reputation.score < 0.7) {
    throw new Error('Agent reputation too low');
  }

  // 3. Execute transaction
  const txHash = await wallet.sendTransaction({
    to: targetAgent.walletAddress,
    value: amount,
  });

  // 4. Submit feedback after successful transaction
  const feedback = new FeedbackBuilder(targetAgentId)
    .positive(100n, 2)
    .tags('reliability', 'speed')
    .proofOfPaymentFromHex(txHash)
    .build();

  await submitFeedback(feedback);

  return txHash;
}
```

---

## ElizaOS Integration

The MPC Wallet ElizaOS plugin includes ERC-8004 actions.

### Available Actions

| Action                  | Description                             |
|-------------------------|-----------------------------------------|
| `REGISTER_AGENT`        | Register the agent in Identity Registry |
| `UPDATE_AGENT_PROFILE`  | Update agent URI                        |
| `GET_AGENT_IDENTITY`    | Look up agent details                   |
| `CHECK_REPUTATION`      | Query agent reputation                  |
| `GIVE_FEEDBACK`         | Submit feedback for an agent            |
| `REQUEST_VALIDATION`    | Request validator attestation           |

### Configuration

```typescript
// elizaos.config.ts
import { MpcWalletPlugin } from '@mpc-wallet/elizaos-plugin';

export default {
  plugins: [
    new MpcWalletPlugin({
      // ... wallet config ...

      // ERC-8004 settings
      agentIdentity: {
        autoRegister: true, // Register on startup if not registered
        agentURI: process.env.AGENT_REGISTRATION_URI,
      },
    }),
  ],
};
```

### Natural Language Examples

```text
User: "Register my agent as a trading assistant"
Agent: [Creates registration file, uploads to IPFS, registers on-chain]

User: "Check the reputation of agent 42"
Agent: [Queries Reputation Registry, returns score and feedback count]

User: "Give positive feedback to agent 42 for the swap transaction"
Agent: [Submits feedback with proof of payment]
```

---

## Best Practices

### Security

1. **Verify agent identities** before transacting
2. **Check reputation** from trusted reviewers
3. **Require validation** for high-value operations
4. **Use proof of payment** for feedback authenticity

### Gas Optimization

1. **Batch operations** when possible
2. **Cache registration files** locally after fetching
3. **Use events** instead of polling for status changes

### IPFS Pinning

1. **Use Filecoin pinning** for permanent storage
2. **Mirror to multiple gateways** for availability
3. **Include content hash** for integrity verification

### Privacy Considerations

1. Agent wallet addresses are **public** on-chain
2. Consider **privacy pools** for sensitive operations
3. Use **separate wallets** for different agent personas

---

## Related Documentation

- [Architecture Guide](./architecture.md) - System design overview
- [Integration Guide](./integration-guide.md) - AI framework integrations
- [Security Model](./security-model.md) - Threat model and protections
- [Agent-to-Agent Example](../examples/agent-to-agent/) - Full working example
