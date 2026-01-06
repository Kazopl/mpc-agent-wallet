# Basic Wallet Example

A simple example showing basic MPC Agent Wallet SDK operations.

## Features

- Create a new MPC wallet
- Generate key shares (simulated 3-party DKG)
- Configure spending policies
- Sign transactions with 2-of-3 threshold
- Store and load encrypted key shares

## Installation

```bash
npm install
```

## Running the Example

```bash
# Run the basic example
npm start

# Run with verbose logging
DEBUG=mpc-wallet:* npm start
```

## Code Walkthrough

### 1. Create Wallet with Policy

```typescript
const wallet = await MpcAgentWallet.create({
  role: PartyRole.Agent,
  policy: new PolicyConfig()
    .withSpendingLimits(ChainType.Evm, {
      perTransaction: parseEther('1'),
      daily: parseEther('10'),
    })
    .withWhitelist(['0x742d35Cc6634C0532925a3b844Bc9e7595f12345']),
});
```

### 2. Generate Key Shares

In production, this happens across 3 separate parties. Here we simulate it:

```typescript
// Simulate 3-party key generation
const keyShares = await simulateKeyGeneration();
wallet.setKeyShare(keyShares.agent);
```

### 3. Sign a Transaction

```typescript
const tx = {
  requestId: crypto.randomUUID(),
  chain: ChainType.Evm,
  to: '0x742d35Cc6634C0532925a3b844Bc9e7595f12345',
  value: parseEther('0.5').toString(),
  chainId: 1,
  timestamp: Date.now(),
};

// Check policy first
const policyResult = wallet.evaluatePolicy(tx);
if (!policyResult.approved) {
  console.log('Transaction rejected:', policyResult.reason);
  return;
}

// Sign with MPC
const signature = await signTransaction(wallet, tx);
console.log('Signature:', signature);
```

## Project Structure

```
basic-wallet/
├── src/
│   ├── index.ts          # Main entry point
│   ├── keygen.ts         # Key generation helpers
│   └── signing.ts        # Signing helpers
├── package.json
└── tsconfig.json
```

## Next Steps

- See [ElizaOS Plugin](../elizaos-plugin/) for AI agent integration
- See [LangChain Tool](../langchain-tool/) for LLM integration
- See [Telegram Bot](../telegram-bot/) for approval via chat
