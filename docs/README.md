# MPC Agent Wallet SDK - Quick Start Guide

This guide covers everything you need to build secure AI-controlled wallets using threshold MPC cryptography.

## What is MPC Agent Wallet?

MPC Agent Wallet is a **2-of-3 threshold Multi-Party Computation (MPC) wallet SDK** built for AI agents. It lets AI applications manage cryptocurrency wallets while keeping humans in control.

### Key Benefits

- **AI agents can't act alone** - Needs approval from user or recovery guardian
- **Policy enforcement** - Spending limits, whitelists and time restrictions
- **Multi-chain support** - Works with EVM, Solana and Bitcoin
- **Developer-friendly** - TypeScript, Python and Rust SDKs

## Installation

### TypeScript/JavaScript

```bash
npm install @mpc-wallet/sdk
# or
yarn add @mpc-wallet/sdk
# or
pnpm add @mpc-wallet/sdk
```

### Python

```bash
pip install mpc-wallet
# or
poetry add mpc-wallet
```

### Rust

```toml
[dependencies]
mpc-wallet-core = "0.1"
```

## Quick Start (TypeScript)

### 1. Create a Wallet

```typescript
import { MpcAgentWallet, PartyRole, PolicyConfig, ChainType } from '@mpc-wallet/sdk';

// Create a wallet for an AI agent with spending policy
const wallet = await MpcAgentWallet.create({
  role: PartyRole.Agent,
  policy: new PolicyConfig()
    .withSpendingLimits(ChainType.Evm, {
      perTransaction: BigInt('1000000000000000000'), // 1 ETH
      daily: BigInt('10000000000000000000'),         // 10 ETH
    })
    .withWhitelist(['0xUniswap...', '0xAave...']),
});
```

### 2. Generate Key Shares (DKG)

Key generation requires all 3 parties (Agent, User, Recovery) to participate:

```typescript
// Each party creates a keygen session
const session = wallet.createKeygenSession({
  role: PartyRole.Agent,
  sessionId: generateSessionId(),
  threshold: 2,
  parties: 3,
});

// Round 1: Generate and broadcast commitments
const round1Msg = session.generateRound1();
// ... send to relay, receive from other parties ...
session.processRound1(otherMessages);

// Round 2: Exchange key shares
const round2Msg = session.generateRound2();
// ... send to relay, receive from other parties ...
session.processRound2(otherMessages);

// Round 3: Verify and finalize
const round3Msg = session.generateRound3();
// ... send to relay, receive from other parties ...
const keyShare = session.finalize(otherMessages);

// Store the key share securely
wallet.setKeyShare(keyShare);
await wallet.saveKeyShare('my-wallet', 'secure-password');
```

### 3. Sign a Transaction

Signing requires 2 of the 3 parties:

```typescript
// Create a transaction request
const tx = {
  requestId: crypto.randomUUID(),
  chain: ChainType.Evm,
  to: '0x742d35Cc6634C0532925a3b844Bc9e7595f...',
  value: '500000000000000000', // 0.5 ETH
  chainId: 1,
  timestamp: Date.now(),
};

// Check policy before signing
const policyCheck = wallet.evaluatePolicy(tx);
if (!policyCheck.approved) {
  console.error('Policy rejected:', policyCheck.reason);
  return;
}

// Create signing session
const messageHash = wallet.hashTransaction(tx);
const signingSession = wallet.createSigningSession(
  {
    sessionId: generateSessionId(),
    parties: [PartyRole.Agent, PartyRole.User], // 2-of-3
    threshold: 2,
  },
  messageHash
);

// Execute MPC signing protocol
const round1 = signingSession.generateRound1();
// ... exchange messages via relay ...
const signature = signingSession.finalize(otherSignatures);

console.log('Signature:', signature);
```

## Quick Start (Python)

```python
from mpc_wallet import MpcAgentWallet, PartyRole, PolicyConfig, ChainType

# Create wallet with policy
wallet = MpcAgentWallet(WalletConfig(
    role=PartyRole.AGENT,
    policy=PolicyConfig()
        .with_spending_limits(ChainType.EVM, per_tx=10**18, daily=10**19)
        .with_whitelist(["0xUniswap...", "0xAave..."]),
))

# Generate keys, sign transactions...
address = wallet.get_address()
print(f"Wallet address: {address}")
```

## Architecture Overview

```
+------------------------------------------------------------+
|                          AI Agent                          |
|  +------------------------------------------------------+  |
|  |  MPC Agent Wallet SDK                                |  |
|  |  - Key share (1 of 3)                                |  |
|  |  - Policy engine                                     |  |
|  |  - Transaction builder                               |  |
|  +------------------+-----------------------------------+  |
+---------------------+--------------------------------------+
                      |
                      v
+------------------------------------------------------------+
|                      Message Relay                         |
|  - Session management                                      |
|  - Approval flow                                           |
|  - Webhook notifications                                   |
+---------------------+--------------------------------------+
                      |
          +-----------+-----------+
          v                       v
  +---------------+       +---------------+
  | User Device   |       | Recovery      |
  | (Key share 2) |       | Guardian      |
  |               |       | (Key share 3) |
  +---------------+       +---------------+
```

## Security Model

| Party | Role | Key Share |
|-------|------|-----------|
| **Agent** | AI assistant initiating transactions | Share 1 |
| **User** | Account owner with approval authority | Share 2 |
| **Recovery** | Backup guardian for recovery | Share 3 |

**Threshold: 2-of-3** - Any two parties must cooperate to sign a transaction.

## Next Steps

- [Architecture Guide](./architecture.md) - Learn how the system works
- [Security Model](./security-model.md) - Threat model and protections
- [Integration Guide](./integration-guide.md) - Connect with AI frameworks
- [TypeScript API Reference](./api-reference/typescript.md)
- [Python API Reference](./api-reference/python.md)

## Examples

| Example | Description |
|---------|-------------|
| [Basic Wallet](../examples/basic-wallet/) | Minimal wallet setup and signing |
| [ElizaOS Plugin](../examples/elizaos-plugin/) | Integration with ElizaOS framework |
| [LangChain Tool](../examples/langchain-tool/) | LangChain tool for blockchain operations |
| [Telegram Bot](../examples/telegram-bot/) | Approval via Telegram |
| [DeFi Agent](../examples/defi-agent/) | Automated DeFi operations |

## Support

- [GitHub Issues](https://github.com/Kazopl/mpc-agent-wallet/issues)

---

Built for AI agents that need secure blockchain access with human oversight.
