# ERC-7715 AI Agent Example

This example demonstrates an AI agent using ERC-7715 wallet execution permissions to autonomously execute transactions on behalf of users with fine-grained constraints.

## Overview

ERC-7715 defines a standard JSON-RPC interface for dapps and AI agents to request fine-grained permissions from wallets to execute transactions on the user's behalf. This example shows how to:

1. Request permissions with spending limits, rate limits, and whitelisted contracts
2. Execute transactions using granted permissions
3. Monitor and manage permission lifecycle
4. Handle permission expiry and revocation

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AI Trading Agent                             │
├─────────────────────────────────────────────────────────────────────┤
│  - Market analysis and strategy execution                           │
│  - Requests ERC-7715 permissions from user wallet                   │
│  - Executes trades within granted permission bounds                 │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      ERC-7715 Provider                              │
├─────────────────────────────────────────────────────────────────────┤
│  - wallet_requestExecutionPermissions                               │
│  - wallet_revokeExecutionPermission                                 │
│  - wallet_getSupportedExecutionPermissions                          │
│  - wallet_getGrantedExecutionPermissions                            │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    MPC Smart Account                                │
├─────────────────────────────────────────────────────────────────────┤
│  - Session key validation                                           │
│  - Spending limit enforcement                                       │
│  - Whitelist/selector restrictions                                  │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Install dependencies
npm install

# Run the demo
npm run demo

# Or run the full agent
npm start
```

## Configuration

Create a `.env` file with:

```env
# Wallet Configuration
WALLET_ADDRESS=0x...

# Chain Configuration
RPC_URL=https://base-sepolia.g.alchemy.com/v2/YOUR_KEY
CHAIN_ID=0x14a34

# Agent Configuration
AGENT_ADDRESS=0x...
MAX_SPENDING_LIMIT=1000000000000000000  # 1 ETH in wei
```

## Usage Example

```typescript
import { ERC7715Agent } from './agent';

// Create agent
const agent = new ERC7715Agent({
  walletAddress: '0x...',
  agentAddress: '0x...',
  chainId: '0x14a34', // Base Sepolia
});

// Request trading permissions
const permission = await agent.requestTradingPermission({
  spendingLimit: '0.5',  // 0.5 ETH
  duration: 24 * 3600,   // 24 hours
  allowedProtocols: ['uniswap'],
});

// Execute a swap
const txHash = await agent.executeSwap({
  tokenIn: '0x...',
  tokenOut: '0x...',
  amountIn: '0.1',
  minAmountOut: '100',
});

// Monitor permissions
const status = await agent.getPermissionStatus();
console.log(`Remaining: ${status.remainingSpending} ETH`);
console.log(`Expires in: ${status.timeRemaining} seconds`);
```

## Permission Types

### Native Token Transfer

```typescript
// Allow agent to spend up to 1 ETH
{
  type: 'native-token-transfer',
  data: { allowance: '0xDE0B6B3A7640000' }, // 1 ETH
  required: true,
}
```

### ERC-20 Token Transfer

```typescript
// Allow agent to transfer up to 1000 USDC
{
  type: 'erc20-token-transfer',
  data: {
    address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // USDC
    allowance: '0x3B9ACA00', // 1000 USDC (6 decimals)
  },
  required: true,
}
```

### Contract Call

```typescript
// Allow agent to call Uniswap router
{
  type: 'contract-call',
  data: {
    address: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45', // SwapRouter02
    calls: [
      { selector: '0x5ae401dc' }, // multicall
      { selector: '0xac9650d8' }, // multicall (legacy)
    ],
  },
  required: true,
}
```

### Rate Limit

```typescript
// Limit to 10 transactions per hour
{
  type: 'rate-limit',
  data: { count: 10, interval: 3600 },
  required: false,
}
```

## Policies

### Spending Limit Policy

```typescript
// Global spending cap regardless of individual permissions
{
  type: 'spending-limit',
  data: { allowance: '0x1BC16D674EC80000', period: 86400 }, // 2 ETH per day
}
```

### Gas Limit Policy

```typescript
// Cap gas usage per transaction
{
  type: 'gas-limit',
  data: { limit: '0x7A120' }, // 500,000 gas
}
```

### Call Limit Policy

```typescript
// Maximum number of calls before permission expires
{
  type: 'call-limit',
  data: { count: 100 },
}
```

## Security Considerations

1. **Minimal Permissions**: Request only the permissions you need
2. **Short Duration**: Use the shortest practical expiry time
3. **Whitelist Contracts**: Always specify allowed target contracts
4. **Rate Limiting**: Implement rate limits to prevent runaway spending
5. **Monitoring**: Continuously monitor permission usage
6. **Revocation**: Implement automatic revocation on anomaly detection

## License

MIT
