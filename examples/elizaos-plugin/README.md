# ElizaOS Plugin Example

Shows how to add the MPC Agent Wallet as an ElizaOS plugin so AI agents can manage cryptocurrency wallets.

## Features

- Full ElizaOS plugin integration
- Check wallet balances
- Send transactions (with approval flow)
- Swap tokens via Uniswap
- View transaction history
- Policy enforcement

## Installation

```bash
npm install
```

## Dependencies

| Package | Version | Description |
|---------|---------|-------------|
| `@elizaos/core` | ^1.0.14 | ElizaOS framework core |
| `@mpc-wallet/sdk` | ^0.1.0 | MPC wallet SDK |
| `viem` | ^2.44.0 | Ethereum interactions |

## Configuration

Create a `.env` file:

```env
# Wallet configuration
WALLET_PASSWORD=your-secure-password
WALLET_KEY_PATH=./keys/agent-share.json

# Relay configuration
RELAY_URL=wss://relay.mpc-wallet.example.com

# Chain configuration
ETH_RPC_URL=https://eth.llamarpc.com
POLYGON_RPC_URL=https://polygon-rpc.com
```

## Usage

### 1. Add Plugin to ElizaOS

```typescript
// elizaos.config.ts
import { MpcWalletPlugin } from '@mpc-wallet/elizaos-plugin';

export default {
  plugins: [
    new MpcWalletPlugin({
      password: process.env.WALLET_PASSWORD!,
      keyPath: process.env.WALLET_KEY_PATH,
      relayUrl: process.env.RELAY_URL,
      policy: {
        spendingLimits: {
          perTransaction: '1000000000000000000', // 1 ETH
          daily: '10000000000000000000',         // 10 ETH
        },
        whitelist: [
          '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45', // Uniswap
        ],
      },
    }),
  ],
};
```

### 2. Available Actions

The plugin exposes these actions to the AI agent:

```typescript
// Get wallet address
await agent.action('wallet:address');
// -> "0x742d35Cc6634C0532925a3b844Bc9e7595f12345"

// Get balance
await agent.action('wallet:balance', { chain: 'ethereum' });
// -> { raw: "1500000000000000000", formatted: "1.5", symbol: "ETH" }

// Send ETH (requires user approval)
await agent.action('wallet:send', {
  to: '0x...',
  value: '0.5',
  chain: 'ethereum',
});
// -> { status: "pending_approval", requestId: "..." }

// Swap tokens
await agent.action('wallet:swap', {
  tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', // WETH
  tokenOut: '0x6B175474E89094C44Da98b954EesdedeafCBB7dC', // DAI
  amountIn: '1.0',
  slippage: 0.5,
});

// Check if transaction would be approved by policy
await agent.action('wallet:checkPolicy', {
  to: '0x...',
  value: '5.0',
});
// -> { approved: false, reason: "Exceeds per-transaction limit" }
```

### 3. Character Configuration

```json
{
  "name": "DeFi Assistant",
  "description": "An AI assistant that helps with DeFi operations",
  "plugins": ["@mpc-wallet/elizaos-plugin"],
  "settings": {
    "wallet": {
      "defaultChain": "ethereum",
      "confirmBeforeSend": true,
      "showGasEstimates": true
    }
  },
  "system": "You are a DeFi assistant with access to a secure MPC wallet. You can check balances, send transactions and swap tokens. Always confirm with the user before sending transactions."
}
```

## Conversation Examples

```
User: What's my wallet balance?
Agent: Let me check your wallet balance.
       Your current balance:
       - ETH: 1.5 ETH ($3,000)
       - USDC: 1,000 USDC

User: Send 0.5 ETH to vitalik.eth
Agent: I'll prepare a transaction to send 0.5 ETH to vitalik.eth.

       Transaction Details:
       - To: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
       - Amount: 0.5 ETH (~$1,000)
       - Gas: ~21,000 (0.001 ETH)

       This requires your approval. Please check your mobile app to approve.

       Waiting for approval...

User: [Approves in mobile app]

Agent: Transaction approved and signed!
       Transaction hash: 0x1234...
       View on Etherscan: https://etherscan.io/tx/0x1234...
```

## Project Structure

```
elizaos-plugin/
├── src/
│   ├── index.ts          # Plugin entry point
│   ├── plugin.ts         # MpcWalletPlugin class
│   ├── actions/          # Plugin actions
│   │   ├── balance.ts
│   │   ├── send.ts
│   │   ├── swap.ts
│   │   └── policy.ts
│   └── utils/
│       └── chains.ts
├── package.json
└── tsconfig.json
```

## Security Considerations

1. **Policy Enforcement**: All transactions are checked against configured policies
2. **Approval Required**: Transactions require user approval via mobile app
3. **Whitelist**: Only allow transactions to known, audited contracts
4. **Spending Limits**: Enforce daily/weekly spending limits

## Next Steps

- See [LangChain Tool](../langchain-tool/) for LangChain integration
- See [Telegram Bot](../telegram-bot/) for approval via Telegram
