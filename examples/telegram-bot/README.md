# Telegram Bot Example

Shows how to build a Telegram bot for transaction approvals. Users can approve MPC wallet transactions directly in chat.

## Features

- Telegram bot for transaction approval
- Interactive inline buttons for approve/reject
- Real-time notification when AI agent requests approval
- Transaction details with value, recipient, gas estimates
- Secure approval flow with signed confirmations

## Installation

```bash
npm install
```

## Dependencies

| Package | Version | Description |
|---------|---------|-------------|
| `grammy` | ^1.39.2 | Telegram bot framework |
| `@mpc-wallet/sdk` | ^0.1.0 | MPC wallet SDK |
| `viem` | ^2.44.0 | Ethereum interactions |
| `ws` | ^8.18.0 | WebSocket client |

## Configuration

### 1. Create Telegram Bot

1. Message [@BotFather](https://t.me/BotFather) on Telegram
2. Send `/newbot` and follow the prompts
3. Copy the bot token

### 2. Create `.env` File

```env
# Telegram Bot
TELEGRAM_BOT_TOKEN=your-bot-token-from-botfather

# Relay Service
RELAY_URL=wss://relay.mpc-wallet.example.com

# Wallet (for signing approvals)
WALLET_KEY_PATH=./keys/user-share.json
WALLET_PASSWORD=your-secure-password

# Optional: Allowed user IDs (comma-separated)
ALLOWED_USER_IDS=123456789,987654321
```

## Usage

### Start the Bot

```bash
npm start
```

### Bot Commands

| Command | Description |
|---------|-------------|
| `/start` | Initialize bot and link wallet |
| `/status` | Check pending approval requests |
| `/history` | View recent transactions |
| `/settings` | Configure notification preferences |
| `/help` | Show available commands |

### Approval Flow

```
1. AI Agent requests transaction
   --> Relay notifies Telegram bot

2. Bot sends approval request
   +---------------------------------------+
   | Transaction Approval Request          |
   |                                       |
   | From: AI Trading Bot                  |
   | To: 0x742d...f12345                   |
   | Amount: 0.5 ETH (~$1,000)             |
   | Chain: Ethereum                       |
   | Gas: ~0.002 ETH                       |
   |                                       |
   | [Approve] [Reject]                    |
   +---------------------------------------+

3. User taps Approve/Reject
   --> Bot sends signed response to relay

4. Transaction executes (if approved)
   --> Bot notifies user of result
```

## Project Structure

```
telegram-bot/
├── src/
│   ├── index.ts          # Entry point
│   ├── bot.ts            # Telegram bot setup
│   ├── handlers/
│   │   ├── commands.ts   # Command handlers
│   │   ├── callbacks.ts  # Button callback handlers
│   │   └── approval.ts   # Approval flow logic
│   ├── relay/
│   │   └── client.ts     # Relay service client
│   └── utils/
│       ├── format.ts     # Message formatting
│       └── crypto.ts     # Signing utilities
├── package.json
└── tsconfig.json
```

## Security Considerations

1. **User Verification**: Only respond to configured user IDs
2. **Signed Approvals**: Approvals are cryptographically signed
3. **Rate Limiting**: Prevent approval spam
4. **Timeout**: Approvals expire after 5 minutes

## Extending the Bot

### Custom Notification Template

```typescript
const template = `
*New Transaction Request*

*From:* ${request.agent}
*To:* \`${request.to}\`
*Amount:* ${formatEther(request.value)} ETH
*Chain:* ${request.chain}

_Gas estimate: ~${formatGwei(request.gas)} Gwei_
`;
```

### Add Custom Commands

```typescript
bot.command('balance', async (ctx) => {
  const balance = await getWalletBalance();
  await ctx.reply(`Balance: ${balance} ETH`);
});
```

## Next Steps

- See [DeFi Agent](../defi-agent/) for automated DeFi operations
- See [ElizaOS Plugin](../elizaos-plugin/) for AI agent integration
