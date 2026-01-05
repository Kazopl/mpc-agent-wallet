# Integration Guide

Learn how to connect the MPC Agent Wallet SDK with popular AI frameworks.

## Table of Contents

- [ElizaOS Integration](#elizaos-integration)
- [LangChain Integration](#langchain-integration)
- [AutoGPT Integration](#autogpt-integration)
- [Custom AI Frameworks](#custom-ai-frameworks)
- [Approval Flow Patterns](#approval-flow-patterns)
- [Best Practices](#best-practices)

---

## ElizaOS Integration

[ElizaOS](https://elizaos.ai) is a popular framework for building AI agents. The MPC Wallet works as a plugin.

### Installation

```bash
npm install @mpc-wallet/sdk @mpc-wallet/elizaos-plugin
```

### Plugin Setup

```typescript
// elizaos.config.ts
import { MpcWalletPlugin } from '@mpc-wallet/elizaos-plugin';

export default {
  plugins: [
    new MpcWalletPlugin({
      // Wallet configuration
      policy: {
        spendingLimits: {
          evm: {
            perTransaction: '1000000000000000000',  // 1 ETH
            daily: '10000000000000000000',          // 10 ETH
          }
        },
        whitelist: [
          '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45', // Uniswap
          '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D', // Uniswap V2
        ],
      },
      // Relay configuration
      relay: {
        url: 'wss://relay.mpc-wallet.example.com',
        timeout: 60000,
      },
      // Storage configuration
      storage: {
        type: 'file',
        path: './keys',
        password: process.env.WALLET_PASSWORD,
      },
    }),
  ],
};
```

### Available Actions

The plugin exposes these actions to the AI agent:

```typescript
// Check wallet balance
await agent.action('wallet:getBalance', { chain: 'evm', chainId: 1 });

// Get wallet address
await agent.action('wallet:getAddress', { chain: 'evm' });

// Send transaction (requires user approval)
await agent.action('wallet:sendTransaction', {
  chain: 'evm',
  chainId: 1,
  to: '0x...',
  value: '0.1',  // 0.1 ETH
});

// Swap tokens via Uniswap
await agent.action('wallet:swap', {
  chain: 'evm',
  chainId: 1,
  tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',  // WETH
  tokenOut: '0x6B175474E89094C44Da98b954EesdedeafCBB7dC', // DAI
  amountIn: '1000000000000000000',  // 1 WETH
  slippage: 0.5,  // 0.5%
});

// Check policy limits
await agent.action('wallet:checkPolicy', {
  chain: 'evm',
  to: '0x...',
  value: '5000000000000000000',  // 5 ETH
});
```

### Character Configuration

```json
{
  "name": "DeFi Assistant",
  "description": "An AI assistant for DeFi operations",
  "plugins": ["@mpc-wallet/elizaos-plugin"],
  "settings": {
    "wallet": {
      "confirmationRequired": true,
      "maxPendingTransactions": 3,
      "defaultChain": "ethereum"
    }
  }
}
```

---

## LangChain Integration

[LangChain](https://langchain.com) is a framework for developing LLM-powered applications.

### Installation

```bash
pip install mpc-wallet langchain
```

### Tool Definition

```python
from langchain.tools import BaseTool
from mpc_wallet import MpcAgentWallet, PolicyConfig, ChainType
from pydantic import BaseModel, Field

class SendTransactionInput(BaseModel):
    to: str = Field(description="Recipient address (0x...)")
    value: str = Field(description="Amount to send in ETH (e.g., '0.1')")
    chain_id: int = Field(default=1, description="Chain ID (1=Ethereum, 137=Polygon)")

class MpcWalletSendTool(BaseTool):
    name = "mpc_wallet_send"
    description = """
    Send cryptocurrency from the MPC wallet. Requires user approval.
    Use this when the user wants to transfer ETH or tokens.
    Always confirm the amount and recipient before calling.
    """
    args_schema = SendTransactionInput

    def __init__(self, wallet: MpcAgentWallet, relay_url: str):
        super().__init__()
        self.wallet = wallet
        self.relay_url = relay_url

    def _run(self, to: str, value: str, chain_id: int = 1) -> str:
        from mpc_wallet import TransactionRequest
        import uuid

        # Create transaction request
        tx = TransactionRequest(
            request_id=str(uuid.uuid4()),
            chain=ChainType.EVM,
            to=to,
            value=str(int(float(value) * 10**18)),  # Convert to wei
            chain_id=chain_id,
        )

        # Check policy
        policy_result = self.wallet.evaluate_policy(tx)
        if not policy_result.approved:
            return f"Transaction rejected by policy: {policy_result.reason}"

        # Request approval and sign
        # (In production, this would coordinate with relay)
        return f"Transaction submitted for approval. To: {to}, Value: {value} ETH"

    async def _arun(self, to: str, value: str, chain_id: int = 1) -> str:
        return self._run(to, value, chain_id)

class MpcWalletBalanceTool(BaseTool):
    name = "mpc_wallet_balance"
    description = "Check the balance of the MPC wallet on a specific chain."

    def __init__(self, wallet: MpcAgentWallet):
        super().__init__()
        self.wallet = wallet

    def _run(self, chain: str = "ethereum") -> str:
        address = self.wallet.get_address()
        # In production, query RPC for balance
        return f"Wallet address: {address}"
```

### Agent Setup

```python
from langchain.agents import initialize_agent, AgentType
from langchain_openai import ChatOpenAI
from mpc_wallet import MpcAgentWallet, WalletConfig, PolicyConfig, PartyRole

# Initialize wallet
wallet = MpcAgentWallet(WalletConfig(
    role=PartyRole.AGENT,
    policy=PolicyConfig()
        .with_spending_limits(ChainType.EVM, per_tx=10**18, daily=10**19)
        .with_whitelist(["0x..."]),
))

# Load existing key share
await wallet.load_key_share("my-wallet", password="...")

# Create tools
tools = [
    MpcWalletSendTool(wallet, relay_url="wss://relay.example.com"),
    MpcWalletBalanceTool(wallet),
]

# Initialize agent
llm = ChatOpenAI(model="gpt-4", temperature=0)
agent = initialize_agent(
    tools,
    llm,
    agent=AgentType.OPENAI_FUNCTIONS,
    verbose=True,
)

# Run agent
response = agent.run("Send 0.1 ETH to 0x742d35Cc6634C0532925a3b844Bc...")
```

### Custom Memory with Transaction History

```python
from langchain.memory import ConversationBufferMemory

class WalletMemory(ConversationBufferMemory):
    def __init__(self, wallet: MpcAgentWallet):
        super().__init__()
        self.wallet = wallet
        self.transaction_history = []

    def add_transaction(self, tx_hash: str, details: dict):
        self.transaction_history.append({
            "hash": tx_hash,
            "details": details,
            "timestamp": datetime.now().isoformat(),
        })

    def get_recent_transactions(self, limit: int = 5) -> list:
        return self.transaction_history[-limit:]
```

---

## AutoGPT Integration

[AutoGPT](https://github.com/Significant-Gravitas/AutoGPT) is an autonomous AI agent framework.

### Plugin Structure

```
autogpt-mpc-wallet/
├── __init__.py
├── wallet_plugin.py
└── commands.py
```

### Plugin Implementation

```python
# wallet_plugin.py
from autogpt.plugins import AutoGPTPluginTemplate

class MpcWalletPlugin(AutoGPTPluginTemplate):
    def __init__(self):
        super().__init__()
        self._name = "MPC Wallet Plugin"
        self._version = "0.1.0"
        self._description = "Secure MPC wallet for AutoGPT"

        # Initialize wallet
        from mpc_wallet import MpcAgentWallet, WalletConfig
        self.wallet = MpcAgentWallet(WalletConfig())

    def can_handle_on_response(self) -> bool:
        return True

    def on_response(self, response: str, *args, **kwargs) -> str:
        # Parse response for wallet commands
        if "WALLET_SEND" in response:
            return self._handle_send(response)
        return response

    def _handle_send(self, response: str) -> str:
        # Parse and execute send command
        pass
```

### Commands

```python
# commands.py
from autogpt.commands import command

@command(
    "wallet_balance",
    "Check the MPC wallet balance",
    {
        "chain": {"type": "string", "description": "Blockchain (ethereum, polygon, etc.)"}
    }
)
def wallet_balance(chain: str = "ethereum") -> str:
    """Check wallet balance on specified chain."""
    # Implementation
    pass

@command(
    "wallet_send",
    "Send cryptocurrency (requires approval)",
    {
        "to": {"type": "string", "description": "Recipient address"},
        "amount": {"type": "string", "description": "Amount in ETH"},
        "chain": {"type": "string", "description": "Blockchain"}
    }
)
def wallet_send(to: str, amount: str, chain: str = "ethereum") -> str:
    """Send cryptocurrency from MPC wallet."""
    # Implementation
    pass
```

---

## Custom AI Frameworks

For custom AI frameworks, you can use the SDK directly.

### TypeScript Example

```typescript
import { MpcAgentWallet, PartyRole, PolicyConfig, ChainType } from '@mpc-wallet/sdk';
import { RelayClient } from '@mpc-wallet/sdk/relay';

class AIWalletManager {
  private wallet: MpcAgentWallet;
  private relay: RelayClient;

  async initialize(config: {
    keySharePath: string;
    password: string;
    relayUrl: string;
    policy: PolicyConfig;
  }) {
    // Create wallet
    this.wallet = await MpcAgentWallet.create({
      role: PartyRole.Agent,
      policy: config.policy,
    });

    // Load key share
    await this.wallet.loadKeyShare(config.keySharePath, config.password);

    // Connect to relay
    this.relay = new RelayClient(config.relayUrl);
    await this.relay.connect();
  }

  async sendTransaction(params: {
    to: string;
    value: string;
    chainId?: number;
  }): Promise<{ status: string; txHash?: string; error?: string }> {
    // Build transaction request
    const tx = {
      requestId: crypto.randomUUID(),
      chain: ChainType.Evm,
      to: params.to,
      value: params.value,
      chainId: params.chainId ?? 1,
      timestamp: Date.now(),
    };

    // Check policy
    const policyResult = this.wallet.evaluatePolicy(tx);
    if (!policyResult.approved) {
      return {
        status: 'rejected',
        error: `Policy violation: ${policyResult.reason}`,
      };
    }

    // Request approval
    const approvalRequest = await this.relay.requestApproval(tx);

    // Wait for approval (or timeout)
    const approval = await this.relay.waitForApproval(
      approvalRequest.sessionId,
      { timeout: 300000 } // 5 minutes
    );

    if (approval.status !== 'approved') {
      return {
        status: 'rejected',
        error: approval.reason ?? 'User rejected transaction',
      };
    }

    // Execute MPC signing
    const signature = await this.executeSigningProtocol(tx, approval.sessionId);

    // Broadcast transaction
    const txHash = await this.broadcastTransaction(tx, signature);

    return { status: 'success', txHash };
  }

  private async executeSigningProtocol(tx: any, sessionId: string) {
    // MPC signing protocol implementation
    // ...
  }

  private async broadcastTransaction(tx: any, signature: any) {
    // Broadcast to blockchain
    // ...
  }
}
```

### Python Example

```python
from mpc_wallet import MpcAgentWallet, PolicyConfig, ChainType
from mpc_wallet.relay import RelayClient
import asyncio

class AIWalletManager:
    def __init__(self):
        self.wallet = None
        self.relay = None

    async def initialize(self, config: dict):
        # Create wallet with policy
        self.wallet = MpcAgentWallet(WalletConfig(
            role=PartyRole.AGENT,
            policy=PolicyConfig()
                .with_spending_limits(ChainType.EVM, **config["limits"])
                .with_whitelist(config.get("whitelist", [])),
        ))

        # Load key share
        await self.wallet.load_key_share(
            config["key_share_path"],
            config["password"]
        )

        # Connect to relay
        self.relay = RelayClient(config["relay_url"])
        await self.relay.connect()

    async def send_transaction(self, to: str, value: str, chain_id: int = 1) -> dict:
        # Implementation similar to TypeScript
        pass
```

---

## Approval Flow Patterns

### Pattern 1: Push Notification

User receives push notification and approves in mobile app.

```typescript
// Agent side
const approval = await relay.requestApproval(tx, {
  notificationChannel: 'push',
  userDeviceId: 'user-device-123',
  timeout: 300000,
});

// User mobile app
relay.onApprovalRequest((request) => {
  showApprovalUI(request);
});

const userDecision = await getUserDecision();
await relay.submitApproval(request.sessionId, userDecision);
```

### Pattern 2: Polling

User app polls for pending approvals.

```typescript
// User app polls for requests
setInterval(async () => {
  const pending = await relay.getPendingApprovals(userId);
  for (const request of pending) {
    await processApprovalRequest(request);
  }
}, 5000);
```

### Pattern 3: QR Code

AI displays QR code, user scans to approve.

```typescript
// Agent side
const qrData = await relay.createQRApproval(tx);
displayQRCode(qrData.qrCodeUrl);

// User scans QR and is directed to approval page
// Approval page shows tx details and approve/reject buttons
```

### Pattern 4: Telegram/Discord Bot

User approves via chat bot command.

```typescript
// Telegram bot handler
bot.on('callback_query', async (ctx) => {
  const [action, sessionId] = ctx.callbackQuery.data.split(':');

  if (action === 'approve') {
    await relay.submitApproval(sessionId, { approved: true });
    await ctx.reply('Transaction approved!');
  } else {
    await relay.submitApproval(sessionId, { approved: false });
    await ctx.reply('Transaction rejected');
  }
});
```

---

## Best Practices

### 1. Policy Configuration

```typescript
// Good: Restrictive default policy
const policy = new PolicyConfig()
  .withSpendingLimits(ChainType.Evm, {
    perTransaction: parseEther('1'),      // Max 1 ETH per tx
    daily: parseEther('10'),              // Max 10 ETH daily
    weekly: parseEther('50'),             // Max 50 ETH weekly
  })
  .withWhitelist([
    // Only allow known, audited protocols
    UNISWAP_ROUTER,
    AAVE_POOL,
  ])
  .withBlacklist([
    // Block known malicious addresses
    TORNADO_CASH,
  ])
  .withTimeBounds({
    // Only during business hours
    startHour: 9,
    endHour: 17,
    timezone: 'America/New_York',
  })
  .withAdditionalApprovalThreshold(parseEther('5')); // >5 ETH needs recovery
```

### 2. Error Handling

```typescript
try {
  const result = await wallet.sendTransaction(tx);
} catch (error) {
  if (error instanceof PolicyViolationError) {
    // Handle policy rejection gracefully
    console.log(`Transaction blocked: ${error.reason}`);
    // Inform user why transaction was blocked
  } else if (error instanceof ApprovalTimeoutError) {
    // Handle approval timeout
    console.log('User did not respond in time');
  } else if (error instanceof SigningError) {
    // Handle MPC protocol errors
    console.error('Signing failed:', error);
  }
}
```

### 3. Logging and Monitoring

```typescript
// Set up logging
wallet.on('policyEvaluated', (tx, decision) => {
  logger.info('Policy evaluated', {
    txId: tx.requestId,
    approved: decision.approved,
    reason: decision.reason,
  });
});

wallet.on('approvalRequested', (request) => {
  logger.info('Approval requested', {
    sessionId: request.sessionId,
    value: request.tx.value,
  });
});

wallet.on('transactionSigned', (tx, signature) => {
  logger.info('Transaction signed', {
    txId: tx.requestId,
    signature: signature.r.slice(0, 10) + '...',
  });
});
```

### 4. Secure Key Share Storage

```typescript
// Use strong passwords
const password = await generateSecurePassword(32);

// Consider hardware security
const storage = new HardwareSecurityStore({
  provider: 'yubikey',
});

// Implement key rotation
await wallet.refreshKeyShares();
```

### 5. User Experience

```typescript
// Show clear transaction details
const approvalMessage = `
Transaction Approval Required

To: ${formatAddress(tx.to)}
Value: ${formatEther(tx.value)} ETH
Network: ${getNetworkName(tx.chainId)}

Estimated Gas: ${formatGwei(tx.gasLimit)} Gwei
`;

// Provide context for the transaction
const context = await getTransactionContext(tx);
if (context.isKnownProtocol) {
  approvalMessage += `\nProtocol: ${context.protocolName}`;
  approvalMessage += `\nAction: ${context.actionDescription}`;
}
```

---

## Next Steps

- [Basic Wallet Example](../examples/basic-wallet/) - Start here
- [ElizaOS Plugin Example](../examples/elizaos-plugin/) - Full ElizaOS setup
- [LangChain Tool Example](../examples/langchain-tool/) - LangChain setup
- [Telegram Bot Example](../examples/telegram-bot/) - Telegram approvals
