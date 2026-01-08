# LangChain Tool Example

Shows how to use the MPC Agent Wallet as LangChain tools so LLM apps can handle cryptocurrency operations.

## Features

- LangChain tool implementations for wallet operations
- Works with any LLM (GPT-4, Claude, Llama, etc.)
- Policy enforcement before execution
- Transaction history tracking
- Async support

## Installation

```bash
pip install -r requirements.txt
```

## Requirements

| Package | Version | Description |
|---------|---------|-------------|
| `langchain` | >=1.2.3 | LangChain framework |
| `langchain-openai` | >=1.1.6 | OpenAI integration |
| `langchain-core` | >=0.3.60 | Core abstractions |
| `mpc-wallet` | >=0.1.0 | MPC wallet SDK |
| `pydantic` | >=2.10.0 | Data validation |

**Note:** Requires Python 3.10+

## Configuration

Create a `.env` file:

```env
# OpenAI API key
OPENAI_API_KEY=sk-...

# Wallet configuration
WALLET_PASSWORD=your-secure-password
WALLET_KEY_PATH=./keys/agent-share.json

# Relay configuration
RELAY_URL=wss://relay.mpc-wallet.example.com

# Chain RPCs
ETH_RPC_URL=https://eth.llamarpc.com
```

## Usage

### Basic Usage

```python
from langchain_openai import ChatOpenAI
from langchain.agents import initialize_agent, AgentType
from mpc_wallet_tools import (
    create_wallet_tools,
    MpcAgentWallet,
    WalletConfig,
    PolicyConfig,
)

# Initialize wallet
wallet = MpcAgentWallet(WalletConfig(
    role=PartyRole.AGENT,
    policy=PolicyConfig()
        .with_spending_limits(ChainType.EVM, per_tx=int(1e18), daily=int(10e18))
        .with_whitelist(["0x..."]),
))

# Create tools
tools = create_wallet_tools(wallet, relay_url="wss://...")

# Initialize agent
llm = ChatOpenAI(model="gpt-4", temperature=0)
agent = initialize_agent(
    tools,
    llm,
    agent=AgentType.OPENAI_FUNCTIONS,
    verbose=True,
)

# Run
response = agent.run("What's my wallet balance?")
print(response)
```

### Available Tools

#### `wallet_balance`
Check wallet balance on a blockchain.

```python
Input: {"chain": "ethereum"}
Output: "Your wallet balance on Ethereum is 1.5 ETH ($3,000)"
```

#### `wallet_send`
Send cryptocurrency (requires approval).

```python
Input: {"to": "0x...", "value": "0.5", "chain": "ethereum"}
Output: "Transaction submitted for approval. Request ID: abc-123"
```

#### `wallet_check_policy`
Check if a transaction would be approved.

```python
Input: {"to": "0x...", "value": "5.0"}
Output: "Transaction would be rejected: Exceeds per-transaction limit of 1 ETH"
```

#### `wallet_address`
Get wallet address.

```python
Input: {}
Output: "0x742d35Cc6634C0532925a3b844Bc9e7595f12345"
```

### Custom Tools

You can extend the base tools:

```python
from langchain.tools import BaseTool
from pydantic import BaseModel, Field

class SwapInput(BaseModel):
    token_in: str = Field(description="Token to swap from")
    token_out: str = Field(description="Token to swap to")
    amount: str = Field(description="Amount to swap")

class WalletSwapTool(BaseTool):
    name = "wallet_swap"
    description = "Swap tokens via Uniswap"
    args_schema = SwapInput

    def __init__(self, wallet: MpcAgentWallet):
        super().__init__()
        self.wallet = wallet

    def _run(self, token_in: str, token_out: str, amount: str) -> str:
        # Implementation...
        pass
```

## Example Conversations

### Balance Check

```
User: How much ETH do I have?
Agent: I'll check your Ethereum wallet balance.
       [Uses wallet_balance tool]
       Your wallet has 1.5 ETH (approximately $3,000 USD).
```

### Send Transaction

```
User: Send 0.5 ETH to vitalik.eth
Agent: I'll prepare that transaction for you.

       Let me first resolve the ENS name...
       vitalik.eth resolves to 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045

       [Uses wallet_send tool]

       Transaction Details:
       - To: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
       - Amount: 0.5 ETH
       - Estimated Gas: 21,000 (0.001 ETH)

       The transaction has been submitted and is waiting for your approval.
       Please check your mobile app to approve.

       Request ID: tx-12345
```

### Policy Check

```
User: Can I send 10 ETH right now?
Agent: Let me check your spending limits.
       [Uses wallet_check_policy tool]

       That transaction would be rejected because:
       - Your per-transaction limit is 1 ETH
       - You've already spent 8 ETH today (daily limit: 10 ETH)

       You could send up to 1 ETH in a single transaction,
       with 2 ETH remaining in your daily allowance.
```

## Project Structure

```
langchain-tool/
├── src/
│   ├── __init__.py
│   ├── tools.py           # LangChain tool definitions
│   ├── agent.py           # Agent setup helper
│   └── prompts.py         # System prompts
├── examples/
│   ├── basic_agent.py     # Basic usage example
│   └── custom_tools.py    # Custom tool example
├── requirements.txt
└── README.md
```

## Advanced Usage

### With Memory

```python
from langchain.memory import ConversationBufferWindowMemory

memory = ConversationBufferWindowMemory(
    memory_key="chat_history",
    k=5,
    return_messages=True,
)

agent = initialize_agent(
    tools,
    llm,
    agent=AgentType.OPENAI_FUNCTIONS,
    memory=memory,
)
```

### With Custom System Prompt

```python
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder

system_prompt = """You are a DeFi assistant with access to a secure MPC wallet.

Rules:
1. Always confirm transaction details before sending
2. Warn users about high-value transactions
3. Explain gas costs when relevant
4. Never reveal private keys or sensitive wallet data

Available chains: Ethereum, Polygon, Arbitrum
"""

prompt = ChatPromptTemplate.from_messages([
    ("system", system_prompt),
    MessagesPlaceholder(variable_name="chat_history"),
    ("human", "{input}"),
    MessagesPlaceholder(variable_name="agent_scratchpad"),
])
```

## Error Handling

```python
from mpc_wallet import MpcWalletError, ErrorCode

try:
    result = agent.run("Send 100 ETH to 0x...")
except MpcWalletError as e:
    if e.code == ErrorCode.POLICY_VIOLATION:
        print(f"Transaction blocked by policy: {e.message}")
    elif e.code == ErrorCode.THRESHOLD_NOT_MET:
        print("Approval required from another party")
```

## Security Best Practices

1. **Use Restrictive Policies**: Always set spending limits
2. **Whitelist Known Addresses**: Only allow transactions to verified contracts
3. **Monitor Transactions**: Log all agent actions for audit
4. **Rate Limit**: Implement rate limiting on agent requests

## Next Steps

- See [Telegram Bot](../telegram-bot/) for approval via Telegram
- See [DeFi Agent](../defi-agent/) for automated DeFi operations
