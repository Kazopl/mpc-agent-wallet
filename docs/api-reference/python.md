# Python API Reference

Complete API reference for the `mpc-wallet` Python package.

## Installation

```bash
pip install mpc-wallet
# or
poetry add mpc-wallet
# or
uv add mpc-wallet
```

## Quick Start

```python
from mpc_wallet import MpcAgentWallet, WalletConfig, PolicyConfig, PartyRole, ChainType

wallet = MpcAgentWallet(WalletConfig(
    role=PartyRole.AGENT,
    policy=PolicyConfig().with_daily_limit(ChainType.EVM, int(10e18)),
))
```

---

## Core Classes

### MpcAgentWallet

Main class for managing MPC-secured wallets.

#### Constructor

```python
def __init__(self, config: WalletConfig | None = None) -> None
```

Create a new MPC wallet instance.

```python
wallet = MpcAgentWallet(WalletConfig(
    role=PartyRole.AGENT,
    policy=PolicyConfig(),
))
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `config.role` | `PartyRole` | Party role (AGENT, USER, RECOVERY) |
| `config.policy` | `PolicyConfig` | Policy configuration |
| `config.key_share` | `KeyShare` | Existing key share to load |

#### Class Methods

##### `from_share(share: KeyShare, policy: PolicyConfig | None = None) -> MpcAgentWallet`

Create a wallet from an existing key share.

```python
wallet = MpcAgentWallet.from_share(key_share, policy=PolicyConfig())
```

#### Instance Methods

##### Key Management

###### `create_keygen_session(config: KeygenConfig) -> KeygenSession`

Create a key generation session.

```python
session = wallet.create_keygen_session(KeygenConfig(
    role=PartyRole.AGENT,
    session_id=str(uuid.uuid4()),
    threshold=2,
    parties=3,
))
```

###### `set_key_share(share: KeyShare) -> None`

Set the key share after key generation.

###### `get_key_share() -> KeyShare | None`

Get the current key share.

###### `has_key_share() -> bool`

Check if a key share is loaded.

###### `role -> PartyRole`

Property to get the party role.

##### Address & Public Key

###### `get_address() -> str`

Get the wallet's Ethereum address.

```python
address = wallet.get_address()
# '0x742d35Cc6634C0532925a3b844Bc9e7595f...'
```

###### `get_public_key() -> str`

Get the wallet's compressed public key.

###### `get_chain_address(chain: ChainType) -> str`

Get address for a specific chain type.

```python
eth_address = wallet.get_chain_address(ChainType.EVM)
sol_address = wallet.get_chain_address(ChainType.SOLANA)
```

##### Policy

###### `set_policy(config: PolicyConfig) -> None`

Set the policy configuration.

###### `get_policy() -> PolicyConfig | None`

Get the current policy configuration.

###### `evaluate_policy(tx: TransactionRequest) -> PolicyDecision`

Evaluate a transaction against the policy.

```python
decision = wallet.evaluate_policy(TransactionRequest(
    request_id="tx-1",
    chain=ChainType.EVM,
    to="0x...",
    value="1000000000000000000",
    chain_id=1,
))

if not decision.approved:
    print(f"Rejected: {decision.reason}")
```

##### Signing

###### `create_signing_session(config: SigningConfig, message_hash: bytes) -> SigningSession`

Create a signing session.

```python
message_hash = wallet.hash_transaction(tx)
session = wallet.create_signing_session(
    SigningConfig(
        session_id=str(uuid.uuid4()),
        parties=[PartyRole.AGENT, PartyRole.USER],
        threshold=2,
    ),
    message_hash
)
```

###### `hash_message(message: bytes) -> bytes`

Hash a message using Keccak256.

###### `hash_eth_message(message: str | bytes) -> bytes`

Hash a message with Ethereum prefix.

###### `hash_transaction(tx: TransactionRequest) -> bytes`

Create a transaction hash for signing.

##### Utilities

###### `to_dict() -> dict[str, Any]`

Export wallet state (without secrets) for debugging.

###### `get_info() -> dict[str, Any]`

Get wallet info summary.

---

### KeygenSession

Manages the distributed key generation (DKG) protocol.

#### Constructor

```python
session = KeygenSession(KeygenConfig(
    role=PartyRole.AGENT,
    session_id="session-123",
    threshold=2,
    parties=3,
))
```

#### Methods

##### `generate_round1() -> ProtocolMessage`

Generate round 1 (commitment) message.

##### `process_round1(messages: list[ProtocolMessage]) -> None`

Process round 1 messages from other parties.

##### `generate_round2() -> ProtocolMessage`

Generate round 2 (key share) message.

##### `process_round2(messages: list[ProtocolMessage]) -> None`

Process round 2 messages from other parties.

##### `generate_round3() -> ProtocolMessage`

Generate round 3 (verification) message.

##### `finalize(messages: list[ProtocolMessage]) -> KeyShare`

Finalize key generation and return the key share.

##### `state -> SessionState`

Property to get current session state.

---

### SigningSession

Manages the distributed signature generation (DSG) protocol.

#### Constructor

```python
session = SigningSession(
    SigningConfig(
        session_id="session-456",
        parties=[PartyRole.AGENT, PartyRole.USER],
        threshold=2,
    ),
    key_share,
    message_hash
)
```

#### Methods

##### `generate_round1() -> ProtocolMessage`

Generate round 1 message.

##### `process_round1(messages: list[ProtocolMessage]) -> None`

Process round 1 messages from other signing parties.

##### `generate_round2() -> ProtocolMessage`

Generate round 2 message.

##### `finalize(messages: list[ProtocolMessage]) -> Signature`

Finalize signing and return the signature.

---

### PolicyConfig

Configuration for the policy engine.

#### Constructor

```python
policy = PolicyConfig()
```

#### Methods

##### `with_spending_limits(chain: ChainType, per_tx: int = 0, daily: int = 0, weekly: int = 0) -> PolicyConfig`

Add spending limits for a chain.

```python
policy.with_spending_limits(
    ChainType.EVM,
    per_tx=int(1e18),   # 1 ETH
    daily=int(10e18),   # 10 ETH
    weekly=int(50e18),  # 50 ETH
)
```

##### `with_whitelist(addresses: list[str]) -> PolicyConfig`

Add address whitelist.

```python
policy.with_whitelist([
    "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
    "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
])
```

##### `with_blacklist(addresses: list[str]) -> PolicyConfig`

Add address blacklist.

##### `with_time_bounds(start_hour: int, end_hour: int, allowed_days: list[int] | None = None, timezone: str = "UTC") -> PolicyConfig`

Add time restrictions.

```python
policy.with_time_bounds(
    start_hour=9,
    end_hour=17,
    allowed_days=[0, 1, 2, 3, 4],  # Monday-Friday
    timezone="America/New_York",
)
```

##### `with_contract_restrictions(allowed_contracts: list[str] | None = None, blocked_selectors: list[str] | None = None) -> PolicyConfig`

Add contract interaction restrictions.

```python
policy.with_contract_restrictions(
    allowed_contracts=["0x..."],
    blocked_selectors=["0xa9059cbb"],  # Block raw ERC20 transfers
)
```

##### `with_additional_approval_threshold(amount: int) -> PolicyConfig`

Require recovery guardian approval for transactions above threshold.

---

### PolicyEngine

Evaluates transactions against configured policies.

#### Constructor

```python
engine = PolicyEngine(policy_config)
```

#### Methods

##### `evaluate(tx: TransactionRequest) -> PolicyDecision`

Evaluate a transaction against all policies.

```python
decision = engine.evaluate(tx)
# PolicyDecision(approved=True)
# or
# PolicyDecision(approved=False, reason="Daily spending limit exceeded")
```

##### `config -> PolicyConfig`

Property to get the current policy configuration.

##### `get_spending_stats(chain: ChainType) -> SpendingStats`

Get current spending statistics.

---

## Data Classes

### WalletConfig

```python
@dataclass
class WalletConfig:
    role: PartyRole = PartyRole.AGENT
    policy: PolicyConfig | None = None
    key_share: KeyShare | None = None
```

### KeygenConfig

```python
@dataclass
class KeygenConfig:
    role: PartyRole
    session_id: str
    threshold: int = 2
    parties: int = 3
```

### SigningConfig

```python
@dataclass
class SigningConfig:
    session_id: str
    parties: list[PartyRole]
    threshold: int = 2
```

### TransactionRequest

```python
@dataclass
class TransactionRequest:
    request_id: str
    chain: ChainType
    to: str
    value: str
    data: str | None = None
    gas_limit: int | None = None
    chain_id: int | None = None
    timestamp: int | None = None
    metadata: dict[str, Any] | None = None
```

### KeyShare

```python
@dataclass
class KeyShare:
    party_id: int
    role: PartyRole
    public_key: str         # Compressed public key (hex)
    eth_address: str        # Derived Ethereum address
    secret_share: str       # Encrypted secret share (base64)
    verification_key: str
    threshold: int
    parties: int
```

### Signature

```python
@dataclass
class Signature:
    r: str            # Hex string with 0x prefix
    s: str            # Hex string with 0x prefix
    recovery_id: int  # 0 or 1
```

### PolicyDecision

```python
@dataclass
class PolicyDecision:
    approved: bool
    reason: str | None = None
    requires_additional_approval: bool = False
```

### ProtocolMessage

```python
@dataclass
class ProtocolMessage:
    type: MessageType  # "broadcast" or "direct"
    from_party: int
    to_party: int | None = None
    round: int
    data: str  # base64 encoded
```

---

## Enums

### PartyRole

```python
class PartyRole(Enum):
    AGENT = 0
    USER = 1
    RECOVERY = 2
```

### ChainType

```python
class ChainType(Enum):
    EVM = 0
    SOLANA = 1
    BITCOIN = 2
```

### SessionState

```python
class SessionState(Enum):
    INITIALIZED = "initialized"
    ROUND1 = "round1"
    ROUND2 = "round2"
    ROUND3 = "round3"
    COMPLETE = "complete"
    FAILED = "failed"
```

### ErrorCode

```python
class ErrorCode(Enum):
    INVALID_CONFIG = "INVALID_CONFIG"
    INVALID_PARTY_ID = "INVALID_PARTY_ID"
    THRESHOLD_NOT_MET = "THRESHOLD_NOT_MET"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    SIGNING_FAILED = "SIGNING_FAILED"
    KEYGEN_FAILED = "KEYGEN_FAILED"
    STORAGE_ERROR = "STORAGE_ERROR"
    NETWORK_ERROR = "NETWORK_ERROR"
    TIMEOUT = "TIMEOUT"
    UNKNOWN = "UNKNOWN"
```

---

## Exceptions

### MpcWalletError

```python
class MpcWalletError(Exception):
    def __init__(self, code: ErrorCode, message: str, cause: Exception | None = None):
        self.code = code
        self.message = message
        self.cause = cause
```

### Error Handling Example

```python
from mpc_wallet import MpcWalletError, ErrorCode

try:
    await wallet.sign_transaction(tx)
except MpcWalletError as e:
    if e.code == ErrorCode.POLICY_VIOLATION:
        print(f"Policy rejected transaction: {e.message}")
    elif e.code == ErrorCode.THRESHOLD_NOT_MET:
        print("Not enough parties for signing")
    elif e.code == ErrorCode.TIMEOUT:
        print("Operation timed out")
    else:
        print(f"Wallet error: {e}")
```

---

## Chain Adapters

### EvmAdapter

Ethereum/EVM chain adapter.

```python
from mpc_wallet.chains import EvmAdapter

adapter = EvmAdapter(
    rpc_urls=["https://eth.llamarpc.com", "https://rpc.ankr.com/eth"],
    chain_id=1,
)

balance = await adapter.get_balance("0x...")
tx = await adapter.build_transaction(
    to="0x...",
    value="1000000000000000000",
)
```

#### Methods

##### `async get_balance(address: str) -> Balance`

Get native token balance.

##### `async build_transaction(to: str, value: str, data: str | None = None, **kwargs) -> UnsignedTx`

Build an unsigned transaction.

##### `async broadcast(signed_tx: SignedTx) -> TxHash`

Broadcast a signed transaction.

##### `derive_address(public_key: bytes) -> str`

Derive Ethereum address from public key.

### SolanaAdapter

Solana chain adapter.

```python
from mpc_wallet.chains import SolanaAdapter

adapter = SolanaAdapter(
    rpc_url="https://api.mainnet-beta.solana.com",
    commitment="confirmed",
)
```

#### Methods

##### `async get_balance(address: str) -> Balance`

Get SOL balance.

##### `async build_transaction(to: str, lamports: int, **kwargs) -> UnsignedTx`

Build an unsigned transaction.

##### `async broadcast(signed_tx: SignedTx) -> TxHash`

Broadcast a signed transaction.

---

## Utility Functions

### Formatting

```python
from mpc_wallet.utils import format_ether, parse_ether, format_gwei

format_ether(10**18)  # "1.0"
parse_ether("1.5")    # 1500000000000000000
format_gwei(10**9)    # "1.0"
```

### Address Validation

```python
from mpc_wallet.utils import is_valid_address, is_valid_hex

is_valid_address("0x742d35Cc6634C0532925a3b844Bc9e7595f12345")  # True
is_valid_hex("0x1234abcd")  # True
```

---

## Async Support

All I/O operations support asyncio:

```python
import asyncio
from mpc_wallet import MpcAgentWallet

async def main():
    wallet = MpcAgentWallet()

    # Async key share loading
    await wallet.load_key_share("my-wallet", "password")

    # Async transaction signing
    signature = await wallet.sign_transaction(tx)

asyncio.run(main())
```

---

## Type Hints

The package includes full type hints and supports mypy/pyright:

```python
from mpc_wallet import MpcAgentWallet, TransactionRequest, PolicyDecision

def process_transaction(wallet: MpcAgentWallet, tx: TransactionRequest) -> PolicyDecision:
    return wallet.evaluate_policy(tx)
```

---

## Integration Examples

### LangChain Tool

```python
from langchain.tools import BaseTool
from mpc_wallet import MpcAgentWallet, TransactionRequest, ChainType

class WalletSendTool(BaseTool):
    name = "wallet_send"
    description = "Send cryptocurrency from the MPC wallet"

    def __init__(self, wallet: MpcAgentWallet):
        super().__init__()
        self.wallet = wallet

    def _run(self, to: str, value: str) -> str:
        tx = TransactionRequest(
            request_id=str(uuid.uuid4()),
            chain=ChainType.EVM,
            to=to,
            value=str(int(float(value) * 10**18)),
            chain_id=1,
        )

        decision = self.wallet.evaluate_policy(tx)
        if not decision.approved:
            return f"Rejected: {decision.reason}"

        return f"Transaction pending approval: {tx.request_id}"
```

### FastAPI Endpoint

```python
from fastapi import FastAPI, HTTPException
from mpc_wallet import MpcAgentWallet, TransactionRequest

app = FastAPI()
wallet = MpcAgentWallet()

@app.post("/transactions")
async def create_transaction(tx: TransactionRequest):
    decision = wallet.evaluate_policy(tx)
    if not decision.approved:
        raise HTTPException(status_code=403, detail=decision.reason)

    # Create approval request...
    return {"status": "pending_approval", "request_id": tx.request_id}
```

---

## Examples

See the [examples directory](../../examples/) for complete working examples:

- [Basic Wallet](../../examples/basic-wallet/)
- [ElizaOS Plugin](../../examples/elizaos-plugin/)
- [LangChain Tool](../../examples/langchain-tool/)
- [Telegram Bot](../../examples/telegram-bot/)
- [DeFi Agent](../../examples/defi-agent/)
