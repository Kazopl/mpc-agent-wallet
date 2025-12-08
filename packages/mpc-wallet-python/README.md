# MPC Wallet Python SDK

Python SDK for MPC-secured AI agent wallets with 2-of-3 threshold signing.

## Installation

```bash
pip install mpc-wallet
```

With optional chain dependencies:

```bash
# For EVM chains
pip install mpc-wallet[evm]

# For Solana
pip install mpc-wallet[solana]

# All dependencies
pip install mpc-wallet[evm,solana]
```

## Quick Start

```python
from mpc_wallet import (
    MpcAgentWallet,
    WalletConfig,
    PolicyConfig,
    PartyRole,
    KeygenConfig,
)
from mpc_wallet.keygen import generate_session_id

# Create a wallet for the AI agent party
wallet = MpcAgentWallet(WalletConfig(
    role=PartyRole.AGENT,
    policy=PolicyConfig().with_daily_limit(int(1e18)),  # 1 ETH daily limit
))

# Create a key generation session
session_id = generate_session_id()
session = wallet.create_keygen_session(KeygenConfig(
    role=PartyRole.AGENT,
    session_id=session_id,
))

# Round 1: Generate commitment
round1_msg = session.generate_round1()
# ... send round1_msg to other parties and receive their messages ...

# Process other parties' round 1 messages
session.process_round1(other_round1_messages_json)

# Round 2: Generate public share
round2_msg = session.generate_round2()
# ... send round2_msg to other parties and receive their messages ...

# Complete keygen
result = session.process_round2(other_round2_messages_json, password="secure-password")
wallet.set_key_share(result.share)

print(f"Wallet address: {wallet.get_address()}")
```

## Signing Transactions

```python
from mpc_wallet import SigningConfig, TransactionRequest, ChainType
from mpc_wallet.signing import generate_signing_session_id

# Create a transaction request
tx = TransactionRequest(
    request_id="tx-1",
    chain=ChainType.EVM,
    to="0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28",
    value="1000000000000000000",  # 1 ETH in wei
    chain_id=1,
    timestamp=int(time.time()),
)

# Check policy
decision = wallet.evaluate_policy(tx)
if not decision.approved:
    print(f"Transaction rejected: {decision.reason}")
    exit(1)

# Create signing session with Agent + User
message_hash = wallet.hash_transaction(tx)
session = wallet.create_signing_session(
    SigningConfig(
        session_id=generate_signing_session_id(),
        participants=[0, 1],  # Agent + User
    ),
    message_hash,
)

# Round 1: Generate and exchange nonce commitments
round1_msg = session.generate_round1()
# ... exchange with other party ...
session.process_round1(other_round1_messages_json)

# Round 2: Generate and exchange partial signatures
round2_msg = session.generate_round2()
# ... exchange with other party ...
signature = session.process_round2(other_round2_messages_json)

print(f"Signature: {signature.to_hex()}")
```

## Chain Adapters

### EVM

```python
from mpc_wallet.chains import EvmAdapter, EVMChains

adapter = EvmAdapter(EVMChains["ETHEREUM_MAINNET"])

# Get balance
balance = await adapter.get_balance("0x...")
print(f"Balance: {balance.formatted}")

# Build and broadcast transaction
unsigned_tx = await adapter.build_transaction(EvmTxParams(
    from_address="0x...",
    to="0x...",
    value="1000000000000000000",
))

signed_tx = adapter.finalize_transaction(unsigned_tx, signature)
tx_hash = await adapter.broadcast(signed_tx)
print(f"Transaction: {tx_hash.explorer_url}")
```

### Solana

```python
from mpc_wallet.chains import SolanaAdapter, SolanaNetworks

adapter = SolanaAdapter(SolanaNetworks["MAINNET"])

# Get balance
balance = await adapter.get_balance("...")
print(f"Balance: {balance.formatted}")
```

## Storage

```python
from mpc_wallet.storage import FileSystemStore, create_backup, restore_backup

# Store key share
store = FileSystemStore("/path/to/shares")
store.store("my-wallet", key_share, password="secure-password")

# Load key share
share = store.load("my-wallet", password="secure-password")

# Create backup
backup = create_backup([share], password="backup-password")

# Restore from backup
shares = restore_backup(backup, password="backup-password")
```

## Policy Configuration

```python
from mpc_wallet import PolicyConfig, TimeBounds, ContractRestriction

policy = (
    PolicyConfig()
    .with_per_tx_limit(int(0.1e18))  # 0.1 ETH per transaction
    .with_daily_limit(int(1e18))     # 1 ETH daily
    .with_weekly_limit(int(5e18))    # 5 ETH weekly
    .with_whitelist(["0x...", "0x..."])
    .with_blacklist(["0xBadAddress..."])
    .with_business_hours()            # 9 AM - 5 PM UTC, weekdays only
    .with_additional_approval_threshold(int(5e18))  # Require extra approval above 5 ETH
)

wallet.set_policy(policy)
```

## License

MIT
