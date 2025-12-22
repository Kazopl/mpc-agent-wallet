# MPC Agent Wallet Smart Contracts

ERC-4337 smart account contracts secured by MPC threshold signatures for AI agent wallets.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MPC SMART ACCOUNT SYSTEM                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐     │
│  │    AI Agent      │     │      User        │     │    Recovery      │     │
│  │    (Share 1)     │     │    (Share 2)     │     │    Guardian      │     │
│  │                  │     │                  │     │    (Share 3)     │     │
│  └────────┬─────────┘     └────────┬─────────┘     └────────┬─────────┘     │
│           │                        │                        │               │
│           └───────────────┬────────┴────────────────────────┘               │
│                           │                                                 │
│                           ▼                                                 │
│            ┌──────────────────────────────┐                                 │
│            │    MPC Threshold Signing     │                                 │
│            │          (2 of 3)            │                                 │
│            └──────────────┬───────────────┘                                 │
│                           │                                                 │
│                           ▼                                                 │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                        MpcSmartAccount                                │  │
│  │  • ERC-4337 compliant                                                 │  │
│  │  • MPC signature validation                                           │  │
│  │  • Built-in spending limits                                           │  │
│  │  • Address whitelisting                                               │  │
│  │  • Time restrictions                                                  │  │
│  │  • UUPS upgradeable                                                   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌────────────────────────────┐  ┌────────────────────────────┐             │
│  │    MpcRecoveryModule       │  │   MpcSpendingLimitHook     │             │
│  │  • Guardian management     │  │  • Per-tx limits           │             │
│  │  • Time-delayed recovery   │  │  • Daily/weekly limits     │             │
│  │  • Key rotation support    │  │  • Token-specific limits   │             │
│  └────────────────────────────┘  │  • Whitelist enforcement   │             │
│                                  └────────────────────────────┘             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Contracts

| Contract | Description |
|----------|-------------|
| `MpcSmartAccount` | ERC-4337 smart account with MPC signature validation and policy enforcement |
| `MpcSmartAccountFactory` | Factory for deploying MPC smart account proxies with CREATE2 |
| `MpcRecoveryModule` | Handles MPC key recovery with time-delayed execution |
| `MpcSpendingLimitHook` | Spending limit enforcement hook for transaction policies |

## Features

### MPC Signature Validation
- Validates aggregated ECDSA signatures from 2-of-3 threshold signing
- Compatible with DKLs23 MPC protocol
- EIP-1271 signature validation for smart contract wallets

### Policy Engine
- **Daily Spending Limits**: Cap total ETH spent per day
- **Transaction Limits**: Maximum ETH per transaction
- **Address Whitelist**: Restrict interactions to approved addresses
- **Time Restrictions**: Allow transactions only during certain hours

### Recovery System
- Guardian-initiated key recovery
- Configurable time delay (default 2 days)
- Cancel pending recovery during delay period
- Support for key share rotation

## Development

### Prerequisites
- [Foundry](https://book.getfoundry.sh/getting-started/installation)

### Install Dependencies
```bash
forge install
```

### Build
```bash
forge build
```

### Test
```bash
# Run all tests
forge test

# Run with verbosity
forge test -vvv

# Run specific test file
forge test --match-path test/unit/MpcSmartAccount.t.sol
```

### Gas Report
```bash
forge test --gas-report
```

## Deployment

### Local (Anvil)
```bash
# Start anvil
anvil

# Deploy
forge script script/Deploy.s.sol:DeployScript --rpc-url http://localhost:8545 --broadcast
```

### Testnet
```bash
forge script script/Deploy.s.sol:DeployScript \
  --rpc-url $SEPOLIA_RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast \
  --verify
```

## Usage

### Creating an Account

```solidity
// 1. Generate MPC public key off-chain via DKG
bytes memory mpcPublicKey = // ... 33-byte compressed public key

// 2. Get counterfactual address
address predictedAddress = factory.getAddress(
    mpcPublicKey,
    recoveryModule,
    10 ether,  // daily limit
    0          // salt
);

// 3. Fund the predicted address
payable(predictedAddress).transfer(1 ether);

// 4. Create account (can be done via UserOperation initCode)
MpcSmartAccount account = factory.createAccount(
    mpcPublicKey,
    recoveryModule,
    10 ether,
    0
);
```

### Executing Transactions

Transactions are executed through ERC-4337 UserOperations:

```typescript
// Build UserOperation
const userOp = {
    sender: accountAddress,
    nonce: await entryPoint.getNonce(accountAddress, 0),
    initCode: "0x",  // Empty if account exists
    callData: account.interface.encodeFunctionData("execute", [
        targetAddress,
        ethValue,
        calldata
    ]),
    // ... gas parameters
    signature: "0x"  // Will be filled by MPC signing
};

// Sign with MPC
const signature = await mpcSign(userOpHash, [aiAgentShare, userShare]);
userOp.signature = signature;

// Submit to bundler
await bundler.sendUserOperation(userOp);
```

### Recovery Flow

```solidity
// 1. Guardian initiates recovery
recoveryModule.initiateRecovery(accountAddress, newMpcPublicKey);

// 2. Wait for delay (2 days by default)

// 3. Execute recovery (anyone can call)
recoveryModule.executeRecovery(accountAddress);

// Alternative: Cancel if malicious
account.cancelRecovery(accountAddress);  // Only account or guardians
```

## Security Considerations

1. **Key Share Distribution**: Store key shares on separate devices
2. **Guardian Selection**: Pick diverse and trusted guardians
3. **Time Delay**: Gives time to detect malicious recovery attempts
4. **Spending Limits**: Limits damage from compromised AI agents
5. **Whitelist**: Only allow known-good contracts

## License

MIT
