# TypeScript API Reference

Complete API reference for the `@mpc-wallet/sdk` TypeScript package.

## Installation

```bash
npm install @mpc-wallet/sdk
# or
yarn add @mpc-wallet/sdk
# or
pnpm add @mpc-wallet/sdk
```

## Quick Start

```typescript
import {
  MpcAgentWallet,
  PartyRole,
  PolicyConfig,
  ChainType
} from '@mpc-wallet/sdk';

const wallet = await MpcAgentWallet.create({
  role: PartyRole.Agent,
  policy: new PolicyConfig().withDailyLimit(ChainType.Evm, BigInt('10000000000000000000')),
});
```

---

## Core Classes

### MpcAgentWallet

Main class for managing MPC-secured wallets.

#### Static Methods

##### `create(config?: WalletConfig): Promise<MpcAgentWallet>`

Create a new MPC wallet instance.

```typescript
const wallet = await MpcAgentWallet.create({
  role: PartyRole.Agent,
  policy: new PolicyConfig(),
});
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `config.role` | `PartyRole` | Party role (Agent, User, Recovery) |
| `config.policy` | `PolicyConfig` | Policy configuration |
| `config.storage` | `KeyShareStore` | Storage backend |
| `config.keyShare` | `KeyShare` | Existing key share to load |

##### `fromShare(share: KeyShare, config?: WalletConfig): Promise<MpcAgentWallet>`

Create a wallet from an existing key share.

```typescript
const wallet = await MpcAgentWallet.fromShare(keyShare, {
  policy: new PolicyConfig(),
});
```

##### `fromStorage(shareId: string, password: string, storage: KeyShareStore, config?: WalletConfig): Promise<MpcAgentWallet>`

Create a wallet by loading a key share from storage.

```typescript
const wallet = await MpcAgentWallet.fromStorage(
  'my-wallet',
  'secure-password',
  new FileStore('./keys')
);
```

#### Instance Methods

##### Key Management

###### `createKeygenSession(config: KeygenConfig): KeygenSession`

Create a key generation session.

```typescript
const session = wallet.createKeygenSession({
  role: PartyRole.Agent,
  sessionId: crypto.randomUUID(),
  threshold: 2,
  parties: 3,
});
```

###### `setKeyShare(share: KeyShare): void`

Set the key share after key generation.

###### `getKeyShare(): KeyShare | null`

Get the current key share.

###### `hasKeyShare(): boolean`

Check if a key share is loaded.

###### `getRole(): PartyRole`

Get the party role.

##### Address & Public Key

###### `getAddress(): Address`

Get the wallet's Ethereum address.

```typescript
const address = wallet.getAddress();
// '0x742d35Cc6634C0532925a3b844Bc9e7595f...'
```

###### `getPublicKey(): string`

Get the wallet's compressed public key.

###### `getChainAddress(chain: ChainType): string`

Get address for a specific chain type.

```typescript
const ethAddress = wallet.getChainAddress(ChainType.Evm);
const solAddress = wallet.getChainAddress(ChainType.Solana);
```

##### Policy

###### `setPolicy(config: PolicyConfig): void`

Set the policy configuration.

###### `getPolicy(): PolicyConfig | null`

Get the current policy configuration.

###### `evaluatePolicy(tx: TransactionRequest): PolicyDecision`

Evaluate a transaction against the policy.

```typescript
const decision = wallet.evaluatePolicy({
  requestId: 'tx-1',
  chain: ChainType.Evm,
  to: '0x...',
  value: '1000000000000000000',
  chainId: 1,
  timestamp: Date.now(),
});

if (!decision.approved) {
  console.log('Rejected:', decision.reason);
}
```

##### Signing

###### `createSigningSession(config: SigningConfig, messageHash: Uint8Array): SigningSession`

Create a signing session.

```typescript
const messageHash = wallet.hashTransaction(tx);
const session = wallet.createSigningSession(
  {
    sessionId: crypto.randomUUID(),
    parties: [PartyRole.Agent, PartyRole.User],
    threshold: 2,
  },
  messageHash
);
```

###### `hashMessage(message: Uint8Array): Uint8Array`

Hash a message using Keccak256.

###### `hashEthMessage(message: string | Uint8Array): Uint8Array`

Hash a message with Ethereum prefix (`\x19Ethereum Signed Message:\n`).

###### `hashTransaction(tx: TransactionRequest): Uint8Array`

Create a transaction hash for signing.

##### Storage

###### `saveKeyShare(shareId: string, password: string): Promise<void>`

Save the key share to storage.

```typescript
await wallet.saveKeyShare('my-wallet', 'secure-password');
```

###### `loadKeyShare(shareId: string, password: string): Promise<void>`

Load a key share from storage.

###### `deleteKeyShare(shareId: string): Promise<boolean>`

Delete a key share from storage.

###### `listKeyShares(): Promise<string[]>`

List all stored share IDs.

##### Utilities

###### `toJSON(): object`

Export wallet state (without secrets) for debugging.

###### `getInfo(): WalletInfo`

Get wallet info summary.

---

### KeygenSession

Manages the distributed key generation (DKG) protocol.

#### Constructor

```typescript
const session = new KeygenSession({
  role: PartyRole.Agent,
  sessionId: 'session-123',
  threshold: 2,
  parties: 3,
});
```

#### Methods

##### `generateRound1(): ProtocolMessage`

Generate round 1 (commitment) message.

##### `processRound1(messages: ProtocolMessage[]): void`

Process round 1 messages from other parties.

##### `generateRound2(): ProtocolMessage`

Generate round 2 (key share) message.

##### `processRound2(messages: ProtocolMessage[]): void`

Process round 2 messages from other parties.

##### `generateRound3(): ProtocolMessage`

Generate round 3 (verification) message.

##### `finalize(messages: ProtocolMessage[]): KeyShare`

Finalize key generation and return the key share.

##### `getState(): SessionState`

Get current session state.

---

### SigningSession

Manages the distributed signature generation (DSG) protocol.

#### Constructor

```typescript
const session = new SigningSession(
  {
    sessionId: 'session-456',
    parties: [PartyRole.Agent, PartyRole.User],
    threshold: 2,
  },
  keyShare,
  messageHash
);
```

#### Methods

##### `generateRound1(): ProtocolMessage`

Generate round 1 message.

##### `processRound1(messages: ProtocolMessage[]): void`

Process round 1 messages from other signing parties.

##### `generateRound2(): ProtocolMessage`

Generate round 2 message.

##### `finalize(messages: ProtocolMessage[]): Signature`

Finalize signing and return the signature.

---

### PolicyConfig

Configuration for the policy engine.

#### Constructor

```typescript
const policy = new PolicyConfig();
```

#### Methods

##### `withSpendingLimits(chain: ChainType, limits: SpendingLimits): PolicyConfig`

Add spending limits for a chain.

```typescript
policy.withSpendingLimits(ChainType.Evm, {
  perTransaction: BigInt('1000000000000000000'),  // 1 ETH
  daily: BigInt('10000000000000000000'),          // 10 ETH
  weekly: BigInt('50000000000000000000'),         // 50 ETH
});
```

##### `withWhitelist(addresses: string[]): PolicyConfig`

Add address whitelist.

```typescript
policy.withWhitelist([
  '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
  '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',
]);
```

##### `withBlacklist(addresses: string[]): PolicyConfig`

Add address blacklist.

##### `withTimeBounds(bounds: TimeBounds): PolicyConfig`

Add time restrictions.

```typescript
policy.withTimeBounds({
  startHour: 9,
  endHour: 17,
  allowedDays: [1, 2, 3, 4, 5], // Monday-Friday
  timezone: 'America/New_York',
});
```

##### `withContractRestrictions(restrictions: ContractRestriction): PolicyConfig`

Add contract interaction restrictions.

```typescript
policy.withContractRestrictions({
  allowedContracts: ['0x...'],
  blockedSelectors: ['0xa9059cbb'], // Block raw ERC20 transfers
});
```

##### `withAdditionalApprovalThreshold(amount: bigint): PolicyConfig`

Require recovery guardian approval for transactions above threshold.

---

### PolicyEngine

Evaluates transactions against configured policies.

#### Constructor

```typescript
const engine = new PolicyEngine(policyConfig);
```

#### Methods

##### `evaluate(tx: TransactionRequest): PolicyDecision`

Evaluate a transaction against all policies.

```typescript
const decision = engine.evaluate(tx);
// { approved: true, requiresAdditionalApproval: false }
// or
// { approved: false, reason: 'Daily spending limit exceeded' }
```

##### `getConfig(): PolicyConfig`

Get the current policy configuration.

##### `updateConfig(config: PolicyConfig): void`

Update the policy configuration.

##### `getSpendingStats(chain: ChainType): SpendingStats`

Get current spending statistics.

---

## Storage Interfaces

### KeyShareStore

Interface for key share storage backends.

```typescript
interface KeyShareStore {
  store(id: string, share: KeyShare, password: string): Promise<void>;
  load(id: string, password: string): Promise<KeyShare>;
  delete(id: string): Promise<boolean>;
  list(): Promise<string[]>;
  exists(id: string): Promise<boolean>;
}
```

### MemoryStore

In-memory storage (for testing).

```typescript
const store = new MemoryStore();
```

### FileStore

File system storage with encryption.

```typescript
const store = new FileStore('./keys', {
  permissions: 0o600,
});
```

### IndexedDBStore

Browser IndexedDB storage.

```typescript
const store = new IndexedDBStore('mpc-wallet');
```

---

## Chain Adapters

### EvmAdapter

Ethereum/EVM chain adapter.

```typescript
import { EvmAdapter } from '@mpc-wallet/sdk/chains';

const adapter = new EvmAdapter({
  rpcUrls: ['https://eth.llamarpc.com', 'https://rpc.ankr.com/eth'],
  chainId: 1,
});

const balance = await adapter.getBalance('0x...');
const tx = await adapter.buildTransaction({
  to: '0x...',
  value: '1000000000000000000',
});
```

### SolanaAdapter

Solana chain adapter.

```typescript
import { SolanaAdapter } from '@mpc-wallet/sdk/chains';

const adapter = new SolanaAdapter({
  rpcUrl: 'https://api.mainnet-beta.solana.com',
  commitment: 'confirmed',
});
```

---

## Type Definitions

### PartyRole

```typescript
enum PartyRole {
  Agent = 0,
  User = 1,
  Recovery = 2,
}
```

### ChainType

```typescript
enum ChainType {
  Evm = 0,
  Solana = 1,
  Bitcoin = 2,
}
```

### TransactionRequest

```typescript
interface TransactionRequest {
  requestId: string;
  chain: ChainType;
  to: string;
  value: string;
  data?: string;
  gasLimit?: number;
  chainId?: number;
  timestamp: number;
  metadata?: Record<string, unknown>;
}
```

### Signature

```typescript
interface Signature {
  r: string;          // Hex string with 0x prefix
  s: string;          // Hex string with 0x prefix
  recoveryId: number; // 0 or 1
}
```

### PolicyDecision

```typescript
interface PolicyDecision {
  approved: boolean;
  reason?: string;
  requiresAdditionalApproval?: boolean;
}
```

### KeyShare

```typescript
interface KeyShare {
  partyId: number;
  role: PartyRole;
  publicKey: string;      // Compressed public key (hex)
  ethAddress: string;     // Derived Ethereum address
  secretShare: string;    // Encrypted secret share (base64)
  verificationKey: string;
  threshold: number;
  parties: number;
}
```

### SessionState

```typescript
type SessionState =
  | 'initialized'
  | 'round1'
  | 'round2'
  | 'round3'
  | 'complete'
  | 'failed';
```

### ErrorCode

```typescript
enum ErrorCode {
  InvalidConfig = 'INVALID_CONFIG',
  InvalidPartyId = 'INVALID_PARTY_ID',
  ThresholdNotMet = 'THRESHOLD_NOT_MET',
  PolicyViolation = 'POLICY_VIOLATION',
  SigningFailed = 'SIGNING_FAILED',
  KeygenFailed = 'KEYGEN_FAILED',
  StorageError = 'STORAGE_ERROR',
  NetworkError = 'NETWORK_ERROR',
  Timeout = 'TIMEOUT',
  Unknown = 'UNKNOWN',
}
```

---

## Error Handling

### MpcWalletError

```typescript
class MpcWalletError extends Error {
  code: ErrorCode;
  cause?: Error;
}
```

### Error Handling Example

```typescript
import { MpcWalletError, ErrorCode } from '@mpc-wallet/sdk';

try {
  await wallet.signTransaction(tx);
} catch (error) {
  if (error instanceof MpcWalletError) {
    switch (error.code) {
      case ErrorCode.PolicyViolation:
        console.log('Policy rejected transaction:', error.message);
        break;
      case ErrorCode.ThresholdNotMet:
        console.log('Not enough parties for signing');
        break;
      case ErrorCode.Timeout:
        console.log('Operation timed out');
        break;
      default:
        console.error('Wallet error:', error);
    }
  }
}
```

---

## Utility Functions

### Type Guards

```typescript
import { isHexString, isAddress } from '@mpc-wallet/sdk';

isHexString('0x1234');  // true
isAddress('0x742d35Cc6634C0532925a3b844Bc9e7595f12345'); // true
```

### Formatting

```typescript
import { formatEther, parseEther, formatGwei } from '@mpc-wallet/sdk/utils';

formatEther(BigInt('1000000000000000000')); // '1.0'
parseEther('1.5');  // BigInt('1500000000000000000')
```

---

## Events

The wallet emits events for monitoring:

```typescript
wallet.on('keyShareLoaded', (share: KeyShare) => {
  console.log('Key share loaded:', share.ethAddress);
});

wallet.on('policyEvaluated', (tx: TransactionRequest, decision: PolicyDecision) => {
  console.log('Policy decision:', decision);
});

wallet.on('signingStarted', (sessionId: string) => {
  console.log('Signing session started:', sessionId);
});

wallet.on('signingComplete', (sessionId: string, signature: Signature) => {
  console.log('Signing complete:', signature);
});
```

---

## Examples

See the [examples directory](../../examples/) for complete working examples:

- [Basic Wallet](../../examples/basic-wallet/)
- [ElizaOS Plugin](../../examples/elizaos-plugin/)
- [LangChain Tool](../../examples/langchain-tool/)
- [Telegram Bot](../../examples/telegram-bot/)
- [DeFi Agent](../../examples/defi-agent/)
