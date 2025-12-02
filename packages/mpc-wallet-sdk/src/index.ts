/**
 * MPC Wallet SDK for AI Agents
 *
 * A TypeScript SDK for secure, threshold-signed cryptocurrency transactions
 * using 2-of-3 MPC (Multi-Party Computation).
 *
 * @example
 * ```typescript
 * import { MpcAgentWallet, PolicyConfig } from '@mpc-wallet/sdk';
 *
 * // Create wallet with policy
 * const wallet = await MpcAgentWallet.create({
 *   policy: PolicyConfig.withDailyLimit('1000000000000000000'), // 1 ETH
 * });
 *
 * // Generate key shares for all parties
 * const { shares, address } = await wallet.generateShares();
 *
 * // Sign a transaction (requires 2-of-3 parties)
 * const signature = await wallet.signTransaction({
 *   to: '0x...',
 *   value: '0.1',
 *   chainId: 1,
 * });
 * ```
 *
 * @packageDocumentation
 */

// Core wallet class
export { MpcAgentWallet, type WalletConfig } from './wallet';

// Key generation
export {
  type KeyShare,
  type KeyShareInfo,
  type KeygenConfig,
  type KeygenResult,
  KeygenSession,
  generateSessionId,
} from './keygen';

// Transaction signing
export {
  type SigningConfig,
  type SigningResult,
  type ApprovalRequest,
  SigningSession,
  generateSigningSessionId,
} from './signing';

// Policy engine
export {
  PolicyConfig,
  PolicyEngine,
  type PolicyDecision,
  type SpendingLimits,
  type TimeBounds,
  type ContractRestriction,
} from './policy';

// Chain adapters
export * from './chains';

// Storage
export * from './storage';

// Types
export * from './types';

// Utilities
export * from './utils';

// Version
export const VERSION = '0.1.0';
export const PROTOCOL_VERSION = '2-of-3-threshold-ecdsa';
