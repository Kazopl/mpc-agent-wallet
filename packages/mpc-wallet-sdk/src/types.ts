/**
 * Core type definitions for MPC Wallet SDK
 */

/**
 * Party roles in the 2-of-3 MPC wallet
 */
export enum PartyRole {
  /** AI agent party - can initiate transactions */
  Agent = 0,
  /** User party - primary approval authority */
  User = 1,
  /** Recovery guardian - backup approval for recovery scenarios */
  Recovery = 2,
}

/**
 * Supported blockchain types
 */
export enum ChainType {
  /** Ethereum and EVM-compatible chains */
  Evm = 0,
  /** Solana */
  Solana = 1,
  /** Bitcoin */
  Bitcoin = 2,
}

/**
 * ECDSA signature components
 */
export interface Signature {
  /** R component (hex string with 0x prefix) */
  r: string;
  /** S component (hex string with 0x prefix) */
  s: string;
  /** Recovery ID (0 or 1) */
  recoveryId: number;
}

/**
 * Transaction parameters for building transactions
 */
export interface TransactionParams {
  /** Sender address */
  from?: string;
  /** Recipient address */
  to: string;
  /** Value to send (in human-readable format like "1.5" or wei string) */
  value: string;
  /** Transaction data (hex string for contract calls) */
  data?: string;
  /** Gas limit (for EVM) */
  gasLimit?: bigint;
  /** Max fee per gas (for EIP-1559) */
  maxFeePerGas?: bigint;
  /** Max priority fee per gas (for EIP-1559) */
  maxPriorityFeePerGas?: bigint;
  /** Nonce override */
  nonce?: number;
  /** Chain ID (for EVM) */
  chainId?: number;
}

/**
 * Transaction request for signing
 */
export interface TransactionRequest {
  /** Unique request ID */
  requestId: string;
  /** Target chain */
  chain: ChainType;
  /** Recipient address */
  to: string;
  /** Value to send */
  value: string;
  /** Transaction data (hex) */
  data?: string;
  /** Gas limit */
  gasLimit?: number;
  /** Chain ID */
  chainId?: number;
  /** Request timestamp */
  timestamp: number;
  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Balance information
 */
export interface Balance {
  /** Raw balance in smallest unit (wei, lamports, etc.) */
  raw: string;
  /** Human-readable balance with decimals */
  formatted: string;
  /** Currency/token symbol */
  symbol: string;
  /** Number of decimals */
  decimals: number;
}

/**
 * Transaction hash result
 */
export interface TxHash {
  /** Transaction hash */
  hash: string;
  /** Explorer URL (if available) */
  explorerUrl?: string;
}

/**
 * Transaction receipt
 */
export interface TxReceipt {
  /** Transaction hash */
  txHash: string;
  /** Block number */
  blockNumber: number;
  /** Transaction status */
  status: 'success' | 'failed' | 'pending';
  /** Gas used */
  gasUsed?: bigint;
  /** Effective gas price */
  effectiveGasPrice?: bigint;
}

/**
 * Message types for MPC protocol
 */
export type MessageType = 'broadcast' | 'direct';

/**
 * Protocol message
 */
export interface ProtocolMessage {
  /** Message type */
  type: MessageType;
  /** Sender party ID */
  from: number;
  /** Recipient party ID (for direct messages) */
  to?: number;
  /** Protocol round */
  round: number;
  /** Message data (base64 encoded) */
  data: string;
}

/**
 * Session state
 */
export type SessionState =
  | 'initialized'
  | 'round1'
  | 'round2'
  | 'round3'
  | 'complete'
  | 'failed';

/**
 * Error codes
 */
export enum ErrorCode {
  /** Invalid configuration */
  InvalidConfig = 'INVALID_CONFIG',
  /** Invalid party ID */
  InvalidPartyId = 'INVALID_PARTY_ID',
  /** Threshold not met */
  ThresholdNotMet = 'THRESHOLD_NOT_MET',
  /** Policy violation */
  PolicyViolation = 'POLICY_VIOLATION',
  /** Signing failed */
  SigningFailed = 'SIGNING_FAILED',
  /** Key generation failed */
  KeygenFailed = 'KEYGEN_FAILED',
  /** Storage error */
  StorageError = 'STORAGE_ERROR',
  /** Network error */
  NetworkError = 'NETWORK_ERROR',
  /** Timeout */
  Timeout = 'TIMEOUT',
  /** Unknown error */
  Unknown = 'UNKNOWN',
}

/**
 * SDK Error class
 */
export class MpcWalletError extends Error {
  constructor(
    public code: ErrorCode,
    message: string,
    public cause?: Error
  ) {
    super(message);
    this.name = 'MpcWalletError';
  }
}

/**
 * Hex string type (with 0x prefix)
 */
export type HexString = `0x${string}`;

/**
 * Address type (hex string, 20 bytes for EVM)
 */
export type Address = HexString;

/**
 * Hash type (hex string, 32 bytes)
 */
export type Hash = HexString;

/**
 * Type guard for hex strings
 */
export function isHexString(value: string): value is HexString {
  return /^0x[0-9a-fA-F]*$/.test(value);
}

/**
 * Type guard for addresses
 */
export function isAddress(value: string): value is Address {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}
