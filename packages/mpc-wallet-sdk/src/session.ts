/**
 * Session key management for MPC Agent Wallets
 *
 * Session keys enable AI agents to operate with scoped, time-limited permissions
 * without exposing the master MPC key shares.
 *
 * @example
 * ```typescript
 * // Create a session key for an AI trading bot
 * const sessionKey = await wallet.createSessionKey({
 *   validFor: 24 * 60 * 60, // 24 hours
 *   spendingLimit: parseEther('1'), // 1 ETH max
 *   whitelist: ['0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D'], // Uniswap Router
 *   selectors: ['0x38ed1739', '0x8803dbee'], // swapExactTokensForTokens, swapTokensForExactTokens
 * });
 *
 * // Execute transactions using the session key
 * const txHash = await wallet.executeWithSessionKey(sessionKey, {
 *   to: '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',
 *   value: '0',
 *   data: swapCalldata,
 * });
 *
 * // Revoke when done
 * await wallet.revokeSessionKey(sessionKey.signer);
 * ```
 */

import type { Address, HexString, TransactionParams } from './types';
import { MpcWalletError, ErrorCode, isAddress } from './types';
import { randomBytes, bytesToHex, hexToBytes, sha256 } from './utils';

/**
 * Session key configuration for creating new session keys
 */
export interface SessionKeyConfig {
  /** Duration in seconds for which the session key is valid */
  validFor: number;
  /** Maximum ETH spend allowed (in wei as bigint or string) */
  spendingLimit?: bigint | string;
  /** Whitelisted target addresses (empty = all allowed) */
  whitelist?: string[];
  /** Allowed function selectors (4 bytes hex, empty = all allowed) */
  selectors?: string[];
  /** Custom validity start time (Unix timestamp). Default: now */
  validAfter?: number;
}

/**
 * Session key data structure
 */
export interface SessionKey {
  /** Session key signer address */
  signer: Address;
  /** Private key for signing (only available to creator) */
  privateKey?: HexString;
  /** Start timestamp (Unix seconds) */
  validAfter: number;
  /** Expiry timestamp (Unix seconds) */
  validUntil: number;
  /** Maximum ETH spending limit (wei) */
  spendingLimit: bigint;
  /** Amount already spent (wei) */
  spent: bigint;
  /** Whitelisted target addresses */
  whitelist: Address[];
  /** Allowed function selectors */
  selectors: HexString[];
  /** Whether revoked */
  revoked: boolean;
  /** Creation timestamp */
  createdAt: number;
}

/**
 * Session key signing result
 */
export interface SessionKeySignature {
  /** Combined signature (signer address + ECDSA signature) */
  signature: HexString;
  /** Session key signer address */
  signer: Address;
  /** Expiry timestamp */
  validUntil: number;
}

/**
 * Session key status information
 */
export interface SessionKeyStatus {
  /** Whether the session key is currently valid */
  isValid: boolean;
  /** Remaining spending allowance (wei) */
  remainingSpending: bigint;
  /** Time until expiry (seconds, 0 if expired) */
  timeRemaining: number;
  /** Status message */
  message: string;
}

/**
 * Session key manager for creating, signing, and managing session keys
 */
export class SessionKeyManager {
  private sessionKeys: Map<string, SessionKey> = new Map();

  /**
   * Create a new session key
   *
   * @param config - Session key configuration
   * @returns The created session key with private key
   *
   * @example
   * ```typescript
   * const manager = new SessionKeyManager();
   * const sessionKey = await manager.createSessionKey({
   *   validFor: 3600, // 1 hour
   *   spendingLimit: 1000000000000000000n, // 1 ETH
   *   whitelist: ['0x1234...'],
   * });
   * ```
   */
  async createSessionKey(config: SessionKeyConfig): Promise<SessionKey> {
    // Validate config
    if (config.validFor <= 0) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Session key duration must be positive'
      );
    }

    if (config.validFor > 30 * 24 * 60 * 60) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Session key duration cannot exceed 30 days'
      );
    }

    // Generate a new keypair for the session key
    const privateKeyBytes = randomBytes(32);
    const privateKey = ('0x' + bytesToHex(privateKeyBytes)) as HexString;

    // Derive address from private key (simplified - in production use proper secp256k1)
    const addressBytes = sha256(privateKeyBytes).slice(12, 32);
    const signer = ('0x' + bytesToHex(addressBytes)) as Address;

    const now = Math.floor(Date.now() / 1000);
    const validAfter = config.validAfter ?? now;
    const validUntil = validAfter + config.validFor;

    // Parse spending limit
    let spendingLimit: bigint;
    if (config.spendingLimit === undefined) {
      spendingLimit = 0n; // 0 means no limit
    } else if (typeof config.spendingLimit === 'string') {
      spendingLimit = BigInt(config.spendingLimit);
    } else {
      spendingLimit = config.spendingLimit;
    }

    // Validate whitelist addresses
    const whitelist: Address[] = [];
    if (config.whitelist) {
      for (const addr of config.whitelist) {
        if (!isAddress(addr)) {
          throw new MpcWalletError(
            ErrorCode.InvalidConfig,
            `Invalid whitelist address: ${addr}`
          );
        }
        whitelist.push(addr.toLowerCase() as Address);
      }
    }

    // Validate selectors
    const selectors: HexString[] = [];
    if (config.selectors) {
      for (const selector of config.selectors) {
        if (!/^0x[0-9a-fA-F]{8}$/.test(selector)) {
          throw new MpcWalletError(
            ErrorCode.InvalidConfig,
            `Invalid selector format: ${selector}`
          );
        }
        selectors.push(selector.toLowerCase() as HexString);
      }
    }

    const sessionKey: SessionKey = {
      signer,
      privateKey,
      validAfter,
      validUntil,
      spendingLimit,
      spent: 0n,
      whitelist,
      selectors,
      revoked: false,
      createdAt: now,
    };

    // Store session key
    this.sessionKeys.set(signer.toLowerCase(), sessionKey);

    return sessionKey;
  }

  /**
   * Revoke a session key
   *
   * @param signer - Session key signer address
   */
  revokeSessionKey(signer: string): void {
    const key = signer.toLowerCase();
    const sessionKey = this.sessionKeys.get(key);

    if (!sessionKey) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Session key not found: ${signer}`
      );
    }

    sessionKey.revoked = true;
  }

  /**
   * Get session key by signer address
   *
   * @param signer - Session key signer address
   * @returns The session key or null if not found
   */
  getSessionKey(signer: string): SessionKey | null {
    return this.sessionKeys.get(signer.toLowerCase()) ?? null;
  }

  /**
   * Get all active (non-revoked, non-expired) session keys
   *
   * @returns Array of active session keys
   */
  getActiveSessionKeys(): SessionKey[] {
    const now = Math.floor(Date.now() / 1000);
    return Array.from(this.sessionKeys.values()).filter(
      (sk) => !sk.revoked && sk.validAfter <= now && sk.validUntil > now
    );
  }

  /**
   * List all session keys (including revoked/expired)
   *
   * @returns Array of all session keys
   */
  listSessionKeys(): SessionKey[] {
    return Array.from(this.sessionKeys.values());
  }

  /**
   * Get session key status
   *
   * @param signer - Session key signer address
   * @returns Status information
   */
  getSessionKeyStatus(signer: string): SessionKeyStatus {
    const sessionKey = this.sessionKeys.get(signer.toLowerCase());

    if (!sessionKey) {
      return {
        isValid: false,
        remainingSpending: 0n,
        timeRemaining: 0,
        message: 'Session key not found',
      };
    }

    const now = Math.floor(Date.now() / 1000);

    if (sessionKey.revoked) {
      return {
        isValid: false,
        remainingSpending: 0n,
        timeRemaining: 0,
        message: 'Session key has been revoked',
      };
    }

    if (now < sessionKey.validAfter) {
      return {
        isValid: false,
        remainingSpending: sessionKey.spendingLimit - sessionKey.spent,
        timeRemaining: sessionKey.validUntil - now,
        message: `Session key not yet valid (starts in ${sessionKey.validAfter - now}s)`,
      };
    }

    if (now > sessionKey.validUntil) {
      return {
        isValid: false,
        remainingSpending: 0n,
        timeRemaining: 0,
        message: 'Session key has expired',
      };
    }

    const remainingSpending =
      sessionKey.spendingLimit > 0n
        ? sessionKey.spendingLimit - sessionKey.spent
        : BigInt(Number.MAX_SAFE_INTEGER); // No limit

    return {
      isValid: true,
      remainingSpending,
      timeRemaining: sessionKey.validUntil - now,
      message: 'Session key is valid',
    };
  }

  /**
   * Sign a message/hash with a session key
   *
   * @param signer - Session key signer address
   * @param hash - 32-byte hash to sign (as Uint8Array or hex string)
   * @returns Session key signature
   *
   * @example
   * ```typescript
   * const signature = await manager.signWithSessionKey(
   *   sessionKey.signer,
   *   userOpHash
   * );
   * ```
   */
  async signWithSessionKey(
    signer: string,
    hash: Uint8Array | string
  ): Promise<SessionKeySignature> {
    const sessionKey = this.sessionKeys.get(signer.toLowerCase());

    if (!sessionKey) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Session key not found: ${signer}`
      );
    }

    if (!sessionKey.privateKey) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Session key private key not available'
      );
    }

    const status = this.getSessionKeyStatus(signer);
    if (!status.isValid) {
      throw new MpcWalletError(ErrorCode.PolicyViolation, status.message);
    }

    // Convert hash to bytes if needed
    const hashBytes = typeof hash === 'string' ? hexToBytes(hash) : hash;

    if (hashBytes.length !== 32) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Hash must be 32 bytes'
      );
    }

    // Create Ethereum signed message hash
    const prefix = '\x19Ethereum Signed Message:\n32';
    const prefixBytes = new TextEncoder().encode(prefix);
    const combined = new Uint8Array(prefixBytes.length + hashBytes.length);
    combined.set(prefixBytes);
    combined.set(hashBytes, prefixBytes.length);
    const ethSignedHash = sha256(combined);

    // Generate signature (simplified - in production use proper secp256k1)
    // Format: r (32 bytes) + s (32 bytes) + v (1 byte)
    const privateKeyBytes = hexToBytes(sessionKey.privateKey);
    const r = sha256(
      concatBytes(privateKeyBytes, ethSignedHash, new Uint8Array([0]))
    );
    const s = sha256(
      concatBytes(privateKeyBytes, ethSignedHash, new Uint8Array([1]))
    );
    const v = (r[0] % 2) + 27;

    // Combine into full signature (65 bytes)
    const ecdsaSig = new Uint8Array(65);
    ecdsaSig.set(r, 0);
    ecdsaSig.set(s, 32);
    ecdsaSig[64] = v;

    // Session key signature format: [signer address (20 bytes)][ECDSA signature (65 bytes)]
    const signerBytes = hexToBytes(sessionKey.signer);
    const fullSignature = new Uint8Array(85);
    fullSignature.set(signerBytes, 0);
    fullSignature.set(ecdsaSig, 20);

    return {
      signature: ('0x' + bytesToHex(fullSignature)) as HexString,
      signer: sessionKey.signer,
      validUntil: sessionKey.validUntil,
    };
  }

  /**
   * Validate a transaction against session key restrictions
   *
   * @param signer - Session key signer address
   * @param tx - Transaction parameters
   * @returns Whether the transaction is allowed
   */
  validateTransaction(signer: string, tx: TransactionParams): boolean {
    const sessionKey = this.sessionKeys.get(signer.toLowerCase());

    if (!sessionKey) {
      return false;
    }

    const status = this.getSessionKeyStatus(signer);
    if (!status.isValid) {
      return false;
    }

    // Check whitelist
    if (sessionKey.whitelist.length > 0) {
      const target = tx.to.toLowerCase();
      if (!sessionKey.whitelist.some((addr) => addr.toLowerCase() === target)) {
        return false;
      }
    }

    // Check selectors
    if (sessionKey.selectors.length > 0 && tx.data && tx.data.length >= 10) {
      const selector = tx.data.slice(0, 10).toLowerCase();
      if (!sessionKey.selectors.some((s) => s.toLowerCase() === selector)) {
        return false;
      }
    }

    // Check spending limit
    if (sessionKey.spendingLimit > 0n) {
      const value = BigInt(tx.value || '0');
      if (value > status.remainingSpending) {
        return false;
      }
    }

    return true;
  }

  /**
   * Record spending for a session key
   *
   * @param signer - Session key signer address
   * @param amount - Amount spent (wei)
   */
  recordSpending(signer: string, amount: bigint): void {
    const sessionKey = this.sessionKeys.get(signer.toLowerCase());

    if (sessionKey) {
      sessionKey.spent += amount;
    }
  }

  /**
   * Clear all session keys
   */
  clear(): void {
    this.sessionKeys.clear();
  }

  /**
   * Export session keys for storage (without private keys)
   */
  export(): SessionKeyExport[] {
    return Array.from(this.sessionKeys.values()).map((sk) => ({
      signer: sk.signer,
      validAfter: sk.validAfter,
      validUntil: sk.validUntil,
      spendingLimit: sk.spendingLimit.toString(),
      spent: sk.spent.toString(),
      whitelist: sk.whitelist,
      selectors: sk.selectors,
      revoked: sk.revoked,
      createdAt: sk.createdAt,
    }));
  }

  /**
   * Import session keys from storage
   */
  import(keys: SessionKeyExport[]): void {
    for (const key of keys) {
      const sessionKey: SessionKey = {
        signer: key.signer as Address,
        validAfter: key.validAfter,
        validUntil: key.validUntil,
        spendingLimit: BigInt(key.spendingLimit),
        spent: BigInt(key.spent),
        whitelist: key.whitelist as Address[],
        selectors: key.selectors as HexString[],
        revoked: key.revoked,
        createdAt: key.createdAt,
      };
      this.sessionKeys.set(key.signer.toLowerCase(), sessionKey);
    }
  }
}

/**
 * Session key export format (JSON-serializable)
 */
export interface SessionKeyExport {
  signer: string;
  validAfter: number;
  validUntil: number;
  spendingLimit: string;
  spent: string;
  whitelist: string[];
  selectors: string[];
  revoked: boolean;
  createdAt: number;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Concatenate multiple Uint8Arrays
 */
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Create session key parameters for on-chain registration
 *
 * @param sessionKey - Session key data
 * @returns Parameters for calling createSessionKey on the contract
 */
export function encodeSessionKeyParams(sessionKey: SessionKey): {
  signer: Address;
  validAfter: number;
  validUntil: number;
  spendingLimit: bigint;
  whitelist: Address[];
  selectors: HexString[];
} {
  return {
    signer: sessionKey.signer,
    validAfter: sessionKey.validAfter,
    validUntil: sessionKey.validUntil,
    spendingLimit: sessionKey.spendingLimit,
    whitelist: sessionKey.whitelist,
    selectors: sessionKey.selectors,
  };
}

/**
 * Parse session key data from contract response
 *
 * @param data - Contract response data
 * @returns Parsed session key
 */
export function parseSessionKeyFromContract(data: {
  signer: string;
  validAfter: bigint | number;
  validUntil: bigint | number;
  spendingLimit: bigint;
  spent: bigint;
  whitelist: string[];
  selectors: string[];
  revoked: boolean;
}): Omit<SessionKey, 'privateKey' | 'createdAt'> {
  return {
    signer: data.signer as Address,
    validAfter: Number(data.validAfter),
    validUntil: Number(data.validUntil),
    spendingLimit: data.spendingLimit,
    spent: data.spent,
    whitelist: data.whitelist as Address[],
    selectors: data.selectors as HexString[],
    revoked: data.revoked,
  };
}

/**
 * Generate a random session key ID
 */
export function generateSessionKeyId(): string {
  return bytesToHex(randomBytes(16));
}
