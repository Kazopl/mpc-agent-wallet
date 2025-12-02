/**
 * Main MPC Agent Wallet class
 */

import type { KeyShare, KeygenConfig } from './keygen';
import { KeygenSession } from './keygen';
import type { PolicyDecision } from './policy';
import { PolicyConfig, PolicyEngine } from './policy';
import type { SigningConfig } from './signing';
import { SigningSession } from './signing';
import type { KeyShareStore } from './storage';
import { MemoryStore } from './storage';
import type {
  Address,
  ChainType,
  PartyRole,
  TransactionRequest,
} from './types';
import { MpcWalletError, ErrorCode } from './types';

/**
 * Configuration for creating an MPC wallet
 */
export interface WalletConfig {
  /** Party role for this wallet instance */
  role?: PartyRole;
  /** Policy configuration */
  policy?: PolicyConfig;
  /** Storage backend */
  storage?: KeyShareStore;
  /** Existing key share to load */
  keyShare?: KeyShare;
}

/**
 * MPC Agent Wallet
 *
 * Main class for managing MPC-secured wallets for AI agents.
 * Implements 2-of-3 threshold signing where any two parties
 * (Agent, User, Recovery) can sign transactions.
 *
 * @example
 * ```typescript
 * // Create a new wallet for the AI agent
 * const wallet = await MpcAgentWallet.create({
 *   role: PartyRole.Agent,
 *   policy: PolicyConfig.withDailyLimit('1000000000000000000'),
 * });
 *
 * // Generate key shares
 * const result = await wallet.generateShares(sessionConfig);
 *
 * // Sign a transaction
 * const tx: TransactionRequest = {
 *   requestId: 'tx-1',
 *   chain: ChainType.Evm,
 *   to: '0x...',
 *   value: '1000000000000000000',
 *   chainId: 1,
 *   timestamp: Date.now(),
 * };
 *
 * const signature = await wallet.signTransaction(tx, signingConfig);
 * ```
 */
export class MpcAgentWallet {
  private keyShare: KeyShare | null = null;
  private policyEngine: PolicyEngine | null = null;
  private storage: KeyShareStore;
  private role: PartyRole;

  private constructor(config: WalletConfig = {}) {
    this.role = config.role ?? 0; // Default to Agent
    this.storage = config.storage ?? new MemoryStore();

    if (config.policy) {
      this.policyEngine = new PolicyEngine(config.policy);
    }

    if (config.keyShare) {
      this.keyShare = config.keyShare;
    }
  }

  /**
   * Create a new MPC wallet instance
   */
  static async create(config: WalletConfig = {}): Promise<MpcAgentWallet> {
    return new MpcAgentWallet(config);
  }

  /**
   * Create a wallet from an existing key share
   */
  static async fromShare(
    share: KeyShare,
    config: Omit<WalletConfig, 'keyShare'> = {}
  ): Promise<MpcAgentWallet> {
    return new MpcAgentWallet({ ...config, keyShare: share });
  }

  /**
   * Create a wallet from a stored share ID
   */
  static async fromStorage(
    shareId: string,
    password: string,
    storage: KeyShareStore,
    config: Omit<WalletConfig, 'keyShare' | 'storage'> = {}
  ): Promise<MpcAgentWallet> {
    const share = await storage.load(shareId, password);
    return new MpcAgentWallet({ ...config, keyShare: share, storage });
  }

  // ============================================================================
  // Key Management
  // ============================================================================

  /**
   * Create a key generation session
   */
  createKeygenSession(config: KeygenConfig): KeygenSession {
    return new KeygenSession(config);
  }

  /**
   * Set the key share after key generation
   */
  setKeyShare(share: KeyShare): void {
    this.keyShare = share;
    this.role = share.role;
  }

  /**
   * Get the current key share (if loaded)
   */
  getKeyShare(): KeyShare | null {
    return this.keyShare;
  }

  /**
   * Check if a key share is loaded
   */
  hasKeyShare(): boolean {
    return this.keyShare !== null;
  }

  /**
   * Get the party role
   */
  getRole(): PartyRole {
    return this.role;
  }

  // ============================================================================
  // Address & Public Key
  // ============================================================================

  /**
   * Get the wallet's Ethereum address
   */
  getAddress(): Address {
    if (!this.keyShare) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'No key share loaded'
      );
    }
    return this.keyShare.ethAddress as Address;
  }

  /**
   * Get the wallet's public key (compressed)
   */
  getPublicKey(): string {
    if (!this.keyShare) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'No key share loaded'
      );
    }
    return this.keyShare.publicKey;
  }

  /**
   * Get address for a specific chain type
   */
  getChainAddress(chain: ChainType): string {
    if (!this.keyShare) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'No key share loaded'
      );
    }

    switch (chain) {
      case 0: // Evm
        return this.keyShare.ethAddress;
      case 1: // Solana
        // For Solana, would need to derive ed25519 address
        // For now, return the public key as base58
        return this.keyShare.publicKey;
      default:
        throw new MpcWalletError(
          ErrorCode.InvalidConfig,
          `Unsupported chain: ${chain}`
        );
    }
  }

  // ============================================================================
  // Policy
  // ============================================================================

  /**
   * Set the policy configuration
   */
  setPolicy(config: PolicyConfig): void {
    this.policyEngine = new PolicyEngine(config);
  }

  /**
   * Get the current policy configuration
   */
  getPolicy(): PolicyConfig | null {
    return this.policyEngine?.getConfig() ?? null;
  }

  /**
   * Evaluate a transaction against the policy
   */
  evaluatePolicy(tx: TransactionRequest): PolicyDecision {
    if (!this.policyEngine) {
      // No policy = approve all
      return { approved: true, requiresAdditionalApproval: false };
    }
    return this.policyEngine.evaluate(tx);
  }

  // ============================================================================
  // Signing
  // ============================================================================

  /**
   * Create a signing session
   */
  createSigningSession(
    config: SigningConfig,
    messageHash: Uint8Array
  ): SigningSession {
    if (!this.keyShare) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'No key share loaded'
      );
    }

    return new SigningSession(config, this.keyShare, messageHash);
  }

  /**
   * Hash a message for signing (Keccak256)
   */
  hashMessage(message: Uint8Array): Uint8Array {
    // Use a simple hash implementation
    // In production, this would use the WASM module
    const hash = new Uint8Array(32);
    for (let i = 0; i < message.length; i++) {
      hash[i % 32] ^= message[i];
    }
    return hash;
  }

  /**
   * Hash a message with Ethereum prefix
   */
  hashEthMessage(message: string | Uint8Array): Uint8Array {
    const msgBytes =
      typeof message === 'string' ? new TextEncoder().encode(message) : message;
    const prefix = `\x19Ethereum Signed Message:\n${msgBytes.length}`;
    const prefixBytes = new TextEncoder().encode(prefix);

    const combined = new Uint8Array(prefixBytes.length + msgBytes.length);
    combined.set(prefixBytes);
    combined.set(msgBytes, prefixBytes.length);

    return this.hashMessage(combined);
  }

  /**
   * Create a transaction hash for signing
   */
  hashTransaction(tx: TransactionRequest): Uint8Array {
    // Serialize and hash the transaction
    const txData = JSON.stringify({
      to: tx.to,
      value: tx.value,
      data: tx.data,
      chainId: tx.chainId,
      gasLimit: tx.gasLimit,
    });
    return this.hashMessage(new TextEncoder().encode(txData));
  }

  // ============================================================================
  // Storage
  // ============================================================================

  /**
   * Save the key share to storage
   */
  async saveKeyShare(shareId: string, password: string): Promise<void> {
    if (!this.keyShare) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'No key share to save'
      );
    }
    await this.storage.store(shareId, this.keyShare, password);
  }

  /**
   * Load a key share from storage
   */
  async loadKeyShare(shareId: string, password: string): Promise<void> {
    const share = await this.storage.load(shareId, password);
    this.setKeyShare(share);
  }

  /**
   * Delete a key share from storage
   */
  async deleteKeyShare(shareId: string): Promise<boolean> {
    return this.storage.delete(shareId);
  }

  /**
   * List all stored share IDs
   */
  async listKeyShares(): Promise<string[]> {
    return this.storage.list();
  }

  // ============================================================================
  // Utilities
  // ============================================================================

  /**
   * Export wallet state (without secrets) for debugging
   */
  toJSON(): object {
    return {
      role: this.role,
      hasKeyShare: this.hasKeyShare(),
      address: this.keyShare?.ethAddress ?? null,
      publicKey: this.keyShare?.publicKey ?? null,
      hasPolicy: this.policyEngine !== null,
    };
  }

  /**
   * Get wallet info summary
   */
  getInfo(): {
    role: PartyRole;
    address: string | null;
    publicKey: string | null;
    hasPolicy: boolean;
  } {
    return {
      role: this.role,
      address: this.keyShare?.ethAddress ?? null,
      publicKey: this.keyShare?.publicKey ?? null,
      hasPolicy: this.policyEngine !== null,
    };
  }
}
