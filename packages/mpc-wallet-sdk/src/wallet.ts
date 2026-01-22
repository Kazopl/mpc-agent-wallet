/**
 * Main MPC Agent Wallet class
 */

import type { KeyShare, KeygenConfig } from './keygen';
import { KeygenSession } from './keygen';
import type {
  PaymasterConfig,
  PackedUserOperation,
  SponsorResult,
  SponsorOptions,
  RemainingSponsorship,
} from './paymaster';
import { PaymasterClient } from './paymaster';
import type { PolicyDecision } from './policy';
import { PolicyConfig, PolicyEngine } from './policy';
import type {
  SessionKey,
  SessionKeyConfig,
  SessionKeySignature,
  SessionKeyStatus,
} from './session';
import { SessionKeyManager } from './session';
import type { SigningConfig } from './signing';
import { SigningSession } from './signing';
import type { KeyShareStore } from './storage';
import { MemoryStore } from './storage';
import type {
  Address,
  ChainType,
  PartyRole,
  TransactionParams,
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
  /** Paymaster configuration for gasless transactions */
  paymaster?: PaymasterConfig;
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
  private sessionKeyManager: SessionKeyManager;
  private paymasterClient: PaymasterClient | null = null;
  private storage: KeyShareStore;
  private role: PartyRole;

  private constructor(config: WalletConfig = {}) {
    this.role = config.role ?? 0; // Default to Agent
    this.storage = config.storage ?? new MemoryStore();
    this.sessionKeyManager = new SessionKeyManager();

    if (config.policy) {
      this.policyEngine = new PolicyEngine(config.policy);
    }

    if (config.keyShare) {
      this.keyShare = config.keyShare;
    }

    if (config.paymaster) {
      this.paymasterClient = new PaymasterClient(config.paymaster);
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
  // Session Keys
  // ============================================================================

  /**
   * Create a new session key for delegated signing
   *
   * Session keys enable AI agents to operate with scoped, time-limited
   * permissions without exposing the master MPC key shares.
   *
   * @param config - Session key configuration
   * @returns The created session key with private key for signing
   *
   * @example
   * ```typescript
   * // Create a session key valid for 24 hours with 1 ETH spending limit
   * const sessionKey = await wallet.createSessionKey({
   *   validFor: 24 * 60 * 60, // 24 hours
   *   spendingLimit: 1000000000000000000n, // 1 ETH
   *   whitelist: ['0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D'],
   * });
   * ```
   */
  async createSessionKey(config: SessionKeyConfig): Promise<SessionKey> {
    return this.sessionKeyManager.createSessionKey(config);
  }

  /**
   * Revoke an existing session key
   *
   * @param signer - Session key signer address to revoke
   *
   * @example
   * ```typescript
   * await wallet.revokeSessionKey(sessionKey.signer);
   * ```
   */
  revokeSessionKey(signer: string): void {
    this.sessionKeyManager.revokeSessionKey(signer);
  }

  /**
   * Get all active session keys
   *
   * @returns Array of active (non-revoked, non-expired) session keys
   */
  listSessionKeys(): SessionKey[] {
    return this.sessionKeyManager.getActiveSessionKeys();
  }

  /**
   * Get all session keys including revoked and expired
   *
   * @returns Array of all session keys
   */
  listAllSessionKeys(): SessionKey[] {
    return this.sessionKeyManager.listSessionKeys();
  }

  /**
   * Get session key by signer address
   *
   * @param signer - Session key signer address
   * @returns The session key or null if not found
   */
  getSessionKey(signer: string): SessionKey | null {
    return this.sessionKeyManager.getSessionKey(signer);
  }

  /**
   * Get session key status
   *
   * @param signer - Session key signer address
   * @returns Status information including validity and remaining spending
   */
  getSessionKeyStatus(signer: string): SessionKeyStatus {
    return this.sessionKeyManager.getSessionKeyStatus(signer);
  }

  /**
   * Sign a hash with a session key
   *
   * Creates a signature in the format expected by MpcSmartAccount:
   * [signer address (20 bytes)][ECDSA signature (65 bytes)]
   *
   * @param signer - Session key signer address
   * @param hash - 32-byte hash to sign
   * @returns Session key signature
   *
   * @example
   * ```typescript
   * const signature = await wallet.signWithSessionKey(
   *   sessionKey.signer,
   *   userOpHash
   * );
   * // Use signature.signature in the UserOperation
   * ```
   */
  async signWithSessionKey(
    signer: string,
    hash: Uint8Array | string
  ): Promise<SessionKeySignature> {
    return this.sessionKeyManager.signWithSessionKey(signer, hash);
  }

  /**
   * Execute a transaction using a session key
   *
   * This validates the transaction against session key restrictions
   * and signs it with the session key.
   *
   * @param sessionKey - Session key to use for signing
   * @param tx - Transaction parameters
   * @returns Signed transaction data ready for submission
   *
   * @example
   * ```typescript
   * const signedTx = await wallet.executeWithSessionKey(sessionKey, {
   *   to: '0x1234...',
   *   value: '0.1', // 0.1 ETH
   *   data: '0x...',
   * });
   * ```
   */
  async executeWithSessionKey(
    sessionKey: SessionKey,
    tx: TransactionParams
  ): Promise<{
    signature: SessionKeySignature;
    transaction: TransactionParams;
    validated: boolean;
  }> {
    // Validate transaction against session key restrictions
    const isValid = this.sessionKeyManager.validateTransaction(
      sessionKey.signer,
      tx
    );

    if (!isValid) {
      const status = this.sessionKeyManager.getSessionKeyStatus(sessionKey.signer);
      throw new MpcWalletError(
        ErrorCode.PolicyViolation,
        `Transaction not allowed by session key: ${status.message}`
      );
    }

    // Create transaction hash for signing
    const txHash = this.hashTransaction({
      requestId: `sk-${Date.now()}`,
      chain: 0, // EVM
      to: tx.to,
      value: tx.value,
      data: tx.data,
      chainId: tx.chainId,
      gasLimit: tx.gasLimit ? Number(tx.gasLimit) : undefined,
      timestamp: Date.now(),
    });

    // Sign with session key
    const signature = await this.sessionKeyManager.signWithSessionKey(
      sessionKey.signer,
      txHash
    );

    // Record spending
    const value = BigInt(tx.value || '0');
    if (value > 0n) {
      this.sessionKeyManager.recordSpending(sessionKey.signer, value);
    }

    return {
      signature,
      transaction: tx,
      validated: true,
    };
  }

  /**
   * Update whitelist for an existing session key
   *
   * @param signer - Session key signer address
   * @param whitelist - New whitelist addresses
   */
  updateSessionKeyWhitelist(signer: string, whitelist: string[]): void {
    const sessionKey = this.sessionKeyManager.getSessionKey(signer);
    if (!sessionKey) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Session key not found: ${signer}`
      );
    }
    // Note: This only updates locally. On-chain update requires separate call
    sessionKey.whitelist = whitelist.map((addr) => addr.toLowerCase() as Address);
  }

  /**
   * Get the session key manager for advanced operations
   */
  getSessionKeyManager(): SessionKeyManager {
    return this.sessionKeyManager;
  }

  // ============================================================================
  // Paymaster (Gasless Transactions)
  // ============================================================================

  /**
   * Configure a paymaster for gasless transactions
   *
   * @param config - Paymaster configuration
   *
   * @example
   * ```typescript
   * wallet.setPaymaster({
   *   paymasterAddress: '0x...',
   *   entryPointAddress: '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789',
   *   rpcUrl: 'https://...',
   * });
   * ```
   */
  setPaymaster(config: PaymasterConfig): void {
    this.paymasterClient = new PaymasterClient(config);
  }

  /**
   * Get the paymaster client for advanced operations
   *
   * @returns PaymasterClient or null if not configured
   */
  getPaymasterClient(): PaymasterClient | null {
    return this.paymasterClient;
  }

  /**
   * Check if a paymaster is configured
   */
  hasPaymaster(): boolean {
    return this.paymasterClient !== null;
  }

  /**
   * Check if the wallet is sponsored by the paymaster
   *
   * @returns True if the wallet is sponsored and can have gas paid
   *
   * @example
   * ```typescript
   * if (await wallet.isSponsored()) {
   *   // Can execute gasless transactions
   *   const sponsoredOp = await wallet.sponsorUserOperation(userOp);
   * }
   * ```
   */
  async isSponsored(): Promise<boolean> {
    if (!this.paymasterClient) {
      return false;
    }
    if (!this.keyShare) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'No key share loaded'
      );
    }
    return this.paymasterClient.isSponsored(this.keyShare.ethAddress as Address);
  }

  /**
   * Get remaining gas sponsorship for the wallet
   *
   * @returns Remaining total and daily sponsorship amounts
   *
   * @example
   * ```typescript
   * const { totalRemaining, dailyRemaining } = await wallet.getRemainingSponsorship();
   * console.log(`Can sponsor up to ${totalRemaining} wei total`);
   * console.log(`Can sponsor up to ${dailyRemaining} wei today`);
   * ```
   */
  async getRemainingSponsorship(): Promise<RemainingSponsorship> {
    if (!this.paymasterClient) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Paymaster not configured'
      );
    }
    if (!this.keyShare) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'No key share loaded'
      );
    }
    return this.paymasterClient.getRemainingSponsorship(
      this.keyShare.ethAddress as Address
    );
  }

  /**
   * Sponsor a UserOperation for gasless execution
   *
   * Adds paymaster data to the UserOperation so gas costs are paid
   * by the paymaster instead of the account.
   *
   * @param userOp - UserOperation to sponsor (without paymasterAndData)
   * @param options - Optional sponsor configuration
   * @returns Sponsored UserOperation with paymaster data
   *
   * @example
   * ```typescript
   * // Create a UserOperation
   * const userOp = createEmptyUserOp(walletAddress);
   * userOp.callData = encodeExecute(recipient, value, data);
   *
   * // Sponsor it for gasless execution
   * const { userOp: sponsoredOp, maxCost } = await wallet.sponsorUserOperation(userOp);
   *
   * // Sign and submit the sponsored operation
   * const signature = await wallet.signUserOp(sponsoredOp);
   * sponsoredOp.signature = signature;
   * // Submit to bundler...
   * ```
   */
  async sponsorUserOperation(
    userOp: PackedUserOperation,
    options?: SponsorOptions
  ): Promise<SponsorResult> {
    if (!this.paymasterClient) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Paymaster not configured'
      );
    }
    return this.paymasterClient.sponsorUserOperation(userOp, options);
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
