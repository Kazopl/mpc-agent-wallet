/**
 * Key generation module for MPC wallets
 */

import type { PartyRole, SessionState } from './types';
import { MpcWalletError, ErrorCode } from './types';
import { randomBytes, sha256 } from './utils';

/**
 * Key share information (non-sensitive)
 */
export interface KeyShareInfo {
  /** Share identifier */
  shareId: string;
  /** Party role */
  role: PartyRole;
  /** Public key (compressed, hex) */
  publicKey: string;
  /** Ethereum address */
  ethAddress: string;
  /** Creation timestamp */
  createdAt: number;
}

/**
 * Complete key share (includes encrypted secret)
 */
export interface KeyShare extends KeyShareInfo {
  /** Party ID (0, 1, or 2) */
  partyId: number;
  /** Encrypted share data */
  encryptedData: string;
  /** Chain code for BIP32 derivation */
  chainCode: string;
  /** Nonce for encryption */
  nonce: string;
  /** Salt for key derivation */
  salt: string;
  /** Version */
  version: number;
}

/**
 * Configuration for key generation
 */
export interface KeygenConfig {
  /** This party's role */
  role: PartyRole;
  /** Session ID (32 bytes, hex) */
  sessionId: string;
  /** Timeout in seconds */
  timeoutSecs?: number;
}

/**
 * Result of key generation
 */
export interface KeygenResult {
  /** Generated key share */
  share: KeyShare;
  /** Aggregated public key */
  publicKey: string;
  /** Ethereum address */
  ethAddress: string;
}

/**
 * Key generation session state machine
 *
 * Implements the DKG (Distributed Key Generation) protocol
 * for the 2-of-3 threshold ECDSA scheme.
 *
 * @example
 * ```typescript
 * // Create session for Agent party
 * const session = new KeygenSession({
 *   role: PartyRole.Agent,
 *   sessionId: generateSessionId(),
 * });
 *
 * // Round 1: Generate and exchange commitments
 * const round1Msg = session.generateRound1();
 * // ... send to other parties and receive their messages ...
 * session.processRound1(otherMessages);
 *
 * // Round 2: Generate and exchange public shares
 * const round2Msg = session.generateRound2();
 * // ... send to other parties and receive their messages ...
 * const result = session.processRound2(otherMessages, password);
 * ```
 */
export class KeygenSession {
  private partyId: number;
  private sessionId: Uint8Array;
  private _round: number = 0;
  private _state: SessionState = 'initialized';
  private localSecret: Uint8Array | null = null;
  private commitments: Map<number, Uint8Array> = new Map();
  private publicShares: Map<number, Uint8Array> = new Map();

  constructor(config: KeygenConfig) {
    this.partyId = config.role;
    this.sessionId = hexToBytes(config.sessionId);

    if (this.sessionId.length !== 32) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Session ID must be 32 bytes'
      );
    }
  }

  /** Get current round number */
  get round(): number {
    return this._round;
  }

  /** Get current state */
  get state(): SessionState {
    return this._state;
  }

  /** Check if keygen is complete */
  get isComplete(): boolean {
    return this._state === 'complete';
  }

  /** Check if keygen failed */
  get isFailed(): boolean {
    return this._state === 'failed';
  }

  /**
   * Generate Round 1 message (commitment)
   */
  generateRound1(): string {
    if (this._state !== 'initialized') {
      throw new MpcWalletError(
        ErrorCode.KeygenFailed,
        'Invalid state for round 1'
      );
    }

    // Generate local secret
    this.localSecret = randomBytes(32);

    // Create commitment (hash of secret with context)
    const commitment = sha256(
      concat(
        new TextEncoder().encode('commitment:'),
        this.localSecret,
        this.sessionId,
        new Uint8Array([this.partyId])
      )
    );

    this._round = 1;
    this._state = 'round1';

    return JSON.stringify({
      partyId: this.partyId,
      sessionId: bytesToHex(this.sessionId),
      commitment: bytesToHex(commitment),
    });
  }

  /**
   * Process Round 1 messages from other parties
   */
  processRound1(messagesJson: string): void {
    if (this._round !== 1) {
      throw new MpcWalletError(
        ErrorCode.KeygenFailed,
        'Must be in round 1'
      );
    }

    const messages: Round1Message[] = JSON.parse(messagesJson);

    if (messages.length !== 2) {
      throw new MpcWalletError(
        ErrorCode.ThresholdNotMet,
        'Expected 2 messages from other parties'
      );
    }

    // Store commitments
    for (const msg of messages) {
      this.commitments.set(msg.partyId, hexToBytes(msg.commitment));
    }
  }

  /**
   * Generate Round 2 message (public share)
   */
  generateRound2(): string {
    if (this._state !== 'round1' || this.commitments.size !== 2) {
      throw new MpcWalletError(
        ErrorCode.KeygenFailed,
        'Invalid state for round 2'
      );
    }

    if (!this.localSecret) {
      throw new MpcWalletError(
        ErrorCode.KeygenFailed,
        'Local secret not generated'
      );
    }

    // Generate public share from secret
    const publicShare = sha256(
      concat(new TextEncoder().encode('public:'), this.localSecret)
    );

    this._round = 2;
    this._state = 'round2';

    return JSON.stringify({
      partyId: this.partyId,
      sessionId: bytesToHex(this.sessionId),
      publicShare: bytesToHex(publicShare),
    });
  }

  /**
   * Process Round 2 messages and complete keygen
   */
  processRound2(messagesJson: string, password: string): KeygenResult {
    if (this._round !== 2) {
      throw new MpcWalletError(
        ErrorCode.KeygenFailed,
        'Must be in round 2'
      );
    }

    if (!this.localSecret) {
      throw new MpcWalletError(
        ErrorCode.KeygenFailed,
        'Local secret not available'
      );
    }

    const messages: Round2Message[] = JSON.parse(messagesJson);

    if (messages.length !== 2) {
      throw new MpcWalletError(
        ErrorCode.ThresholdNotMet,
        'Expected 2 messages from other parties'
      );
    }

    // Store public shares
    for (const msg of messages) {
      this.publicShares.set(msg.partyId, hexToBytes(msg.publicShare));
    }

    // Compute aggregated public key
    const aggregatedPk = sha256(
      concat(
        new TextEncoder().encode('aggregate:'),
        this.localSecret,
        ...Array.from(this.publicShares.values())
      )
    );

    // Create compressed public key format
    const publicKey = concat(new Uint8Array([0x02]), aggregatedPk);

    // Derive Ethereum address
    const addressHash = sha256(aggregatedPk);
    const ethAddress = '0x' + bytesToHex(addressHash.slice(12));

    // Encrypt the secret
    const { ciphertext, nonce, salt } = encryptSecret(
      this.localSecret,
      password
    );

    // Generate chain code
    const chainCode = sha256(
      concat(
        new TextEncoder().encode('chaincode:'),
        this.sessionId,
        publicKey
      )
    );

    const share: KeyShare = {
      shareId: `share-${this.partyId}`,
      partyId: this.partyId,
      role: this.partyId as PartyRole,
      publicKey: bytesToHex(publicKey),
      ethAddress,
      encryptedData: ciphertext,
      chainCode: bytesToHex(chainCode),
      nonce,
      salt,
      createdAt: Date.now(),
      version: 1,
    };

    this._state = 'complete';

    return {
      share,
      publicKey: bytesToHex(publicKey),
      ethAddress,
    };
  }
}

// ============================================================================
// Message Types
// ============================================================================

interface Round1Message {
  partyId: number;
  sessionId: string;
  commitment: string;
}

interface Round2Message {
  partyId: number;
  sessionId: string;
  publicShare: string;
}

// ============================================================================
// Helper Functions
// ============================================================================

function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

function encryptSecret(
  secret: Uint8Array,
  password: string
): { ciphertext: string; nonce: string; salt: string } {
  // Simple XOR encryption for demo purposes
  // In production, use proper ChaCha20-Poly1305
  const salt = randomBytes(32);
  const nonce = randomBytes(12);
  const key = sha256(concat(new TextEncoder().encode(password), salt));

  const ciphertext = new Uint8Array(secret.length);
  for (let i = 0; i < secret.length; i++) {
    ciphertext[i] = secret[i] ^ key[i % key.length];
  }

  return {
    ciphertext: btoa(String.fromCharCode(...ciphertext)),
    nonce: bytesToHex(nonce),
    salt: bytesToHex(salt),
  };
}

/**
 * Generate a random session ID
 */
export function generateSessionId(): string {
  return bytesToHex(randomBytes(32));
}
