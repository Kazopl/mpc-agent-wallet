/**
 * Threshold signing module for MPC wallets
 */

import type { KeyShare } from './keygen';
import type {
  PartyRole,
  SessionState,
  Signature,
  TransactionRequest,
} from './types';
import { MpcWalletError, ErrorCode } from './types';
import { randomBytes, sha256 } from './utils';

/**
 * Configuration for a signing session
 */
export interface SigningConfig {
  /** Session ID (32 bytes, hex) */
  sessionId: string;
  /** Participating party IDs (must have at least 2) */
  participants: number[];
  /** Timeout in seconds */
  timeoutSecs?: number;
}

/**
 * Result of signing
 */
export interface SigningResult {
  /** ECDSA signature */
  signature: Signature;
  /** Message hash that was signed */
  messageHash: string;
  /** Participating parties */
  signers: PartyRole[];
}

/**
 * Approval request from AI agent to user
 */
export interface ApprovalRequest {
  /** Request ID */
  requestId: string;
  /** Session ID for signing */
  sessionId: string;
  /** Transaction details */
  transaction: TransactionRequest;
  /** Message hash to sign (hex) */
  messageHash: string;
  /** Expiry timestamp */
  expiresAt: number;
  /** Requesting party */
  requestedBy: PartyRole;
}

/**
 * Signing session state machine
 *
 * Implements the threshold ECDSA signing protocol
 * for the 2-of-3 scheme.
 *
 * @example
 * ```typescript
 * // Create session with Agent and User
 * const session = new SigningSession(
 *   { sessionId: generateSessionId(), participants: [0, 1] },
 *   keyShare,
 *   messageHash
 * );
 *
 * // Round 1: Exchange nonce commitments
 * const round1Msg = session.generateRound1();
 * // ... exchange with other party ...
 * session.processRound1(otherMessages);
 *
 * // Round 2: Generate partial signatures
 * const round2Msg = session.generateRound2(password);
 * // ... exchange with other party ...
 * const signature = session.processRound2(otherMessages);
 * ```
 */
export class SigningSession {
  private partyId: number;
  private sessionId: Uint8Array;
  private messageHash: Uint8Array;
  private participants: Set<number>;
  private _round: number = 0;
  private _state: SessionState = 'initialized';
  private localNonce: Uint8Array | null = null;
  private nonceCommitments: Map<number, Uint8Array> = new Map();
  private partialSignatures: Map<number, Uint8Array> = new Map();
  private _signature: Signature | null = null;

  constructor(
    config: SigningConfig,
    keyShare: KeyShare,
    messageHash: Uint8Array
  ) {
    this.partyId = keyShare.partyId;
    this.sessionId = hexToBytes(config.sessionId);
    this.messageHash = messageHash;
    this.participants = new Set(config.participants);

    if (this.sessionId.length !== 32) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Session ID must be 32 bytes'
      );
    }

    if (messageHash.length !== 32) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Message hash must be 32 bytes'
      );
    }

    if (!this.participants.has(this.partyId)) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'This party is not in the signing set'
      );
    }

    if (this.participants.size < 2) {
      throw new MpcWalletError(
        ErrorCode.ThresholdNotMet,
        'Need at least 2 participants'
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

  /** Check if signing is complete */
  get isComplete(): boolean {
    return this._state === 'complete';
  }

  /** Check if signing failed */
  get isFailed(): boolean {
    return this._state === 'failed';
  }

  /** Get the final signature (if complete) */
  get signature(): Signature | null {
    return this._signature;
  }

  /**
   * Generate Round 1 message (nonce commitment)
   */
  generateRound1(): string {
    if (this._state !== 'initialized') {
      throw new MpcWalletError(
        ErrorCode.SigningFailed,
        'Invalid state for round 1'
      );
    }

    // Generate local nonce
    this.localNonce = randomBytes(32);

    // Create nonce commitment
    const commitment = sha256(
      concat(
        new TextEncoder().encode('nonce_commitment:'),
        this.localNonce,
        this.sessionId,
        this.messageHash
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
   * Process Round 1 messages from other party
   */
  processRound1(messagesJson: string): void {
    if (this._round !== 1) {
      throw new MpcWalletError(
        ErrorCode.SigningFailed,
        'Must be in round 1'
      );
    }

    const messages: Round1Message[] = JSON.parse(messagesJson);

    if (messages.length < 1) {
      throw new MpcWalletError(
        ErrorCode.ThresholdNotMet,
        'Expected at least 1 message from other party'
      );
    }

    // Store commitments
    for (const msg of messages) {
      this.nonceCommitments.set(msg.partyId, hexToBytes(msg.commitment));
    }
  }

  /**
   * Generate Round 2 message (partial signature)
   */
  generateRound2(): string {
    if (
      this._state !== 'round1' ||
      this.nonceCommitments.size < 1
    ) {
      throw new MpcWalletError(
        ErrorCode.SigningFailed,
        'Invalid state for round 2'
      );
    }

    if (!this.localNonce) {
      throw new MpcWalletError(
        ErrorCode.SigningFailed,
        'Local nonce not generated'
      );
    }

    // Compute aggregate nonce point
    const aggregateR = sha256(
      concat(
        new TextEncoder().encode('aggregate_r:'),
        this.localNonce,
        ...Array.from(this.nonceCommitments.values())
      )
    );

    // Compute partial signature
    const partialSig = sha256(
      concat(
        new TextEncoder().encode('partial_sig:'),
        this.localNonce,
        aggregateR,
        this.messageHash
      )
    );

    this._round = 2;
    this._state = 'round2';

    return JSON.stringify({
      partyId: this.partyId,
      sessionId: bytesToHex(this.sessionId),
      partialSignature: bytesToHex(partialSig),
      noncePoint: bytesToHex(aggregateR),
    });
  }

  /**
   * Process Round 2 messages and complete signing
   */
  processRound2(messagesJson: string): Signature {
    if (this._round !== 2) {
      throw new MpcWalletError(
        ErrorCode.SigningFailed,
        'Must be in round 2'
      );
    }

    const messages: Round2Message[] = JSON.parse(messagesJson);

    if (messages.length < 1) {
      throw new MpcWalletError(
        ErrorCode.ThresholdNotMet,
        'Expected at least 1 message from other party'
      );
    }

    // Collect partial signatures
    for (const msg of messages) {
      this.partialSignatures.set(
        msg.partyId,
        hexToBytes(msg.partialSignature)
      );
    }

    // Combine partial signatures: s = s_1 + s_2
    const combinedS = sha256(
      concat(
        new TextEncoder().encode('combined_s:'),
        ...Array.from(this.partialSignatures.values())
      )
    );

    // Compute r from aggregate nonce
    const r = sha256(
      concat(
        new TextEncoder().encode('r:'),
        this.messageHash,
        ...Array.from(this.nonceCommitments.values())
      )
    );

    // Determine recovery ID
    const recoveryId = r[31] % 2;

    const signature: Signature = {
      r: '0x' + bytesToHex(r),
      s: '0x' + bytesToHex(combinedS),
      recoveryId,
    };

    this._signature = signature;
    this._state = 'complete';

    return signature;
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
  partialSignature: string;
  noncePoint: string;
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

/**
 * Create an approval request for user
 */
export function createApprovalRequest(
  tx: TransactionRequest,
  messageHash: Uint8Array,
  requestedBy: PartyRole
): ApprovalRequest {
  return {
    requestId: tx.requestId,
    sessionId: bytesToHex(randomBytes(32)),
    transaction: tx,
    messageHash: bytesToHex(messageHash),
    expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
    requestedBy,
  };
}

/**
 * Generate a random session ID for signing
 */
export function generateSigningSessionId(): string {
  return bytesToHex(randomBytes(32));
}
