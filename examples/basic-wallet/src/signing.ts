/**
 * Signing Helpers
 *
 * Simulates the 2-of-3 threshold signing process.
 * In production, signing parties coordinate via the relay service.
 */

import {
  MpcAgentWallet,
  PartyRole,
  SigningSession,
  generateSigningSessionId,
  type TransactionRequest,
  type Signature,
  type KeyShare,
} from '@mpc-wallet/sdk';
import type { SimulatedKeyShares } from './keygen.js';

/**
 * Sign a transaction with simulated parties
 *
 * In production:
 * - Agent creates signing session
 * - User receives approval request via webhook/push notification
 * - Both parties execute MPC signing protocol via relay
 */
export async function signWithSimulatedParties(
  wallet: MpcAgentWallet,
  keyShares: SimulatedKeyShares,
  tx: TransactionRequest,
  signingParties: [PartyRole, PartyRole]
): Promise<Signature> {
  const sessionId = generateSigningSessionId();

  // Get the key shares for the signing parties
  const shares: KeyShare[] = signingParties.map((role) => {
    switch (role) {
      case PartyRole.Agent:
        return keyShares.agent;
      case PartyRole.User:
        return keyShares.user;
      case PartyRole.Recovery:
        return keyShares.recovery;
    }
  });

  // Create message hash
  const messageHash = wallet.hashTransaction(tx);

  // Convert participant roles to party IDs
  const participants = signingParties.map((role) => role as number);

  // Create signing sessions for each party
  const session1 = new SigningSession(
    { sessionId, participants },
    shares[0],
    messageHash
  );
  const session2 = new SigningSession(
    { sessionId, participants },
    shares[1],
    messageHash
  );

  console.log(
    `      Signing with ${PartyRole[signingParties[0]]} + ${PartyRole[signingParties[1]]}...`
  );

  // Round 1: Generate nonce commitments
  console.log('      Round 1: Generating nonce commitments...');
  const msg1R1 = session1.generateRound1();
  const msg2R1 = session2.generateRound1();

  // Exchange round 1 messages
  session1.processRound1(JSON.stringify([JSON.parse(msg2R1)]));
  session2.processRound1(JSON.stringify([JSON.parse(msg1R1)]));

  // Round 2: Generate partial signatures
  console.log('      Round 2: Generating partial signatures...');
  const msg1R2 = session1.generateRound2();
  const msg2R2 = session2.generateRound2();

  // Finalize and combine signatures
  const signature = session1.processRound2(JSON.stringify([JSON.parse(msg2R2)]));

  return signature;
}

/**
 * Sign a raw message (not a transaction)
 */
export async function signMessage(
  wallet: MpcAgentWallet,
  keyShares: SimulatedKeyShares,
  message: string,
  signingParties: [PartyRole, PartyRole]
): Promise<Signature> {
  const messageHash = wallet.hashEthMessage(message);
  const sessionId = generateSigningSessionId();

  const shares: KeyShare[] = signingParties.map((role) => {
    switch (role) {
      case PartyRole.Agent:
        return keyShares.agent;
      case PartyRole.User:
        return keyShares.user;
      case PartyRole.Recovery:
        return keyShares.recovery;
    }
  });

  const participants = signingParties.map((role) => role as number);

  const session1 = new SigningSession(
    { sessionId, participants },
    shares[0],
    messageHash
  );
  const session2 = new SigningSession(
    { sessionId, participants },
    shares[1],
    messageHash
  );

  // Execute signing protocol
  const msg1R1 = session1.generateRound1();
  const msg2R1 = session2.generateRound1();

  session1.processRound1(JSON.stringify([JSON.parse(msg2R1)]));
  session2.processRound1(JSON.stringify([JSON.parse(msg1R1)]));

  const msg1R2 = session1.generateRound2();
  const msg2R2 = session2.generateRound2();

  return session1.processRound2(JSON.stringify([JSON.parse(msg2R2)]));
}

/**
 * Verify a signature against a message and public key
 */
export function verifySignature(
  _messageHash: Uint8Array,
  _signature: Signature,
  _publicKey: string
): boolean {
  // In production, use secp256k1 ECDSA verification
  // This is a placeholder that always returns true for demo
  console.log('      Verifying signature...');
  return true;
}
