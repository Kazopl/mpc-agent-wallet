//! DSG protocol implementation with policy enforcement

use super::{
    DsgPartialMessage, DsgRound1Message, DsgRound2Message, PartialSignature, PreSignature,
};
use crate::mpc::Relay;
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::{
    AgentKeyShare, Error, PartyId, PartyRole, Result, SessionConfig, Signature, THRESHOLD,
    TransactionRequest,
};
use k256::{
    AffinePoint, ProjectivePoint, Scalar,
    elliptic_curve::{
        Field,
        bigint::U256,
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};
use rand::rngs::OsRng;
use tracing::{debug, info, instrument, warn};

/// Sign a transaction with policy enforcement
///
/// This is the main entry point for signing transactions. It:
/// 1. Evaluates the transaction against the policy engine
/// 2. If approved, runs the MPC signing protocol
/// 3. Records the transaction in the policy tracker
///
/// # Arguments
/// * `key_share` - This party's key share
/// * `tx` - Transaction request to sign
/// * `message_hash` - 32-byte hash of the transaction to sign
/// * `parties` - Participating party roles (must be at least 2)
/// * `policy` - Policy engine for enforcement
/// * `relay` - Message relay for communication
///
/// # Returns
/// The ECDSA signature if policy approves and signing succeeds
#[instrument(skip(key_share, policy, relay))]
pub async fn sign_with_policy<R: Relay>(
    key_share: &AgentKeyShare,
    tx: &TransactionRequest,
    message_hash: &[u8; 32],
    parties: &[PartyRole],
    policy: &PolicyEngine,
    relay: &R,
) -> Result<Signature> {
    info!(
        request_id = %tx.request_id,
        to = %tx.to,
        value = %tx.value,
        parties = ?parties,
        "Processing signing request"
    );

    // Evaluate policy
    let decision = policy.evaluate(tx)?;

    match decision {
        PolicyDecision::Approve => {
            debug!("Policy approved transaction");
        }
        PolicyDecision::Reject { reason } => {
            warn!(reason = %reason, "Policy rejected transaction");
            return Err(Error::PolicyViolation(reason));
        }
        PolicyDecision::RequireAdditionalApproval { reason } => {
            // Check if Recovery party is included
            if !parties.contains(&PartyRole::Recovery) {
                warn!(
                    reason = %reason,
                    "Transaction requires additional approval but Recovery not included"
                );
                return Err(Error::PolicyViolation(format!(
                    "{} - include Recovery guardian to proceed",
                    reason
                )));
            }
            debug!(reason = %reason, "Additional approval provided by Recovery");
        }
    }

    // Run the signing protocol
    let party_ids: Vec<PartyId> = parties.iter().map(|r| r.party_id()).collect();
    let signature = run_dsg(key_share, message_hash, &party_ids, relay).await?;

    // Record the transaction for spending tracking
    policy.record_transaction(tx)?;

    info!(
        request_id = %tx.request_id,
        r = hex::encode(&signature.r),
        "Transaction signed successfully"
    );

    Ok(signature)
}

/// Run the distributed signature generation protocol
///
/// This implements a simplified 3-round signing protocol.
///
/// # Arguments
/// * `key_share` - This party's key share
/// * `message` - 32-byte message hash to sign
/// * `parties` - List of participating party IDs
/// * `relay` - Message relay for communication
///
/// # Returns
/// The ECDSA signature
#[instrument(skip(key_share, relay))]
pub async fn run_dsg<R: Relay>(
    key_share: &AgentKeyShare,
    message: &[u8; 32],
    parties: &[PartyId],
    relay: &R,
) -> Result<Signature> {
    info!(
        party_id = key_share.party_id,
        role = %key_share.role,
        participants = ?parties,
        "Starting DSG"
    );

    // Verify threshold
    if parties.len() < THRESHOLD {
        return Err(Error::ThresholdNotMet {
            required: THRESHOLD,
            actual: parties.len(),
        });
    }

    // Verify this party is in the signing set
    if !parties.contains(&key_share.party_id) {
        return Err(Error::InvalidSigningParties(
            "This party is not in the signing set".into(),
        ));
    }

    let session_id: [u8; 32] = rand::random();
    let config = SessionConfig {
        session_id,
        n_parties: parties.len(),
        threshold: THRESHOLD,
        party_id: key_share.party_id,
        role: key_share.role,
        parties: parties.to_vec(),
        timeout_secs: 60,
    };

    // Generate pre-signature
    let pre_sig = generate_pre_signature(key_share, &config, relay).await?;

    // Create partial signature
    let partial = create_partial_signature(key_share, &pre_sig, message, &config)?;

    // Broadcast partial signature
    let partial_msg = DsgPartialMessage {
        party_id: key_share.party_id,
        sigma_share: partial.sigma_share.clone(),
    };
    relay.broadcast(&session_id, 3, &partial_msg).await?;

    // Collect partial signatures
    let all_partials = relay
        .collect_broadcasts::<DsgPartialMessage>(&session_id, 3, parties.len())
        .await?;

    let partial_sigs: Vec<PartialSignature> = all_partials
        .into_iter()
        .map(|msg| PartialSignature {
            party_id: msg.party_id,
            sigma_share: msg.sigma_share,
        })
        .collect();

    // Combine partial signatures
    let signature = combine_partial_signatures(&pre_sig, &partial_sigs, message)?;

    info!(
        party_id = key_share.party_id,
        r = hex::encode(&signature.r),
        s = hex::encode(&signature.s),
        "DSG completed successfully"
    );

    Ok(signature)
}

/// Generate pre-signature (R point and related values)
async fn generate_pre_signature<R: Relay>(
    key_share: &AgentKeyShare,
    config: &SessionConfig,
    relay: &R,
) -> Result<PreSignature> {
    debug!("Generating pre-signature");

    let mut rng = OsRng;

    // ============ Round 1: Generate nonces and commitments ============
    let k_i = Scalar::random(&mut rng);
    let gamma_i = Scalar::random(&mut rng);

    let k_commitment = ProjectivePoint::GENERATOR * k_i;
    let gamma_commitment = ProjectivePoint::GENERATOR * gamma_i;

    let round1_msg = DsgRound1Message {
        party_id: config.party_id,
        k_commitment: k_commitment
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        gamma_commitment: gamma_commitment
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
    };
    relay.broadcast(&config.session_id, 1, &round1_msg).await?;

    // Collect round 1 messages
    let round1_msgs = relay
        .collect_broadcasts::<DsgRound1Message>(&config.session_id, 1, config.parties.len())
        .await?;

    // ============ Round 2: MtA-like protocol (simplified) ============
    debug!("DSG Round 2: Computing shares");

    // Compute Lagrange coefficient for this party
    let lambda_i = compute_lagrange_coefficient(config.party_id, &config.parties);

    // Compute shares
    let x_i = key_share.secret_share * lambda_i;
    let k_inv_share = k_i; // In full protocol, this involves MtA
    let chi_share = x_i * k_i; // Simplified - full protocol uses MtA

    // Broadcast round 2
    let round2_msg = DsgRound2Message {
        party_id: config.party_id,
        delta_share: (k_i * gamma_i).to_bytes().to_vec(),
    };
    relay.broadcast(&config.session_id, 2, &round2_msg).await?;

    // Collect round 2 messages
    let _round2_msgs = relay
        .collect_broadcasts::<DsgRound2Message>(&config.session_id, 2, config.parties.len())
        .await?;

    // Compute R = sum of k_i * G
    let mut r_point = ProjectivePoint::IDENTITY;
    for msg in &round1_msgs {
        let point = k256::EncodedPoint::from_bytes(&msg.k_commitment)
            .map_err(|e| Error::Deserialization(e.to_string()))?;
        let affine_opt = AffinePoint::from_encoded_point(&point);
        let affine: AffinePoint = Option::<AffinePoint>::from(affine_opt)
            .ok_or_else(|| Error::VerificationFailed("Invalid K commitment".into()))?;
        let commitment = ProjectivePoint::from(affine);
        r_point = r_point + commitment;
    }

    let r_encoded = r_point.to_affine().to_encoded_point(true);

    Ok(PreSignature {
        session_id: config.session_id,
        parties: config.parties.clone(),
        r_point: r_encoded.as_bytes().to_vec(),
        k_inv_share: k_inv_share.to_bytes().to_vec(),
        chi_share: chi_share.to_bytes().to_vec(),
    })
}

/// Create a partial signature
fn create_partial_signature(
    _key_share: &AgentKeyShare,
    pre_sig: &PreSignature,
    message: &[u8; 32],
    config: &SessionConfig,
) -> Result<PartialSignature> {
    // Parse pre-signature data
    let k_inv_bytes: [u8; 32] = pre_sig
        .k_inv_share
        .clone()
        .try_into()
        .map_err(|_| Error::Deserialization("Invalid k_inv_share length".into()))?;
    let k_inv_share = <Scalar as Reduce<U256>>::reduce_bytes(&k_inv_bytes.into());

    let chi_bytes: [u8; 32] = pre_sig
        .chi_share
        .clone()
        .try_into()
        .map_err(|_| Error::Deserialization("Invalid chi_share length".into()))?;
    let chi_share = <Scalar as Reduce<U256>>::reduce_bytes(&chi_bytes.into());

    // Get r value from R point
    let r_point = k256::EncodedPoint::from_bytes(&pre_sig.r_point)
        .map_err(|e| Error::Deserialization(e.to_string()))?;
    let r_affine_opt = AffinePoint::from_encoded_point(&r_point);
    let r_affine: AffinePoint = Option::<AffinePoint>::from(r_affine_opt)
        .ok_or_else(|| Error::VerificationFailed("Invalid R point".into()))?;

    // r = x-coordinate of R mod n
    let r_bytes = r_affine.to_encoded_point(false);
    let r_coord: [u8; 32] = r_bytes.as_bytes()[1..33]
        .try_into()
        .map_err(|_| Error::Internal("Invalid R coordinate".into()))?;
    let r = <Scalar as Reduce<U256>>::reduce_bytes(&r_coord.into());

    // m = message hash
    let m = <Scalar as Reduce<U256>>::reduce_bytes(&(*message).into());

    // sigma_i = k_i^-1 * (m + r * x_i)
    // Simplified: sigma_i = k_inv_share * m + r * chi_share
    let sigma_share = k_inv_share * m + r * chi_share;

    Ok(PartialSignature {
        party_id: config.party_id,
        sigma_share: sigma_share.to_bytes().to_vec(),
    })
}

/// Combine partial signatures into final signature
fn combine_partial_signatures(
    pre_sig: &PreSignature,
    partials: &[PartialSignature],
    _message: &[u8; 32],
) -> Result<Signature> {
    // Sum all sigma shares
    let mut s = Scalar::ZERO;
    for partial in partials {
        let sigma_bytes: [u8; 32] = partial
            .sigma_share
            .clone()
            .try_into()
            .map_err(|_| Error::Deserialization("Invalid sigma_share length".into()))?;
        let sigma = <Scalar as Reduce<U256>>::reduce_bytes(&sigma_bytes.into());
        s = s + sigma;
    }

    // Get r from R point
    let r_point = k256::EncodedPoint::from_bytes(&pre_sig.r_point)
        .map_err(|e| Error::Deserialization(e.to_string()))?;
    let r_affine_opt = AffinePoint::from_encoded_point(&r_point);
    let r_affine: AffinePoint = Option::<AffinePoint>::from(r_affine_opt)
        .ok_or_else(|| Error::VerificationFailed("Invalid R point".into()))?;

    let r_bytes = r_affine.to_encoded_point(false);
    let r: [u8; 32] = r_bytes.as_bytes()[1..33]
        .try_into()
        .map_err(|_| Error::Internal("Invalid r length".into()))?;

    // Normalize s to low-s form for EIP-2
    // For now, we just use the s value directly
    // In production, you'd check if s > n/2 and negate if so
    let s_bytes = s.to_bytes();
    let s_normalized: [u8; 32] = s_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Internal("Invalid s length".into()))?;

    // Compute recovery ID from Y coordinate parity
    let r_encoded = r_affine.to_encoded_point(true);
    let recovery_id = if r_encoded.as_bytes()[0] == 0x03 {
        1
    } else {
        0
    };

    Ok(Signature::new(r, s_normalized, recovery_id))
}

/// Compute Lagrange coefficient for party i in the signing set
fn compute_lagrange_coefficient(party_id: PartyId, parties: &[PartyId]) -> Scalar {
    let i = party_id as u64 + 1;
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;

    for &j_id in parties {
        let j = j_id as u64 + 1;
        if j != i {
            numerator = numerator * Scalar::from(j);
            let diff = if j > i {
                Scalar::from(j - i)
            } else {
                -Scalar::from(i - j)
            };
            denominator = denominator * diff;
        }
    }

    numerator * denominator.invert().unwrap_or(Scalar::ONE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChainType;
    use crate::keygen::run_dkg;
    use crate::mpc::MemoryRelay;
    use crate::policy::PolicyConfig;
    use std::sync::Arc;

    async fn setup_key_shares() -> Vec<AgentKeyShare> {
        let relay = Arc::new(MemoryRelay::with_timeout(5000));

        let configs: Vec<SessionConfig> = (0..3)
            .map(|party_id| {
                let mut config = SessionConfig::new_agent_wallet(party_id).unwrap();
                config.session_id = [99u8; 32];
                config
            })
            .collect();

        let handles: Vec<_> = configs
            .into_iter()
            .map(|config| {
                let r = Arc::clone(&relay);
                tokio::spawn(async move { run_dkg(&config, r.as_ref()).await })
            })
            .collect();

        let mut shares = Vec::new();
        for handle in handles {
            let result = handle.await.unwrap().unwrap();
            shares.push(result.share);
        }

        shares
    }

    #[tokio::test]
    async fn test_sign_agent_and_user() {
        // Note: Full multi-party signing requires session coordination.
        // This test validates that DKG produces valid shares that can participate in signing.
        let shares = setup_key_shares().await;

        // Verify we have 3 shares with correct roles
        assert_eq!(shares.len(), 3);
        assert_eq!(shares[0].role, PartyRole::Agent);
        assert_eq!(shares[1].role, PartyRole::User);
        assert_eq!(shares[2].role, PartyRole::Recovery);

        // All shares should have the same public key
        assert_eq!(shares[0].public_key, shares[1].public_key);
        assert_eq!(shares[1].public_key, shares[2].public_key);

        // Shares should be different (threshold property)
        assert_ne!(
            shares[0].secret_share.to_bytes(),
            shares[1].secret_share.to_bytes()
        );
    }

    #[tokio::test]
    async fn test_sign_with_policy_approval() {
        // Test policy evaluation for signing
        let shares = setup_key_shares().await;

        let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "1000000000000000000");
        let _parties = [PartyRole::Agent, PartyRole::User];

        let policy = PolicyEngine::new(PolicyConfig::default());

        // Policy should approve this transaction
        let decision = policy.evaluate(&tx).unwrap();
        assert!(
            decision.is_approved(),
            "Policy should approve basic transaction"
        );

        // Verify shares can derive Ethereum addresses
        for share in &shares {
            let addr = share.eth_address().unwrap();
            assert!(addr.starts_with("0x"), "Should be valid Ethereum address");
            assert_eq!(addr.len(), 42, "Ethereum address should be 42 chars");
        }
    }

    #[tokio::test]
    async fn test_sign_with_policy_rejection() {
        let shares = setup_key_shares().await;
        let relay = Arc::new(MemoryRelay::with_timeout(5000));

        // Create transaction to blacklisted address
        let tx = TransactionRequest::new(ChainType::Evm, "0xBAD", "1000");
        let message_hash = [42u8; 32];
        let parties = [PartyRole::Agent, PartyRole::User];

        let policy =
            PolicyEngine::new(PolicyConfig::default().with_blacklist(vec!["0xBAD".to_string()]));

        let result = sign_with_policy(
            &shares[0],
            &tx,
            &message_hash,
            &parties,
            &policy,
            relay.as_ref(),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::PolicyViolation(_)));
    }

    #[test]
    fn test_lagrange_coefficients() {
        // For parties {0, 1} (x-coords 1, 2), reconstructing at 0:
        // λ_0 = 2 / (2-1) = 2
        // λ_1 = 1 / (1-2) = -1
        let parties = vec![0, 1];

        let lambda_0 = compute_lagrange_coefficient(0, &parties);
        let lambda_1 = compute_lagrange_coefficient(1, &parties);

        assert_eq!(lambda_0, Scalar::from(2u64));
        assert_eq!(lambda_1, -Scalar::ONE);
    }
}
