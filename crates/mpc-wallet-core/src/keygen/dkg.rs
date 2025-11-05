//! DKG protocol implementation for 2-of-3 agent wallet

use super::{DkgRound1Message, DkgRound2Message, KeygenResult};
use crate::mpc::Relay;
use crate::types::{ChainType, KeyShareMetadata};
use crate::{AgentKeyShare, Error, N_PARTIES, Result, SessionConfig, THRESHOLD};
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
use std::collections::HashMap;
use tracing::{debug, info, instrument};

/// Run the distributed key generation protocol for 2-of-3 agent wallet
///
/// This implements a Feldman VSS-based DKG protocol where each party:
/// 1. Generates a random polynomial of degree t-1 (t=2)
/// 2. Commits to the polynomial coefficients
/// 3. Sends secret shares to other parties
/// 4. Verifies received shares against commitments
/// 5. Combines shares to get final secret share
///
/// # Arguments
/// * `config` - Session configuration with party ID and role
/// * `relay` - Message relay for communication
///
/// # Returns
/// The keygen result containing the party's key share
#[instrument(skip(relay))]
pub async fn run_dkg<R: Relay>(config: &SessionConfig, relay: &R) -> Result<KeygenResult> {
    // Validate configuration
    if config.n_parties != N_PARTIES {
        return Err(Error::InvalidConfig(format!(
            "Agent wallet requires exactly {} parties, got {}",
            N_PARTIES, config.n_parties
        )));
    }
    if config.threshold != THRESHOLD {
        return Err(Error::InvalidConfig(format!(
            "Agent wallet requires threshold of {}, got {}",
            THRESHOLD, config.threshold
        )));
    }

    info!(
        party_id = config.party_id,
        role = %config.role,
        "Starting DKG for agent wallet"
    );

    // ============ Round 1: Commitment ============
    debug!("DKG Round 1: Generating secret polynomial and commitments");

    let (secret_poly, commitments) = generate_secret_polynomial(config.threshold)?;

    // Broadcast commitment
    let commitment_msg = DkgRound1Message {
        party_id: config.party_id,
        commitments: commitments.clone(),
    };
    relay
        .broadcast(&config.session_id, 1, &commitment_msg)
        .await?;

    // Collect commitments from all parties
    let all_commitments = relay
        .collect_broadcasts::<DkgRound1Message>(&config.session_id, 1, config.n_parties)
        .await?;

    // Sort commitments by party ID for consistency
    let mut sorted_commitments = all_commitments;
    sorted_commitments.sort_by_key(|m| m.party_id);

    // ============ Round 2: Secret Sharing ============
    debug!("DKG Round 2: Sending secret shares to other parties");

    for party_id in &config.parties {
        if *party_id == config.party_id {
            continue;
        }

        // Evaluate polynomial at party's x-coordinate (party_id + 1)
        let share = evaluate_polynomial(&secret_poly, *party_id as u64 + 1);

        let share_msg = DkgRound2Message {
            from: config.party_id,
            to: *party_id,
            share: share.to_bytes().to_vec(),
        };

        relay
            .send_direct(&config.session_id, 2, *party_id, &share_msg)
            .await?;
    }

    // Collect shares from other parties
    let received_shares = relay
        .collect_direct::<DkgRound2Message>(
            &config.session_id,
            2,
            config.party_id,
            config.n_parties - 1,
        )
        .await?;

    // ============ Round 3: Verification and Combination ============
    debug!("DKG Round 3: Verifying shares and computing final key share");

    // Verify received shares against commitments
    for share_msg in &received_shares {
        let sender_commitments = sorted_commitments
            .iter()
            .find(|c| c.party_id == share_msg.from)
            .ok_or_else(|| Error::VerificationFailed("Missing commitment".into()))?;

        verify_share(share_msg, &sender_commitments.commitments, config.party_id)?;
    }

    // Compute final secret share = own share + received shares
    let my_share = evaluate_polynomial(&secret_poly, config.party_id as u64 + 1);
    let mut final_secret = my_share;

    for share_msg in &received_shares {
        let share_bytes: [u8; 32] = share_msg
            .share
            .clone()
            .try_into()
            .map_err(|_| Error::Deserialization("Invalid share length".into()))?;
        let share = <Scalar as Reduce<U256>>::reduce_bytes(&share_bytes.into());
        final_secret = final_secret + share;
    }

    // Compute aggregated public key
    let public_key = compute_public_key(&sorted_commitments)?;

    // Compute public shares for all parties
    let public_shares = compute_public_shares(&sorted_commitments, config.n_parties)?;

    // Generate chain code for BIP32 derivation
    let chain_code: [u8; 32] = rand::random();

    // Create the key share
    let key_share = AgentKeyShare {
        party_id: config.party_id,
        role: config.role,
        secret_share: final_secret,
        public_key: public_key.clone(),
        public_shares,
        chain_code,
        metadata: KeyShareMetadata {
            share_id: uuid::Uuid::new_v4().to_string(),
            role: config.role,
            created_at: chrono::Utc::now().timestamp(),
            last_refreshed_at: None,
            addresses: HashMap::new(),
            label: Some(format!("{} key share", config.role)),
        },
    };

    // Compute and add addresses
    let mut addresses = HashMap::new();
    if let Ok(eth_addr) = key_share.eth_address() {
        addresses.insert(ChainType::Evm, eth_addr);
    }

    let mut key_share = key_share;
    key_share.metadata.addresses = addresses;

    info!(
        party_id = config.party_id,
        role = %config.role,
        public_key = hex::encode(&public_key),
        "DKG completed successfully"
    );

    KeygenResult::new(key_share)
}

/// Generate a random secret polynomial of degree t-1
fn generate_secret_polynomial(threshold: usize) -> Result<(Vec<Scalar>, Vec<Vec<u8>>)> {
    let mut rng = OsRng;
    let mut coefficients = Vec::with_capacity(threshold);
    let mut commitments = Vec::with_capacity(threshold);

    for _ in 0..threshold {
        let coef = Scalar::random(&mut rng);
        let commitment = (ProjectivePoint::GENERATOR * coef).to_affine();

        coefficients.push(coef);
        commitments.push(commitment.to_encoded_point(true).as_bytes().to_vec());
    }

    Ok((coefficients, commitments))
}

/// Evaluate polynomial at a point using Horner's method
fn evaluate_polynomial(coefficients: &[Scalar], x: u64) -> Scalar {
    let x_scalar = Scalar::from(x);
    let mut result = Scalar::ZERO;
    let mut x_power = Scalar::ONE;

    for coef in coefficients {
        result = result + (*coef * x_power);
        x_power = x_power * x_scalar;
    }

    result
}

/// Verify a received share against the sender's commitments
fn verify_share(share_msg: &DkgRound2Message, commitments: &[Vec<u8>], my_id: usize) -> Result<()> {
    let share_bytes: [u8; 32] = share_msg
        .share
        .clone()
        .try_into()
        .map_err(|_| Error::Deserialization("Invalid share length".into()))?;
    let share = <Scalar as Reduce<U256>>::reduce_bytes(&share_bytes.into());

    // Expected: g^share
    let expected = ProjectivePoint::GENERATOR * share;

    // Actual: Product of (C_j)^(x^j) where x = my_id + 1
    let x = (my_id + 1) as u64;
    let mut actual = ProjectivePoint::IDENTITY;
    let mut x_power = Scalar::ONE;
    let x_scalar = Scalar::from(x);

    for commitment_bytes in commitments {
        let point = k256::EncodedPoint::from_bytes(commitment_bytes)
            .map_err(|e| Error::VerificationFailed(e.to_string()))?;
        let affine_opt = AffinePoint::from_encoded_point(&point);
        let affine: AffinePoint = Option::<AffinePoint>::from(affine_opt)
            .ok_or_else(|| Error::VerificationFailed("Invalid commitment point".into()))?;
        let commitment = ProjectivePoint::from(affine);

        actual = actual + (commitment * x_power);
        x_power = x_power * x_scalar;
    }

    if expected != actual {
        return Err(Error::VerificationFailed(format!(
            "Share from party {} does not match commitment",
            share_msg.from
        )));
    }

    Ok(())
}

/// Compute the aggregated public key from all parties' commitments
fn compute_public_key(all_commitments: &[DkgRound1Message]) -> Result<Vec<u8>> {
    let mut public_key = ProjectivePoint::IDENTITY;

    for commitment_msg in all_commitments {
        if commitment_msg.commitments.is_empty() {
            return Err(Error::VerificationFailed("Empty commitments".into()));
        }

        // The first commitment (C_0) is the commitment to the free term (the secret)
        let point = k256::EncodedPoint::from_bytes(&commitment_msg.commitments[0])
            .map_err(|e| Error::VerificationFailed(e.to_string()))?;
        let affine_opt = AffinePoint::from_encoded_point(&point);
        let affine: AffinePoint = Option::<AffinePoint>::from(affine_opt)
            .ok_or_else(|| Error::VerificationFailed("Invalid commitment point".into()))?;
        let commitment = ProjectivePoint::from(affine);

        public_key = public_key + commitment;
    }

    let encoded = public_key.to_affine().to_encoded_point(true);
    Ok(encoded.as_bytes().to_vec())
}

/// Compute public key shares for all parties (for signature verification)
fn compute_public_shares(
    all_commitments: &[DkgRound1Message],
    n_parties: usize,
) -> Result<Vec<Vec<u8>>> {
    let mut public_shares = Vec::with_capacity(n_parties);

    for party_id in 0..n_parties {
        let x = (party_id + 1) as u64;
        let mut public_share = ProjectivePoint::IDENTITY;

        for commitment_msg in all_commitments {
            let mut x_power = Scalar::ONE;
            let x_scalar = Scalar::from(x);

            for commitment_bytes in &commitment_msg.commitments {
                let point = k256::EncodedPoint::from_bytes(commitment_bytes)
                    .map_err(|e| Error::VerificationFailed(e.to_string()))?;
                let affine_opt = AffinePoint::from_encoded_point(&point);
                let affine: AffinePoint = Option::<AffinePoint>::from(affine_opt)
                    .ok_or_else(|| Error::VerificationFailed("Invalid commitment point".into()))?;
                let commitment = ProjectivePoint::from(affine);

                public_share = public_share + (commitment * x_power);
                x_power = x_power * x_scalar;
            }
        }

        let encoded = public_share.to_affine().to_encoded_point(true);
        public_shares.push(encoded.as_bytes().to_vec());
    }

    Ok(public_shares)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PartyRole;
    use crate::mpc::MemoryRelay;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_dkg_full_protocol() {
        let relay = Arc::new(MemoryRelay::with_timeout(5000));

        // Create configurations for all three parties
        let configs: Vec<SessionConfig> = (0..3)
            .map(|party_id| {
                let mut config = SessionConfig::new_agent_wallet(party_id).unwrap();
                // Use the same session ID for all parties
                config.session_id = [42u8; 32];
                config
            })
            .collect();

        // Run DKG for all parties concurrently
        let handles: Vec<_> = configs
            .into_iter()
            .map(|config| {
                let r = Arc::clone(&relay);
                tokio::spawn(async move { run_dkg(&config, r.as_ref()).await })
            })
            .collect();

        // Collect results
        let mut results = Vec::new();
        for handle in handles {
            let result = handle.await.unwrap().unwrap();
            results.push(result);
        }

        // Verify all parties computed the same public key
        let public_key = &results[0].public_key;
        for result in &results {
            assert_eq!(
                &result.public_key, public_key,
                "All parties should have the same public key"
            );
        }

        // Verify all parties have different secret shares
        let secret_shares: Vec<_> = results.iter().map(|r| r.share.secret_share).collect();
        assert_ne!(
            secret_shares[0], secret_shares[1],
            "Parties should have different secret shares"
        );
        assert_ne!(
            secret_shares[1], secret_shares[2],
            "Parties should have different secret shares"
        );

        // Verify roles are assigned correctly
        assert_eq!(results[0].share.role, PartyRole::Agent);
        assert_eq!(results[1].share.role, PartyRole::User);
        assert_eq!(results[2].share.role, PartyRole::Recovery);

        // Verify Ethereum addresses match
        for result in &results {
            assert_eq!(
                result.eth_address, results[0].eth_address,
                "All parties should derive the same Ethereum address"
            );
        }
    }

    #[test]
    fn test_polynomial_evaluation() {
        // Test polynomial: f(x) = 5 + 3x (coefficients: [5, 3])
        let coefficients = vec![Scalar::from(5u64), Scalar::from(3u64)];

        // f(1) = 5 + 3 = 8
        let result1 = evaluate_polynomial(&coefficients, 1);
        assert_eq!(result1, Scalar::from(8u64));

        // f(2) = 5 + 6 = 11
        let result2 = evaluate_polynomial(&coefficients, 2);
        assert_eq!(result2, Scalar::from(11u64));

        // f(3) = 5 + 9 = 14
        let result3 = evaluate_polynomial(&coefficients, 3);
        assert_eq!(result3, Scalar::from(14u64));
    }
}
