//! Proactive key share refresh
//!
//! Key share refresh allows updating the secret shares while maintaining
//! the same public key and threshold. This is useful for:
//! - Recovering from potential share compromise
//! - Regular security maintenance
//! - Refreshing shares after personnel changes

use crate::mpc::Relay;
use crate::{AgentKeyShare, Error, Result, SessionConfig, THRESHOLD};
use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{Field, bigint::U256, ops::Reduce, sec1::ToEncodedPoint},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument};

/// Refresh message for Round 1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshRound1Message {
    pub party_id: usize,
    /// Commitments to the refresh polynomial (which has 0 as the free term)
    pub commitments: Vec<Vec<u8>>,
}

/// Refresh message for Round 2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshRound2Message {
    pub from: usize,
    pub to: usize,
    /// Refresh share
    pub share: Vec<u8>,
}

/// Refresh key shares while keeping the same public key
///
/// This implements a proactive refresh protocol where parties generate
/// new polynomial with 0 as the free term. Adding these to existing
/// shares produces new shares that still combine to the same secret.
///
/// # Arguments
/// * `share` - Current key share
/// * `config` - Session configuration
/// * `relay` - Message relay for communication
///
/// # Returns
/// Updated key share with refreshed secret
#[instrument(skip(share, relay))]
pub async fn refresh_shares<R: Relay>(
    share: &AgentKeyShare,
    config: &SessionConfig,
    relay: &R,
) -> Result<AgentKeyShare> {
    info!(
        party_id = config.party_id,
        role = %config.role,
        "Starting key share refresh"
    );

    // ============ Round 1: Generate refresh polynomial and commit ============
    debug!("Refresh Round 1: Generating refresh polynomial");

    // Generate polynomial with 0 as free term: f(x) = 0 + a_1*x + ... + a_{t-1}*x^{t-1}
    let (refresh_poly, commitments) = generate_refresh_polynomial(THRESHOLD)?;

    let round1_msg = RefreshRound1Message {
        party_id: config.party_id,
        commitments,
    };
    relay.broadcast(&config.session_id, 1, &round1_msg).await?;

    // Collect commitments
    let all_commitments = relay
        .collect_broadcasts::<RefreshRound1Message>(&config.session_id, 1, config.n_parties)
        .await?;

    // ============ Round 2: Send refresh shares ============
    debug!("Refresh Round 2: Sending refresh shares");

    for party_id in &config.parties {
        if *party_id == config.party_id {
            continue;
        }

        let refresh_share = evaluate_refresh_polynomial(&refresh_poly, *party_id as u64 + 1);

        let round2_msg = RefreshRound2Message {
            from: config.party_id,
            to: *party_id,
            share: refresh_share.to_bytes().to_vec(),
        };

        relay
            .send_direct(&config.session_id, 2, *party_id, &round2_msg)
            .await?;
    }

    // Collect refresh shares
    let received_shares = relay
        .collect_direct::<RefreshRound2Message>(
            &config.session_id,
            2,
            config.party_id,
            config.n_parties - 1,
        )
        .await?;

    // ============ Round 3: Verify and apply refresh ============
    debug!("Refresh Round 3: Verifying and applying refresh");

    // Verify received refresh shares
    for refresh_msg in &received_shares {
        let sender_commitments = all_commitments
            .iter()
            .find(|c| c.party_id == refresh_msg.from)
            .ok_or_else(|| Error::VerificationFailed("Missing commitment".into()))?;

        verify_refresh_share(
            refresh_msg,
            &sender_commitments.commitments,
            config.party_id,
        )?;
    }

    // Compute new secret share = old share + own refresh + received refreshes
    let my_refresh = evaluate_refresh_polynomial(&refresh_poly, config.party_id as u64 + 1);
    let mut new_secret = share.secret_share + my_refresh;

    for refresh_msg in &received_shares {
        let refresh_bytes: [u8; 32] = refresh_msg
            .share
            .clone()
            .try_into()
            .map_err(|_| Error::Deserialization("Invalid share length".into()))?;
        let refresh = <Scalar as Reduce<U256>>::reduce_bytes(&refresh_bytes.into());
        new_secret = new_secret + refresh;
    }

    // Create new key share with refreshed secret
    let mut new_share = share.clone();
    new_share.secret_share = new_secret;
    new_share.metadata.last_refreshed_at = Some(chrono::Utc::now().timestamp());

    info!(
        party_id = config.party_id,
        "Key share refresh completed successfully"
    );

    Ok(new_share)
}

/// Generate a refresh polynomial with 0 as the free term
fn generate_refresh_polynomial(threshold: usize) -> Result<(Vec<Scalar>, Vec<Vec<u8>>)> {
    let mut rng = OsRng;
    let mut coefficients = Vec::with_capacity(threshold);
    let mut commitments = Vec::with_capacity(threshold);

    // First coefficient is 0 (so shares sum to 0, preserving the secret)
    coefficients.push(Scalar::ZERO);
    // Commitment to 0 is the point at infinity, but we use the identity point
    commitments.push(
        ProjectivePoint::IDENTITY
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
    );

    // Random coefficients for higher terms
    for _ in 1..threshold {
        let coef = Scalar::random(&mut rng);
        let commitment = (ProjectivePoint::GENERATOR * coef).to_affine();

        coefficients.push(coef);
        commitments.push(commitment.to_encoded_point(true).as_bytes().to_vec());
    }

    Ok((coefficients, commitments))
}

/// Evaluate refresh polynomial at a point
fn evaluate_refresh_polynomial(coefficients: &[Scalar], x: u64) -> Scalar {
    let x_scalar = Scalar::from(x);
    let mut result = Scalar::ZERO;
    let mut x_power = Scalar::ONE;

    for coef in coefficients {
        result = result + (*coef * x_power);
        x_power = x_power * x_scalar;
    }

    result
}

/// Verify a refresh share against commitments
fn verify_refresh_share(
    refresh_msg: &RefreshRound2Message,
    commitments: &[Vec<u8>],
    my_id: usize,
) -> Result<()> {
    use k256::{AffinePoint, elliptic_curve::sec1::FromEncodedPoint};

    let share_bytes: [u8; 32] = refresh_msg
        .share
        .clone()
        .try_into()
        .map_err(|_| Error::Deserialization("Invalid share length".into()))?;
    let share = <Scalar as Reduce<U256>>::reduce_bytes(&share_bytes.into());

    let expected = ProjectivePoint::GENERATOR * share;

    let x = (my_id + 1) as u64;
    let mut actual = ProjectivePoint::IDENTITY;
    let mut x_power = Scalar::ONE;
    let x_scalar = Scalar::from(x);

    for commitment_bytes in commitments {
        // Handle the identity point (commitment to 0)
        if commitment_bytes.len() == 1 && commitment_bytes[0] == 0 {
            // Point at infinity, contributes nothing
            x_power = x_power * x_scalar;
            continue;
        }

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
            "Refresh share from party {} does not match commitment",
            refresh_msg.from
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_refresh_polynomial_zero_free_term() {
        let (poly, _) = generate_refresh_polynomial(2).unwrap();

        // Free term should be zero
        assert_eq!(poly[0], Scalar::ZERO);

        // At x=0, polynomial should evaluate to 0
        let _at_zero = evaluate_refresh_polynomial(&poly, 0);
        // Actually x=0 gives the free term, which is 0
        // But we use x=party_id+1, so x is never 0
    }

    #[test]
    fn test_refresh_shares_sum_to_zero() {
        // If we evaluate at points 1, 2, 3 and sum with Lagrange coefficients,
        // we should get 0 (since the secret is 0)
        let (poly, _) = generate_refresh_polynomial(2).unwrap();

        let s1 = evaluate_refresh_polynomial(&poly, 1);
        let s2 = evaluate_refresh_polynomial(&poly, 2);
        let _s3 = evaluate_refresh_polynomial(&poly, 3);

        // Lagrange coefficients for 2-of-3 at points {1, 2} to reconstruct at 0
        // λ_1 = 2/(2-1) = 2
        // λ_2 = 1/(1-2) = -1
        let lambda_1 = Scalar::from(2u64);
        let lambda_2 = -Scalar::ONE;

        let reconstructed = s1 * lambda_1 + s2 * lambda_2;
        assert_eq!(reconstructed, Scalar::ZERO);
    }
}
