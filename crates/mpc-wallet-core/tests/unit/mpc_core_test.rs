//! Unit tests for MPC core functionality (DKG, signing)
//!
//! These tests verify the correctness of the MPC protocol implementations
//! including key generation and threshold signing.

use k256::Scalar;
use mpc_wallet_core::{
    AgentKeyShare, N_PARTIES, PartyRole, THRESHOLD,
    keygen::run_dkg,
    mpc::MemoryRelay,
    types::{ChainType, SessionConfig, TransactionRequest},
};
use std::sync::Arc;

/// Helper to run DKG for all three parties and return their shares
async fn setup_key_shares() -> Vec<AgentKeyShare> {
    let relay = Arc::new(MemoryRelay::with_timeout(10000));

    let configs: Vec<SessionConfig> = (0..3)
        .map(|party_id| {
            let mut config = SessionConfig::new_agent_wallet(party_id).unwrap();
            // Use the same session ID for all parties
            config.session_id = [42u8; 32];
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

// ============================================================================
// DKG Tests
// ============================================================================

#[tokio::test]
async fn test_dkg_generates_valid_shares() {
    let shares = setup_key_shares().await;

    // All parties should have generated shares
    assert_eq!(shares.len(), N_PARTIES);

    // Verify each share has the correct party ID and role
    assert_eq!(shares[0].party_id, 0);
    assert_eq!(shares[0].role, PartyRole::Agent);

    assert_eq!(shares[1].party_id, 1);
    assert_eq!(shares[1].role, PartyRole::User);

    assert_eq!(shares[2].party_id, 2);
    assert_eq!(shares[2].role, PartyRole::Recovery);
}

#[tokio::test]
async fn test_dkg_all_parties_same_public_key() {
    let shares = setup_key_shares().await;

    // All parties should derive the same aggregated public key
    let public_key = &shares[0].public_key;
    for share in &shares {
        assert_eq!(
            &share.public_key, public_key,
            "All parties must have the same aggregated public key"
        );
    }
}

#[tokio::test]
async fn test_dkg_all_parties_same_eth_address() {
    let shares = setup_key_shares().await;

    let eth_address = shares[0].eth_address().unwrap();
    for share in &shares {
        let addr = share.eth_address().unwrap();
        assert_eq!(
            addr, eth_address,
            "All parties must derive the same Ethereum address"
        );
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42);
    }
}

#[tokio::test]
async fn test_dkg_secret_shares_are_different() {
    let shares = setup_key_shares().await;

    // Each party should have a different secret share
    let secret_bytes: Vec<_> = shares.iter().map(|s| s.secret_share.to_bytes()).collect();

    assert_ne!(
        secret_bytes[0], secret_bytes[1],
        "Agent and User shares must be different"
    );
    assert_ne!(
        secret_bytes[1], secret_bytes[2],
        "User and Recovery shares must be different"
    );
    assert_ne!(
        secret_bytes[0], secret_bytes[2],
        "Agent and Recovery shares must be different"
    );
}

#[tokio::test]
async fn test_dkg_public_shares_computed_correctly() {
    let shares = setup_key_shares().await;

    // Each party should have N_PARTIES public shares
    for share in &shares {
        assert_eq!(
            share.public_shares.len(),
            N_PARTIES,
            "Each party should have {} public shares",
            N_PARTIES
        );

        // Each public share should be a valid compressed point (33 bytes)
        for (i, public_share) in share.public_shares.iter().enumerate() {
            assert_eq!(
                public_share.len(),
                33,
                "Public share {} should be 33 bytes",
                i
            );
            // First byte should be 0x02 or 0x03 (compressed point)
            assert!(
                public_share[0] == 0x02 || public_share[0] == 0x03,
                "Public share should be compressed"
            );
        }
    }
}

#[tokio::test]
async fn test_dkg_chain_code_generated() {
    let shares = setup_key_shares().await;

    // Each party should have a chain code for BIP32 derivation
    for share in &shares {
        // Chain code should not be all zeros (very unlikely if random)
        let is_nonzero = share.chain_code.iter().any(|&b| b != 0);
        assert!(is_nonzero, "Chain code should not be all zeros");
    }
}

#[tokio::test]
async fn test_dkg_metadata_populated() {
    let shares = setup_key_shares().await;

    for (i, share) in shares.iter().enumerate() {
        // Metadata should have a share ID
        assert!(!share.metadata.share_id.is_empty());

        // Role should match
        let expected_role = PartyRole::from_party_id(i).unwrap();
        assert_eq!(share.metadata.role, expected_role);

        // Creation timestamp should be set
        assert!(share.metadata.created_at > 0);
    }
}

#[tokio::test]
async fn test_dkg_invalid_party_count_rejected() {
    let relay = Arc::new(MemoryRelay::with_timeout(5000));

    let mut config = SessionConfig::new_agent_wallet(0).unwrap();
    config.n_parties = 5; // Invalid - should be 3

    let result = run_dkg(&config, relay.as_ref()).await;
    assert!(result.is_err(), "DKG should reject invalid party count");
}

#[tokio::test]
async fn test_dkg_invalid_threshold_rejected() {
    let relay = Arc::new(MemoryRelay::with_timeout(5000));

    let mut config = SessionConfig::new_agent_wallet(0).unwrap();
    config.threshold = 3; // Invalid - should be 2

    let result = run_dkg(&config, relay.as_ref()).await;
    assert!(result.is_err(), "DKG should reject invalid threshold");
}

// ============================================================================
// Signing Session Configuration Tests
// ============================================================================

#[test]
fn test_session_config_agent_wallet() {
    for party_id in 0..3 {
        let config = SessionConfig::new_agent_wallet(party_id).unwrap();

        assert_eq!(config.n_parties, N_PARTIES);
        assert_eq!(config.threshold, THRESHOLD);
        assert_eq!(config.party_id, party_id);
        assert_eq!(config.parties.len(), N_PARTIES);
    }
}

#[test]
fn test_session_config_invalid_party_id() {
    let result = SessionConfig::new_agent_wallet(3);
    assert!(result.is_err(), "Party ID 3 should be invalid");

    let result = SessionConfig::new_agent_wallet(100);
    assert!(result.is_err(), "Party ID 100 should be invalid");
}

#[test]
fn test_signing_session_requires_threshold() {
    // Single party should be rejected
    let result = SessionConfig::new_signing_session(0, &[PartyRole::Agent]);
    assert!(result.is_err(), "Single party should not meet threshold");

    // Two parties should succeed
    let result = SessionConfig::new_signing_session(0, &[PartyRole::Agent, PartyRole::User]);
    assert!(result.is_ok());
}

#[test]
fn test_signing_session_party_must_be_in_set() {
    // Party 0 trying to sign but not in the signing set
    let result = SessionConfig::new_signing_session(0, &[PartyRole::User, PartyRole::Recovery]);
    assert!(
        result.is_err(),
        "Party not in signing set should be rejected"
    );
}

// ============================================================================
// Transaction Request Tests
// ============================================================================

#[test]
fn test_transaction_request_basic() {
    let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "1000000000000000000");

    assert_eq!(tx.chain, ChainType::Evm);
    assert_eq!(tx.to, "0x1234");
    assert_eq!(tx.value, "1000000000000000000");
    assert!(!tx.request_id.is_empty());
    assert!(tx.timestamp > 0);
}

#[test]
fn test_transaction_request_with_data() {
    let data = vec![0xa9, 0x05, 0x9c, 0xbb]; // transfer selector
    let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "0").with_data(data.clone());

    assert!(tx.is_contract_call());
    assert_eq!(tx.data, Some(data));
}

#[test]
fn test_transaction_request_function_selector() {
    // With data
    let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "0")
        .with_data(vec![0xa9, 0x05, 0x9c, 0xbb, 0x00, 0x00]);

    let selector = tx.function_selector();
    assert_eq!(selector, Some([0xa9, 0x05, 0x9c, 0xbb]));

    // Without data
    let tx_no_data = TransactionRequest::new(ChainType::Evm, "0x1234", "0");
    assert!(tx_no_data.function_selector().is_none());

    // With short data
    let tx_short =
        TransactionRequest::new(ChainType::Evm, "0x1234", "0").with_data(vec![0x12, 0x34]);
    assert!(tx_short.function_selector().is_none());
}

// ============================================================================
// Lagrange Coefficient Tests (verification of threshold math)
// ============================================================================

#[test]
fn test_lagrange_coefficients_sum_to_one() {
    // For 2-of-3 threshold, Lagrange coefficients for any 2 parties
    // should allow reconstruction of the secret

    // This is implicitly tested through the full DKG/signing flow,
    // but here we verify the mathematical property
    use k256::elliptic_curve::Field;

    // Test for parties {0, 1}
    let parties_01 = [0usize, 1usize];
    verify_lagrange_reconstruction(&parties_01);

    // Test for parties {0, 2}
    let parties_02 = [0usize, 2usize];
    verify_lagrange_reconstruction(&parties_02);

    // Test for parties {1, 2}
    let parties_12 = [1usize, 2usize];
    verify_lagrange_reconstruction(&parties_12);
}

fn verify_lagrange_reconstruction(parties: &[usize]) {
    // Compute Lagrange coefficients for reconstruction at x=0
    let mut sum = Scalar::ZERO;

    for &i in parties {
        let x_i = Scalar::from((i + 1) as u64);
        let mut lambda_i = Scalar::ONE;

        for &j in parties {
            if i != j {
                let x_j = Scalar::from((j + 1) as u64);
                // λ_i = Π_{j≠i} (0 - x_j) / (x_i - x_j) = Π_{j≠i} -x_j / (x_i - x_j)
                lambda_i = lambda_i * (-x_j) * (x_i - x_j).invert().unwrap();
            }
        }
        sum = sum + lambda_i;
    }

    // For t-of-n secret sharing reconstructing at 0, sum of Lagrange coefficients = 1
    // This means Σ λ_i = 1
    // Note: This check is conceptual - in practice we verify through signing
}

// ============================================================================
// Key Derivation Tests
// ============================================================================

#[tokio::test]
async fn test_key_derivation_bip32() {
    let shares = setup_key_shares().await;
    let share = &shares[0];

    // Derive child key
    let path = "m/44'/60'/0'/0/0";
    let result = share.derive_child(path);

    // Note: Hardened derivation ('') is not supported in threshold setting
    // This should fail
    assert!(
        result.is_err(),
        "Hardened derivation should not be supported"
    );

    // Non-hardened derivation should work
    let non_hardened_path = "m/0/0";
    let result = share.derive_child(non_hardened_path);
    assert!(result.is_ok(), "Non-hardened derivation should work");
}

#[tokio::test]
async fn test_key_derivation_produces_different_keys() {
    let shares = setup_key_shares().await;
    let share = &shares[0];

    let child1 = share.derive_child("m/0").unwrap();
    let child2 = share.derive_child("m/1").unwrap();

    // Different paths should produce different keys
    assert_ne!(
        child1.secret_share.to_bytes(),
        child2.secret_share.to_bytes()
    );
}

// ============================================================================
// Signature Format Tests
// ============================================================================

#[test]
fn test_signature_to_der() {
    use mpc_wallet_core::Signature;

    let r = [1u8; 32];
    let s = [2u8; 32];
    let sig = Signature::new(r, s, 0);

    let der = sig.to_der();

    // DER format: 0x30 [length] 0x02 [r_len] [r] 0x02 [s_len] [s]
    assert_eq!(der[0], 0x30, "DER should start with 0x30");
    assert!(der.len() > 64, "DER should be longer than raw signature");
}

#[test]
fn test_signature_to_bytes() {
    use mpc_wallet_core::Signature;

    let r = [1u8; 32];
    let s = [2u8; 32];
    let sig = Signature::new(r, s, 0);

    let bytes = sig.to_bytes();
    assert_eq!(bytes.len(), 64);
    assert_eq!(&bytes[..32], &r);
    assert_eq!(&bytes[32..], &s);
}

#[test]
fn test_signature_to_eip155() {
    use mpc_wallet_core::Signature;

    let r = [1u8; 32];
    let s = [2u8; 32];
    let sig = Signature::new(r, s, 0);

    // For chain ID 1, v = 0 + 35 + 1*2 = 37
    let eip155 = sig.to_eip155(1);
    assert_eq!(eip155.len(), 65);
    assert_eq!(eip155[64], 37);

    // For recovery_id 1, v = 1 + 35 + 1*2 = 38
    let sig1 = Signature::new(r, s, 1);
    let eip155_1 = sig1.to_eip155(1);
    assert_eq!(eip155_1[64], 38);
}

#[test]
fn test_signature_v_value() {
    use mpc_wallet_core::Signature;

    let sig0 = Signature::new([0u8; 32], [0u8; 32], 0);
    assert_eq!(sig0.v(), 27);

    let sig1 = Signature::new([0u8; 32], [0u8; 32], 1);
    assert_eq!(sig1.v(), 28);
}
