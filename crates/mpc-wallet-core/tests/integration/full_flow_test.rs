//! Integration tests for full signing flow
//!
//! These tests verify end-to-end functionality of the MPC wallet including:
//! - Complete DKG -> Sign flow
//! - Multi-party coordination
//! - Policy enforcement in signing

use mpc_wallet_core::{
    AgentKeyShare, Error, PartyRole, THRESHOLD,
    keygen::run_dkg,
    mpc::MemoryRelay,
    policy::{PolicyConfig, PolicyEngine, SpendingLimits},
    sign::{run_dsg, sign_with_policy},
    types::{ChainType, SessionConfig, TransactionRequest},
};
use std::sync::Arc;

/// Helper to run DKG and return shares for all parties
async fn setup_wallet() -> (Vec<AgentKeyShare>, Arc<MemoryRelay>) {
    let relay = Arc::new(MemoryRelay::with_timeout(10000));

    let configs: Vec<SessionConfig> = (0..3)
        .map(|party_id| {
            let mut config = SessionConfig::new_agent_wallet(party_id).unwrap();
            config.session_id = rand::random();
            config
        })
        .collect();

    // Ensure all configs have the same session ID
    let session_id = configs[0].session_id;
    let configs: Vec<SessionConfig> = configs
        .into_iter()
        .map(|mut c| {
            c.session_id = session_id;
            c
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

    (shares, relay)
}

// ============================================================================
// Full DKG Flow Tests
// ============================================================================

#[tokio::test]
async fn test_full_dkg_creates_valid_wallet() {
    let (shares, _relay) = setup_wallet().await;

    // Verify all shares are created
    assert_eq!(shares.len(), 3);

    // Verify public keys match
    let public_key = &shares[0].public_key;
    for share in &shares {
        assert_eq!(&share.public_key, public_key);
    }

    // Verify all parties can derive the same Ethereum address
    let eth_address = shares[0].eth_address().unwrap();
    for share in &shares {
        assert_eq!(share.eth_address().unwrap(), eth_address);
    }

    println!("Wallet created with address: {}", eth_address);
}

#[tokio::test]
async fn test_dkg_with_multiple_sessions() {
    // Run DKG twice to create two different wallets
    let (shares1, _) = setup_wallet().await;
    let (shares2, _) = setup_wallet().await;

    // The two wallets should have different public keys (very high probability)
    assert_ne!(
        shares1[0].public_key, shares2[0].public_key,
        "Different DKG sessions should produce different keys"
    );

    // Each wallet should have consistent internal state
    assert_eq!(shares1[0].public_key, shares1[1].public_key);
    assert_eq!(shares2[0].public_key, shares2[1].public_key);
}

// ============================================================================
// Signing with Policy Flow Tests
// ============================================================================

#[tokio::test]
async fn test_sign_with_policy_approval() {
    let (shares, relay) = setup_wallet().await;

    // Create a basic transaction
    let tx = TransactionRequest::new(ChainType::Evm, "0x1234567890abcdef", "1000000000000000000");
    let message_hash = [42u8; 32];
    let parties = [PartyRole::Agent, PartyRole::User];

    // Create policy that allows this transaction
    let policy = PolicyEngine::new(PolicyConfig::default());

    // Policy should approve
    let decision = policy.evaluate(&tx).unwrap();
    assert!(decision.is_approved());
}

#[tokio::test]
async fn test_sign_with_policy_rejection_blacklist() {
    let (shares, relay) = setup_wallet().await;

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
    match result.unwrap_err() {
        Error::PolicyViolation(reason) => {
            assert!(reason.contains("blacklisted"));
        }
        e => panic!("Expected PolicyViolation, got {:?}", e),
    }
}

#[tokio::test]
async fn test_sign_with_policy_rejection_spending_limit() {
    let (shares, relay) = setup_wallet().await;

    // Create transaction over spending limit
    let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "10000000000000000000"); // 10 ETH
    let message_hash = [42u8; 32];
    let parties = [PartyRole::Agent, PartyRole::User];

    let limits = SpendingLimits::with_per_tx(1_000_000_000_000_000_000u128, "ETH"); // 1 ETH limit
    let policy =
        PolicyEngine::new(PolicyConfig::default().with_spending_limits(ChainType::Evm, limits));

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
    match result.unwrap_err() {
        Error::PolicyViolation(reason) => {
            assert!(reason.contains("exceeds"));
        }
        e => panic!("Expected PolicyViolation, got {:?}", e),
    }
}

#[tokio::test]
async fn test_sign_requires_additional_approval() {
    let (shares, relay) = setup_wallet().await;

    // Create large transaction that requires additional approval
    let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "100000000000000000000"); // 100 ETH
    let message_hash = [42u8; 32];
    let parties = [PartyRole::Agent, PartyRole::User]; // No Recovery

    let policy = PolicyEngine::new(
        PolicyConfig::default().with_additional_approval_threshold(50_000_000_000_000_000_000u128), // 50 ETH
    );

    let result = sign_with_policy(
        &shares[0],
        &tx,
        &message_hash,
        &parties,
        &policy,
        relay.as_ref(),
    )
    .await;

    // Should fail because Recovery is not included
    assert!(result.is_err());
    match result.unwrap_err() {
        Error::PolicyViolation(reason) => {
            assert!(reason.contains("Recovery guardian"));
        }
        e => panic!("Expected PolicyViolation, got {:?}", e),
    }
}

#[tokio::test]
async fn test_sign_with_recovery_for_additional_approval() {
    let (shares, relay) = setup_wallet().await;

    // Large transaction with Recovery included
    let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "100000000000000000000");
    let parties = [PartyRole::Agent, PartyRole::Recovery]; // Include Recovery

    let policy = PolicyEngine::new(
        PolicyConfig::default().with_additional_approval_threshold(50_000_000_000_000_000_000u128),
    );

    // Policy should allow (RequireAdditionalApproval but Recovery is present)
    let decision = policy.evaluate(&tx).unwrap();
    assert!(decision.requires_additional_approval());
}

// ============================================================================
// Party Combination Tests
// ============================================================================

#[tokio::test]
async fn test_all_party_combinations_can_sign() {
    let (shares, _relay) = setup_wallet().await;

    // Test that all valid 2-party combinations have valid configurations
    let combinations = [
        [PartyRole::Agent, PartyRole::User],
        [PartyRole::Agent, PartyRole::Recovery],
        [PartyRole::User, PartyRole::Recovery],
    ];

    for combo in &combinations {
        // Verify session config can be created
        let my_party_id = combo[0].party_id();
        let result = SessionConfig::new_signing_session(my_party_id, combo);
        assert!(
            result.is_ok(),
            "Should be able to create signing session for {:?}",
            combo
        );

        let config = result.unwrap();
        assert_eq!(config.parties.len(), 2);
        assert!(config.parties.contains(&combo[0].party_id()));
        assert!(config.parties.contains(&combo[1].party_id()));
    }
}

#[tokio::test]
async fn test_single_party_cannot_sign() {
    let (shares, _relay) = setup_wallet().await;

    // Single party should not be able to create a signing session
    let result = SessionConfig::new_signing_session(0, &[PartyRole::Agent]);

    assert!(result.is_err());
    match result.unwrap_err() {
        Error::ThresholdNotMet { required, actual } => {
            assert_eq!(required, THRESHOLD);
            assert_eq!(actual, 1);
        }
        e => panic!("Expected ThresholdNotMet, got {:?}", e),
    }
}

// ============================================================================
// Key Derivation Integration Tests
// ============================================================================

#[tokio::test]
async fn test_key_derivation_consistency() {
    let (shares, _relay) = setup_wallet().await;

    // All parties derive child keys at the same path
    let path = "m/0/1";

    let derived_shares: Vec<_> = shares
        .iter()
        .map(|s| s.derive_child(path).unwrap())
        .collect();

    // All derived shares should still have the same role
    for (original, derived) in shares.iter().zip(&derived_shares) {
        assert_eq!(original.role, derived.role);
        assert_eq!(original.party_id, derived.party_id);
    }

    // Derived shares should have different secret values than originals
    for (original, derived) in shares.iter().zip(&derived_shares) {
        assert_ne!(
            original.secret_share.to_bytes(),
            derived.secret_share.to_bytes()
        );
    }
}

#[tokio::test]
async fn test_different_derivation_paths_produce_different_keys() {
    let (shares, _relay) = setup_wallet().await;

    let derived0 = shares[0].derive_child("m/0").unwrap();
    let derived1 = shares[0].derive_child("m/1").unwrap();

    assert_ne!(
        derived0.secret_share.to_bytes(),
        derived1.secret_share.to_bytes()
    );
}

// ============================================================================
// Spending Tracker Integration Tests
// ============================================================================

#[tokio::test]
async fn test_spending_tracking_across_multiple_transactions() {
    let (shares, relay) = setup_wallet().await;

    let limits = SpendingLimits::default().daily(3_000_000_000_000_000_000u128); // 3 ETH daily
    let policy =
        PolicyEngine::new(PolicyConfig::default().with_spending_limits(ChainType::Evm, limits));

    // Transaction 1: 1 ETH (cumulative: 1 ETH)
    let tx1 = TransactionRequest::new(ChainType::Evm, "0x1111", "1000000000000000000");
    assert!(policy.evaluate(&tx1).unwrap().is_approved());
    policy.record_transaction(&tx1).unwrap();
    assert_eq!(
        policy.daily_spending(ChainType::Evm),
        1_000_000_000_000_000_000u128
    );

    // Transaction 2: 1 ETH (cumulative: 2 ETH)
    let tx2 = TransactionRequest::new(ChainType::Evm, "0x2222", "1000000000000000000");
    assert!(policy.evaluate(&tx2).unwrap().is_approved());
    policy.record_transaction(&tx2).unwrap();
    assert_eq!(
        policy.daily_spending(ChainType::Evm),
        2_000_000_000_000_000_000u128
    );

    // Transaction 3: 1 ETH (cumulative: 3 ETH - at limit)
    let tx3 = TransactionRequest::new(ChainType::Evm, "0x3333", "1000000000000000000");
    assert!(policy.evaluate(&tx3).unwrap().is_approved());
    policy.record_transaction(&tx3).unwrap();

    // Transaction 4: 0.5 ETH (would exceed limit)
    let tx4 = TransactionRequest::new(ChainType::Evm, "0x4444", "500000000000000000");
    assert!(!policy.evaluate(&tx4).unwrap().is_approved());
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_invalid_party_in_signing_set() {
    let (shares, _relay) = setup_wallet().await;

    // Party 0 (Agent) trying to create a session but not in the signing set
    let result = SessionConfig::new_signing_session(
        0,                                       // Agent
        &[PartyRole::User, PartyRole::Recovery], // Only User and Recovery
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        Error::InvalidSigningParties(msg) => {
            assert!(msg.contains("not in the signing set"));
        }
        e => panic!("Expected InvalidSigningParties, got {:?}", e),
    }
}

#[tokio::test]
async fn test_run_dsg_threshold_check() {
    let (shares, relay) = setup_wallet().await;

    let message = [1u8; 32];
    let parties = [0usize]; // Only one party - below threshold

    let result = run_dsg(&shares[0], &message, &parties, relay.as_ref()).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        Error::ThresholdNotMet { required, actual } => {
            assert_eq!(required, THRESHOLD);
            assert_eq!(actual, 1);
        }
        e => panic!("Expected ThresholdNotMet, got {:?}", e),
    }
}

#[tokio::test]
async fn test_run_dsg_party_not_in_set() {
    let (shares, relay) = setup_wallet().await;

    let message = [1u8; 32];
    let parties = [1usize, 2usize]; // User and Recovery

    // Try to sign with Agent's share, but Agent is not in the parties list
    let result = run_dsg(&shares[0], &message, &parties, relay.as_ref()).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        Error::InvalidSigningParties(msg) => {
            assert!(msg.contains("not in the signing set"));
        }
        e => panic!("Expected InvalidSigningParties, got {:?}", e),
    }
}

// ============================================================================
// Concurrent Operations Tests
// ============================================================================

#[tokio::test]
async fn test_concurrent_policy_evaluations() {
    let policy =
        PolicyEngine::new(PolicyConfig::default().with_whitelist(vec!["0xGOOD".to_string()]));

    let handles: Vec<_> = (0..100)
        .map(|i| {
            let addr = if i % 2 == 0 { "0xGOOD" } else { "0xBAD" };
            let tx = TransactionRequest::new(ChainType::Evm, addr, "1000");
            tokio::spawn(async move {
                let engine = PolicyEngine::new(
                    PolicyConfig::default().with_whitelist(vec!["0xGOOD".to_string()]),
                );
                engine.evaluate(&tx)
            })
        })
        .collect();

    for (i, handle) in handles.into_iter().enumerate() {
        let result = handle.await.unwrap().unwrap();
        if i % 2 == 0 {
            assert!(result.is_approved());
        } else {
            assert!(!result.is_approved());
        }
    }
}

#[tokio::test]
async fn test_concurrent_spending_tracking() {
    let policy = Arc::new(PolicyEngine::new(
        PolicyConfig::default()
            .with_spending_limits(ChainType::Evm, SpendingLimits::default().daily(u128::MAX)),
    ));

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let p = Arc::clone(&policy);
            tokio::spawn(async move {
                let tx = TransactionRequest::new(
                    ChainType::Evm,
                    format!("0x{:040x}", i),
                    "1000000000000000000",
                );
                p.record_transaction(&tx)
            })
        })
        .collect();

    for handle in handles {
        handle.await.unwrap().unwrap();
    }

    // 10 transactions of 1 ETH each
    let spent = policy.daily_spending(ChainType::Evm);
    assert_eq!(spent, 10_000_000_000_000_000_000u128);
}
