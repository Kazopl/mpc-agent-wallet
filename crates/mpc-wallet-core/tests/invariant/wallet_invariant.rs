//! Invariant tests for MPC Agent Wallet
//!
//! These tests verify critical invariants that must always hold:
//! - Key share consistency across parties
//! - Threshold properties
//! - Policy enforcement consistency
//! - Cryptographic correctness

use mpc_wallet_core::{
    AgentKeyShare, N_PARTIES, PartyRole, THRESHOLD,
    keygen::run_dkg,
    mpc::MemoryRelay,
    policy::{PolicyConfig, PolicyDecision, PolicyEngine, SpendingLimits},
    types::{ChainType, SessionConfig, TransactionRequest},
};
use std::sync::Arc;

/// Helper to run DKG and get all shares
async fn setup_shares() -> Vec<AgentKeyShare> {
    let relay = Arc::new(MemoryRelay::with_timeout(10000));
    let session_id: [u8; 32] = rand::random();

    let configs: Vec<SessionConfig> = (0..3)
        .map(|party_id| {
            let mut config = SessionConfig::new_agent_wallet(party_id).unwrap();
            config.session_id = session_id;
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
// Key Share Invariants
// ============================================================================

/// INVARIANT: All parties must derive the same aggregated public key
#[tokio::test]
async fn invariant_same_public_key_all_parties() {
    for _ in 0..5 {
        // Run multiple times to catch race conditions
        let shares = setup_shares().await;

        let public_key = &shares[0].public_key;
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(
                &share.public_key, public_key,
                "Party {} has different public key",
                i
            );
        }
    }
}

/// INVARIANT: Each party must have a unique secret share
#[tokio::test]
async fn invariant_unique_secret_shares() {
    let shares = setup_shares().await;

    let secret_bytes: Vec<_> = shares.iter().map(|s| s.secret_share.to_bytes()).collect();

    // All pairs must be different
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            assert_ne!(
                secret_bytes[i], secret_bytes[j],
                "Parties {} and {} have same secret share",
                i, j
            );
        }
    }
}

/// INVARIANT: Party roles must be correctly assigned
#[tokio::test]
async fn invariant_correct_party_roles() {
    let shares = setup_shares().await;

    assert_eq!(shares[0].role, PartyRole::Agent, "Party 0 should be Agent");
    assert_eq!(shares[1].role, PartyRole::User, "Party 1 should be User");
    assert_eq!(
        shares[2].role,
        PartyRole::Recovery,
        "Party 2 should be Recovery"
    );
}

/// INVARIANT: Party IDs must match indices
#[tokio::test]
async fn invariant_correct_party_ids() {
    let shares = setup_shares().await;

    for (expected_id, share) in shares.iter().enumerate() {
        assert_eq!(
            share.party_id, expected_id,
            "Party {} has wrong party_id {}",
            expected_id, share.party_id
        );
    }
}

/// INVARIANT: All parties must derive the same Ethereum address
#[tokio::test]
async fn invariant_same_eth_address() {
    let shares = setup_shares().await;

    let eth_address = shares[0].eth_address().unwrap();

    // Verify format
    assert!(eth_address.starts_with("0x"));
    assert_eq!(eth_address.len(), 42);

    // All parties derive same address
    for (i, share) in shares.iter().enumerate() {
        let addr = share.eth_address().unwrap();
        assert_eq!(
            addr, eth_address,
            "Party {} derives different Ethereum address",
            i
        );
    }
}

/// INVARIANT: Public key shares must be consistently stored across parties
#[tokio::test]
async fn invariant_consistent_public_shares() {
    let shares = setup_shares().await;

    // All parties should have the same number of public shares
    for share in &shares {
        assert_eq!(
            share.public_shares.len(),
            N_PARTIES,
            "Should have {} public shares",
            N_PARTIES
        );
    }

    // Public shares should be identical across all parties
    let reference_public_shares = &shares[0].public_shares;
    for (i, share) in shares.iter().enumerate().skip(1) {
        assert_eq!(
            &share.public_shares, reference_public_shares,
            "Party {} has different public shares",
            i
        );
    }
}

/// INVARIANT: Chain code must be present
#[tokio::test]
async fn invariant_chain_code_present() {
    let shares = setup_shares().await;

    for (i, share) in shares.iter().enumerate() {
        // Chain code should not be all zeros (extremely unlikely if random)
        let is_nonzero = share.chain_code.iter().any(|&b| b != 0);
        assert!(is_nonzero, "Party {} has zero chain code", i);
    }
}

// ============================================================================
// Threshold Invariants
// ============================================================================

/// INVARIANT: Threshold must always be 2
#[test]
fn invariant_threshold_is_two() {
    assert_eq!(THRESHOLD, 2, "Threshold must be 2 for 2-of-3 scheme");
}

/// INVARIANT: Number of parties must always be 3
#[test]
fn invariant_n_parties_is_three() {
    assert_eq!(
        N_PARTIES, 3,
        "Must have exactly 3 parties for AI agent wallet"
    );
}

/// INVARIANT: Any 2 parties can create a valid signing session
#[test]
fn invariant_any_two_parties_can_sign() {
    let valid_combinations = [
        [PartyRole::Agent, PartyRole::User],
        [PartyRole::Agent, PartyRole::Recovery],
        [PartyRole::User, PartyRole::Recovery],
    ];

    for combo in &valid_combinations {
        let party_id = combo[0].party_id();
        let result = SessionConfig::new_signing_session(party_id, combo);
        assert!(
            result.is_ok(),
            "Should be able to create signing session with {:?}",
            combo
        );
    }
}

/// INVARIANT: Single party cannot create a valid signing session
#[test]
fn invariant_single_party_cannot_sign() {
    for role in PartyRole::all() {
        let result = SessionConfig::new_signing_session(role.party_id(), &[role]);
        assert!(
            result.is_err(),
            "Single party {:?} should not be able to sign",
            role
        );
    }
}

// ============================================================================
// Policy Engine Invariants
// ============================================================================

/// INVARIANT: Blacklist takes precedence over whitelist
#[test]
fn invariant_blacklist_precedence() {
    let config = PolicyConfig::default()
        .with_whitelist(vec!["0xTEST".to_string()])
        .with_blacklist(vec!["0xTEST".to_string()]);

    let engine = PolicyEngine::new(config);
    let tx = TransactionRequest::new(ChainType::Evm, "0xtest", "1000");

    let decision = engine.evaluate(&tx).unwrap();
    assert!(
        !decision.is_approved(),
        "Blacklist should take precedence over whitelist"
    );
}

/// INVARIANT: Disabled policy always approves
#[test]
fn invariant_disabled_policy_approves() {
    let engine = PolicyEngine::new(PolicyConfig::disabled());

    // Test with various "bad" transactions
    let test_cases = [
        TransactionRequest::new(ChainType::Evm, "0xBAD", "999999999999999999999"),
        TransactionRequest::new(ChainType::Solana, "EVIL", "999999999999999999999"),
    ];

    for tx in &test_cases {
        let decision = engine.evaluate(tx).unwrap();
        assert!(
            decision.is_approved(),
            "Disabled policy must approve all transactions"
        );
    }
}

/// INVARIANT: Policy evaluation is deterministic
#[test]
fn invariant_policy_deterministic() {
    let config = PolicyConfig::default()
        .with_per_tx_limit(1_000_000_000_000_000_000u128, "ETH")
        .with_whitelist(vec!["0xGOOD".to_string()]);
    let engine = PolicyEngine::new(config);

    let tx = TransactionRequest::new(ChainType::Evm, "0xgood", "500000000000000000");

    // Evaluate multiple times
    let decisions: Vec<_> = (0..100).map(|_| engine.evaluate(&tx).unwrap()).collect();

    // All decisions should be the same
    let first_approved = decisions[0].is_approved();
    for (i, decision) in decisions.iter().enumerate() {
        assert_eq!(
            decision.is_approved(),
            first_approved,
            "Decision {} differed from first",
            i
        );
    }
}

/// INVARIANT: Spending limits are correctly enforced
#[test]
fn invariant_spending_limits_enforced() {
    let limit = 1_000_000_000_000_000_000u128; // 1 ETH
    let config = PolicyConfig::default()
        .with_spending_limits(ChainType::Evm, SpendingLimits::with_per_tx(limit, "ETH"));
    let engine = PolicyEngine::new(config);

    // Test boundary values
    let at_limit = TransactionRequest::new(ChainType::Evm, "0x1234", &limit.to_string());
    let over_limit = TransactionRequest::new(ChainType::Evm, "0x1234", &(limit + 1).to_string());
    let under_limit = TransactionRequest::new(ChainType::Evm, "0x1234", &(limit - 1).to_string());

    assert!(
        engine.evaluate(&under_limit).unwrap().is_approved(),
        "Under limit should be approved"
    );
    assert!(
        engine.evaluate(&at_limit).unwrap().is_approved(),
        "At limit should be approved"
    );
    assert!(
        !engine.evaluate(&over_limit).unwrap().is_approved(),
        "Over limit should be rejected"
    );
}

/// INVARIANT: Daily spending tracking is accurate
#[test]
fn invariant_daily_spending_accurate() {
    let engine = PolicyEngine::new(
        PolicyConfig::default()
            .with_spending_limits(ChainType::Evm, SpendingLimits::default().daily(u128::MAX)),
    );

    let amounts = [100u128, 200, 300, 400, 500];
    let mut expected_total = 0u128;

    for amount in &amounts {
        let tx = TransactionRequest::new(ChainType::Evm, "0x1234", &amount.to_string());
        engine.record_transaction(&tx).unwrap();
        expected_total += amount;

        assert_eq!(
            engine.daily_spending(ChainType::Evm),
            expected_total,
            "Daily spending should be {}",
            expected_total
        );
    }
}

/// INVARIANT: Reset clears all spending
#[test]
fn invariant_reset_clears_spending() {
    let engine = PolicyEngine::new(
        PolicyConfig::default()
            .with_spending_limits(ChainType::Evm, SpendingLimits::default().daily(u128::MAX))
            .with_spending_limits(
                ChainType::Solana,
                SpendingLimits::default().daily(u128::MAX),
            ),
    );

    // Record spending on both chains
    let evm_tx = TransactionRequest::new(ChainType::Evm, "0x1234", "1000000000000000000");
    let sol_tx = TransactionRequest::new(ChainType::Solana, "SOL", "1000000000");
    engine.record_transaction(&evm_tx).unwrap();
    engine.record_transaction(&sol_tx).unwrap();

    // Verify spending was recorded
    assert!(engine.daily_spending(ChainType::Evm) > 0);
    assert!(engine.daily_spending(ChainType::Solana) > 0);

    // Reset
    engine.reset_spending();

    // Verify all spending is cleared
    assert_eq!(
        engine.daily_spending(ChainType::Evm),
        0,
        "EVM spending should be 0 after reset"
    );
    assert_eq!(
        engine.daily_spending(ChainType::Solana),
        0,
        "Solana spending should be 0 after reset"
    );
}

// ============================================================================
// Decision Type Invariants
// ============================================================================

/// INVARIANT: Decision types are mutually exclusive
#[test]
fn invariant_decision_types_exclusive() {
    let decisions = [
        PolicyDecision::Approve,
        PolicyDecision::Reject {
            reason: "test".to_string(),
        },
        PolicyDecision::RequireAdditionalApproval {
            reason: "test".to_string(),
        },
    ];

    for decision in &decisions {
        let approved = decision.is_approved();
        let requires_approval = decision.requires_additional_approval();

        // Cannot be both approved and require additional approval
        if approved {
            assert!(
                !requires_approval,
                "Approved decision cannot require additional approval"
            );
        }

        // RequireAdditionalApproval is not approved but also not a flat rejection
        if requires_approval {
            assert!(
                !approved,
                "Decision requiring approval should not be approved"
            );
        }
    }
}

// ============================================================================
// Key Derivation Invariants
// ============================================================================

/// INVARIANT: Derived keys maintain party role
#[tokio::test]
async fn invariant_derived_keys_maintain_role() {
    let shares = setup_shares().await;

    for share in &shares {
        let derived = share.derive_child("m/0").unwrap();
        assert_eq!(
            derived.role, share.role,
            "Derived key should maintain party role"
        );
        assert_eq!(
            derived.party_id, share.party_id,
            "Derived key should maintain party ID"
        );
    }
}

/// INVARIANT: Same path produces same derived key
#[tokio::test]
async fn invariant_derivation_deterministic() {
    let shares = setup_shares().await;
    let share = &shares[0];

    let path = "m/0/1/2";
    let derived1 = share.derive_child(path).unwrap();
    let derived2 = share.derive_child(path).unwrap();

    assert_eq!(
        derived1.secret_share.to_bytes(),
        derived2.secret_share.to_bytes(),
        "Same derivation path should produce same key"
    );
}

/// INVARIANT: Different paths produce different keys
#[tokio::test]
async fn invariant_different_paths_different_keys() {
    let shares = setup_shares().await;
    let share = &shares[0];

    let derived0 = share.derive_child("m/0").unwrap();
    let derived1 = share.derive_child("m/1").unwrap();

    assert_ne!(
        derived0.secret_share.to_bytes(),
        derived1.secret_share.to_bytes(),
        "Different paths should produce different keys"
    );
}

// ============================================================================
// Concurrent Access Invariants
// ============================================================================

/// INVARIANT: Policy engine is thread-safe
#[tokio::test]
async fn invariant_policy_thread_safe() {
    use std::sync::Arc;

    let engine = Arc::new(PolicyEngine::new(
        PolicyConfig::default()
            .with_spending_limits(ChainType::Evm, SpendingLimits::default().daily(u128::MAX)),
    ));

    let handles: Vec<_> = (0..100)
        .map(|i| {
            let e = Arc::clone(&engine);
            tokio::spawn(async move {
                let tx =
                    TransactionRequest::new(ChainType::Evm, format!("0x{:040x}", i), "1000000");

                // Mix of reads and writes
                let _ = e.evaluate(&tx);
                e.record_transaction(&tx).unwrap();
                let _ = e.daily_spending(ChainType::Evm);
            })
        })
        .collect();

    for handle in handles {
        handle.await.unwrap();
    }

    // Final spending should be 100 * 1000000
    assert_eq!(
        engine.daily_spending(ChainType::Evm),
        100 * 1000000u128,
        "Concurrent operations should maintain consistency"
    );
}
