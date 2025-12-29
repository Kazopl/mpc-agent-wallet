//! Unit tests for Policy Engine
//!
//! These tests verify the correctness of policy enforcement including:
//! - Spending limits (per-transaction, daily, weekly)
//! - Address whitelist/blacklist
//! - Time bounds
//! - Contract restrictions

use chrono::{TimeZone, Utc};
use mpc_wallet_core::policy::{
    ContractRestriction, PolicyBuilder, PolicyConfig, PolicyDecision, PolicyEngine, SpendingLimits,
    TimeBounds,
};
use mpc_wallet_core::types::{ChainType, TransactionRequest};

// ============================================================================
// Basic Policy Tests
// ============================================================================

#[test]
fn test_policy_approve_basic_transaction() {
    let engine = PolicyEngine::new(PolicyConfig::default());
    let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "1000000000000000000");

    let decision = engine.evaluate(&tx).unwrap();
    assert!(decision.is_approved());
}

#[test]
fn test_policy_disabled_allows_all() {
    let engine = PolicyEngine::new(PolicyConfig::disabled());

    // Even a huge transaction should pass
    let tx = TransactionRequest::new(ChainType::Evm, "0xBAD", "999999999999999999999999999999");

    let decision = engine.evaluate(&tx).unwrap();
    assert!(decision.is_approved());
}

#[test]
fn test_policy_can_be_updated() {
    let mut engine = PolicyEngine::new(PolicyConfig::default());

    // Initially should approve
    let tx = TransactionRequest::new(ChainType::Evm, "0xBAD", "1000");
    assert!(engine.evaluate(&tx).unwrap().is_approved());

    // Update to blacklist the address
    engine.update_config(PolicyConfig::default().with_blacklist(vec!["0xBAD".to_string()]));

    // Now should reject
    assert!(!engine.evaluate(&tx).unwrap().is_approved());
}

// ============================================================================
// Blacklist Tests
// ============================================================================

#[test]
fn test_blacklist_rejects_exact_match() {
    let config = PolicyConfig::default().with_blacklist(vec!["0xBAD".to_string()]);
    let engine = PolicyEngine::new(config);

    let tx = TransactionRequest::new(ChainType::Evm, "0xbad", "1000");
    let decision = engine.evaluate(&tx).unwrap();

    assert!(!decision.is_approved());
    if let PolicyDecision::Reject { reason } = decision {
        assert!(reason.contains("blacklisted"));
    }
}

#[test]
fn test_blacklist_case_insensitive() {
    let config = PolicyConfig::default().with_blacklist(vec!["0xBaD123".to_string()]);
    let engine = PolicyEngine::new(config);

    // Should reject regardless of case
    let tx_lower = TransactionRequest::new(ChainType::Evm, "0xbad123", "1000");
    let tx_upper = TransactionRequest::new(ChainType::Evm, "0xBAD123", "1000");
    let tx_mixed = TransactionRequest::new(ChainType::Evm, "0xBaD123", "1000");

    assert!(!engine.evaluate(&tx_lower).unwrap().is_approved());
    assert!(!engine.evaluate(&tx_upper).unwrap().is_approved());
    assert!(!engine.evaluate(&tx_mixed).unwrap().is_approved());
}

#[test]
fn test_blacklist_allows_other_addresses() {
    let config = PolicyConfig::default().with_blacklist(vec!["0xBAD".to_string()]);
    let engine = PolicyEngine::new(config);

    let tx = TransactionRequest::new(ChainType::Evm, "0xGOOD", "1000");
    assert!(engine.evaluate(&tx).unwrap().is_approved());
}

#[test]
fn test_multiple_blacklisted_addresses() {
    let config = PolicyConfig::default().with_blacklist(vec![
        "0xBAD1".to_string(),
        "0xBAD2".to_string(),
        "0xBAD3".to_string(),
    ]);
    let engine = PolicyEngine::new(config);

    assert!(
        !engine
            .evaluate(&TransactionRequest::new(ChainType::Evm, "0xbad1", "1000"))
            .unwrap()
            .is_approved()
    );
    assert!(
        !engine
            .evaluate(&TransactionRequest::new(ChainType::Evm, "0xbad2", "1000"))
            .unwrap()
            .is_approved()
    );
    assert!(
        !engine
            .evaluate(&TransactionRequest::new(ChainType::Evm, "0xbad3", "1000"))
            .unwrap()
            .is_approved()
    );
    assert!(
        engine
            .evaluate(&TransactionRequest::new(ChainType::Evm, "0xgood", "1000"))
            .unwrap()
            .is_approved()
    );
}

// ============================================================================
// Whitelist Tests
// ============================================================================

#[test]
fn test_whitelist_allows_listed_address() {
    let config = PolicyConfig::default().with_whitelist(vec!["0xGOOD".to_string()]);
    let engine = PolicyEngine::new(config);

    let tx = TransactionRequest::new(ChainType::Evm, "0xgood", "1000");
    assert!(engine.evaluate(&tx).unwrap().is_approved());
}

#[test]
fn test_whitelist_rejects_unlisted_address() {
    let config = PolicyConfig::default().with_whitelist(vec!["0xGOOD".to_string()]);
    let engine = PolicyEngine::new(config);

    let tx = TransactionRequest::new(ChainType::Evm, "0xOTHER", "1000");
    let decision = engine.evaluate(&tx).unwrap();

    assert!(!decision.is_approved());
    if let PolicyDecision::Reject { reason } = decision {
        assert!(reason.contains("not whitelisted"));
    }
}

#[test]
fn test_whitelist_case_insensitive() {
    let config = PolicyConfig::default().with_whitelist(vec!["0xGoOd".to_string()]);
    let engine = PolicyEngine::new(config);

    let tx_lower = TransactionRequest::new(ChainType::Evm, "0xgood", "1000");
    let tx_upper = TransactionRequest::new(ChainType::Evm, "0xGOOD", "1000");

    assert!(engine.evaluate(&tx_lower).unwrap().is_approved());
    assert!(engine.evaluate(&tx_upper).unwrap().is_approved());
}

#[test]
fn test_no_whitelist_allows_any() {
    // When whitelist is not set (None), any address is allowed
    let config = PolicyConfig::default();
    let engine = PolicyEngine::new(config);

    let tx1 = TransactionRequest::new(ChainType::Evm, "0xAny1", "1000");
    let tx2 = TransactionRequest::new(ChainType::Evm, "0xAny2", "1000");

    assert!(engine.evaluate(&tx1).unwrap().is_approved());
    assert!(engine.evaluate(&tx2).unwrap().is_approved());
}

#[test]
fn test_blacklist_takes_precedence_over_whitelist() {
    // If an address is both whitelisted and blacklisted, blacklist wins
    let config = PolicyConfig::default()
        .with_whitelist(vec!["0xADDRESS".to_string()])
        .with_blacklist(vec!["0xADDRESS".to_string()]);
    let engine = PolicyEngine::new(config);

    let tx = TransactionRequest::new(ChainType::Evm, "0xaddress", "1000");
    assert!(!engine.evaluate(&tx).unwrap().is_approved());
}

// ============================================================================
// Spending Limit Tests
// ============================================================================

#[test]
fn test_per_transaction_limit_under() {
    let limits = SpendingLimits::with_per_tx(1_000_000_000_000_000_000u128, "ETH"); // 1 ETH
    let config = PolicyConfig::default().with_spending_limits(ChainType::Evm, limits);
    let engine = PolicyEngine::new(config);

    // 0.5 ETH - under limit
    let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "500000000000000000");
    assert!(engine.evaluate(&tx).unwrap().is_approved());
}

#[test]
fn test_per_transaction_limit_over() {
    let limits = SpendingLimits::with_per_tx(1_000_000_000_000_000_000u128, "ETH"); // 1 ETH
    let config = PolicyConfig::default().with_spending_limits(ChainType::Evm, limits);
    let engine = PolicyEngine::new(config);

    // 2 ETH - over limit
    let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "2000000000000000000");
    let decision = engine.evaluate(&tx).unwrap();

    assert!(!decision.is_approved());
    if let PolicyDecision::Reject { reason } = decision {
        assert!(reason.contains("exceeds per-transaction limit"));
    }
}

#[test]
fn test_per_transaction_limit_exact() {
    let limits = SpendingLimits::with_per_tx(1_000_000_000_000_000_000u128, "ETH"); // 1 ETH
    let config = PolicyConfig::default().with_spending_limits(ChainType::Evm, limits);
    let engine = PolicyEngine::new(config);

    // Exactly 1 ETH - should pass (equal to limit)
    let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "1000000000000000000");
    assert!(engine.evaluate(&tx).unwrap().is_approved());
}

#[test]
fn test_daily_limit_tracking() {
    let limits = SpendingLimits::default().daily(2_000_000_000_000_000_000u128); // 2 ETH
    let config = PolicyConfig::default().with_spending_limits(ChainType::Evm, limits);
    let engine = PolicyEngine::new(config);

    // First transaction: 1 ETH
    let tx1 = TransactionRequest::new(ChainType::Evm, "0x1234", "1000000000000000000");
    assert!(engine.evaluate(&tx1).unwrap().is_approved());
    engine.record_transaction(&tx1).unwrap();

    // Second transaction: 0.5 ETH (total 1.5 ETH, under limit)
    let tx2 = TransactionRequest::new(ChainType::Evm, "0x1234", "500000000000000000");
    assert!(engine.evaluate(&tx2).unwrap().is_approved());
    engine.record_transaction(&tx2).unwrap();

    // Third transaction: 1 ETH (would bring total to 2.5 ETH, over limit)
    let tx3 = TransactionRequest::new(ChainType::Evm, "0x1234", "1000000000000000000");
    let decision = engine.evaluate(&tx3).unwrap();

    assert!(!decision.is_approved());
    if let PolicyDecision::Reject { reason } = decision {
        assert!(reason.contains("daily limit"));
    }
}

#[test]
fn test_weekly_limit_tracking() {
    let limits = SpendingLimits::default().weekly(5_000_000_000_000_000_000u128); // 5 ETH
    let config = PolicyConfig::default().with_spending_limits(ChainType::Evm, limits);
    let engine = PolicyEngine::new(config);

    // Spend 3 ETH
    let tx1 = TransactionRequest::new(ChainType::Evm, "0x1234", "3000000000000000000");
    assert!(engine.evaluate(&tx1).unwrap().is_approved());
    engine.record_transaction(&tx1).unwrap();

    // Try to spend 3 more ETH (would be 6 ETH total, over weekly limit)
    let tx2 = TransactionRequest::new(ChainType::Evm, "0x1234", "3000000000000000000");
    let decision = engine.evaluate(&tx2).unwrap();

    assert!(!decision.is_approved());
    if let PolicyDecision::Reject { reason } = decision {
        assert!(reason.contains("weekly limit"));
    }
}

#[test]
fn test_spending_tracker_per_chain() {
    let evm_limits = SpendingLimits::default().daily(1_000_000_000_000_000_000u128); // 1 ETH
    let sol_limits = SpendingLimits::default().daily(1_000_000_000u128); // 1 SOL (9 decimals)

    let config = PolicyConfig::default()
        .with_spending_limits(ChainType::Evm, evm_limits)
        .with_spending_limits(ChainType::Solana, sol_limits);
    let engine = PolicyEngine::new(config);

    // Spend on EVM
    let evm_tx = TransactionRequest::new(ChainType::Evm, "0x1234", "500000000000000000");
    engine.record_transaction(&evm_tx).unwrap();

    // Spending on EVM shouldn't affect Solana limit
    let sol_tx = TransactionRequest::new(ChainType::Solana, "SOL123", "500000000");
    assert!(engine.evaluate(&sol_tx).unwrap().is_approved());
}

#[test]
fn test_spending_reset() {
    let limits = SpendingLimits::default().daily(1_000_000_000_000_000_000u128);
    let config = PolicyConfig::default().with_spending_limits(ChainType::Evm, limits);
    let engine = PolicyEngine::new(config);

    // Spend the limit
    let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "1000000000000000000");
    engine.record_transaction(&tx).unwrap();

    // Verify limit is reached
    assert_eq!(
        engine.daily_spending(ChainType::Evm),
        1_000_000_000_000_000_000u128
    );

    // Reset spending
    engine.reset_spending();

    // Verify reset worked
    assert_eq!(engine.daily_spending(ChainType::Evm), 0);
}

// ============================================================================
// Additional Approval Threshold Tests
// ============================================================================

#[test]
fn test_additional_approval_under_threshold() {
    let config =
        PolicyConfig::default().with_additional_approval_threshold(5_000_000_000_000_000_000u128); // 5 ETH
    let engine = PolicyEngine::new(config);

    // 1 ETH - under threshold, should approve
    let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "1000000000000000000");
    assert!(engine.evaluate(&tx).unwrap().is_approved());
}

#[test]
fn test_additional_approval_over_threshold() {
    let config =
        PolicyConfig::default().with_additional_approval_threshold(5_000_000_000_000_000_000u128); // 5 ETH
    let engine = PolicyEngine::new(config);

    // 10 ETH - over threshold, should require additional approval
    let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "10000000000000000000");
    let decision = engine.evaluate(&tx).unwrap();

    assert!(decision.requires_additional_approval());
    if let PolicyDecision::RequireAdditionalApproval { reason } = decision {
        assert!(reason.contains("additional approval threshold"));
    }
}

// ============================================================================
// Time Bounds Tests
// ============================================================================

#[test]
fn test_time_bounds_business_hours() {
    let bounds = TimeBounds::business_hours();

    assert_eq!(bounds.start_hour, 9);
    assert_eq!(bounds.end_hour, 17);
    assert_eq!(bounds.allowed_days, vec![1, 2, 3, 4, 5]); // Monday-Friday
}

#[test]
fn test_time_bounds_within_window() {
    let bounds = TimeBounds {
        start_hour: 9,
        end_hour: 17,
        allowed_days: vec![0, 1, 2, 3, 4, 5, 6],
    };

    // 10:00 UTC should be allowed
    let time_10am = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();
    assert!(bounds.is_allowed(time_10am));

    // 16:30 UTC should be allowed
    let time_430pm = Utc.with_ymd_and_hms(2024, 1, 15, 16, 30, 0).unwrap();
    assert!(bounds.is_allowed(time_430pm));
}

#[test]
fn test_time_bounds_outside_window() {
    let bounds = TimeBounds {
        start_hour: 9,
        end_hour: 17,
        allowed_days: vec![0, 1, 2, 3, 4, 5, 6],
    };

    // 8:00 UTC should not be allowed (before 9)
    let time_8am = Utc.with_ymd_and_hms(2024, 1, 15, 8, 0, 0).unwrap();
    assert!(!bounds.is_allowed(time_8am));

    // 17:00 UTC should not be allowed (at end, exclusive)
    let time_5pm = Utc.with_ymd_and_hms(2024, 1, 15, 17, 0, 0).unwrap();
    assert!(!bounds.is_allowed(time_5pm));

    // 22:00 UTC should not be allowed
    let time_10pm = Utc.with_ymd_and_hms(2024, 1, 15, 22, 0, 0).unwrap();
    assert!(!bounds.is_allowed(time_10pm));
}

#[test]
fn test_time_bounds_day_restriction() {
    let bounds = TimeBounds {
        start_hour: 0,
        end_hour: 24,
        allowed_days: vec![1, 2, 3, 4, 5], // Monday-Friday only
    };

    // Monday should be allowed (day 1)
    let monday = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap(); // Monday
    assert!(bounds.is_allowed(monday));

    // Sunday should not be allowed (day 0)
    let sunday = Utc.with_ymd_and_hms(2024, 1, 14, 12, 0, 0).unwrap(); // Sunday
    assert!(!bounds.is_allowed(sunday));

    // Saturday should not be allowed (day 6)
    let saturday = Utc.with_ymd_and_hms(2024, 1, 13, 12, 0, 0).unwrap(); // Saturday
    assert!(!bounds.is_allowed(saturday));
}

#[test]
fn test_time_bounds_wrap_around() {
    // Test overnight window (22:00 - 06:00)
    let bounds = TimeBounds {
        start_hour: 22,
        end_hour: 6,
        allowed_days: vec![0, 1, 2, 3, 4, 5, 6],
    };

    // 23:00 should be allowed
    let time_11pm = Utc.with_ymd_and_hms(2024, 1, 15, 23, 0, 0).unwrap();
    assert!(bounds.is_allowed(time_11pm));

    // 2:00 should be allowed
    let time_2am = Utc.with_ymd_and_hms(2024, 1, 15, 2, 0, 0).unwrap();
    assert!(bounds.is_allowed(time_2am));

    // 12:00 should not be allowed
    let time_noon = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();
    assert!(!bounds.is_allowed(time_noon));
}

// ============================================================================
// Contract Restriction Tests
// ============================================================================

#[test]
fn test_contract_restriction_allowed_contract() {
    let restrictions = ContractRestriction::default().allow_contract("0xUniswap");

    let config = PolicyConfig::default().with_contract_restrictions(restrictions);
    let engine = PolicyEngine::new(config);

    // Contract call to allowed contract
    let mut tx = TransactionRequest::new(ChainType::Evm, "0xuniswap", "0");
    tx.data = Some(vec![0x12, 0x34, 0x56, 0x78]); // Some data

    assert!(engine.evaluate(&tx).unwrap().is_approved());
}

#[test]
fn test_contract_restriction_disallowed_contract() {
    let restrictions = ContractRestriction::default().allow_contract("0xUniswap");

    let config = PolicyConfig::default().with_contract_restrictions(restrictions);
    let engine = PolicyEngine::new(config);

    // Contract call to non-allowed contract
    let mut tx = TransactionRequest::new(ChainType::Evm, "0xOtherContract", "0");
    tx.data = Some(vec![0x12, 0x34, 0x56, 0x78]);

    let decision = engine.evaluate(&tx).unwrap();
    assert!(!decision.is_approved());
}

#[test]
fn test_contract_restriction_blocked_selector() {
    let restrictions = ContractRestriction::default()
        .allow_contract("0xUniswap")
        .block_selector("a9059cbb"); // transfer

    let config = PolicyConfig::default().with_contract_restrictions(restrictions);
    let engine = PolicyEngine::new(config);

    // Call with blocked selector
    let mut tx = TransactionRequest::new(ChainType::Evm, "0xuniswap", "0");
    tx.data = Some(vec![0xa9, 0x05, 0x9c, 0xbb, 0x00, 0x00]); // transfer selector

    let decision = engine.evaluate(&tx).unwrap();
    assert!(!decision.is_approved());
    if let PolicyDecision::Reject { reason } = decision {
        assert!(reason.contains("blocked"));
    }
}

#[test]
fn test_contract_restriction_allowed_selector() {
    let restrictions = ContractRestriction::default()
        .allow_contract("0xUniswap")
        .allow_selector("12345678"); // Only this selector allowed

    let config = PolicyConfig::default().with_contract_restrictions(restrictions);
    let engine = PolicyEngine::new(config);

    // Call with allowed selector
    let mut tx_allowed = TransactionRequest::new(ChainType::Evm, "0xuniswap", "0");
    tx_allowed.data = Some(vec![0x12, 0x34, 0x56, 0x78]);
    assert!(engine.evaluate(&tx_allowed).unwrap().is_approved());

    // Call with non-allowed selector
    let mut tx_disallowed = TransactionRequest::new(ChainType::Evm, "0xuniswap", "0");
    tx_disallowed.data = Some(vec![0xaa, 0xbb, 0xcc, 0xdd]);
    assert!(!engine.evaluate(&tx_disallowed).unwrap().is_approved());
}

#[test]
fn test_non_contract_call_bypasses_restrictions() {
    let restrictions = ContractRestriction::default().allow_contract("0xUniswap"); // Only Uniswap allowed

    let config = PolicyConfig::default().with_contract_restrictions(restrictions);
    let engine = PolicyEngine::new(config);

    // Simple ETH transfer (no data) should not be affected by contract restrictions
    let tx = TransactionRequest::new(ChainType::Evm, "0xSomeEOA", "1000000000000000000");
    // No data = not a contract call
    assert!(engine.evaluate(&tx).unwrap().is_approved());
}

// ============================================================================
// Policy Builder Tests
// ============================================================================

#[test]
fn test_policy_builder_complete() {
    let policy = PolicyBuilder::new()
        .spending_limits(
            ChainType::Evm,
            SpendingLimits::with_per_tx(1_000_000_000_000_000_000, "ETH")
                .daily(5_000_000_000_000_000_000)
                .weekly(20_000_000_000_000_000_000),
        )
        .whitelist(["0x1234", "0x5678"])
        .blacklist(["0xBAD"])
        .time_bounds(TimeBounds::business_hours())
        .additional_approval_threshold(10_000_000_000_000_000_000)
        .build();

    // Verify all settings
    assert!(policy.whitelist.is_some());
    assert_eq!(policy.whitelist.as_ref().unwrap().len(), 2);
    assert!(policy.blacklist.contains("0xbad"));
    assert!(policy.time_bounds.is_some());
    assert!(policy.additional_approval_threshold.is_some());
    assert!(policy.spending_limits.contains_key(&ChainType::Evm));
}

#[test]
fn test_policy_builder_partial() {
    let policy = PolicyBuilder::new().whitelist(["0x1234"]).build();

    assert!(policy.whitelist.is_some());
    assert!(policy.blacklist.is_empty());
    assert!(policy.time_bounds.is_none());
}

// ============================================================================
// Value Parsing Tests
// ============================================================================

#[test]
fn test_parse_decimal_value() {
    let engine = PolicyEngine::new(PolicyConfig::default());

    // Create transactions with decimal values and ensure they're properly parsed
    // These are internally tested through spending limit enforcement

    let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "1.5");
    // The policy engine should parse "1.5" as 1.5 ETH = 1500000000000000000 wei
    let result = engine.evaluate(&tx);
    assert!(result.is_ok());
}

#[test]
fn test_parse_whole_number_value() {
    let engine = PolicyEngine::new(PolicyConfig::default());

    let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "1000000000000000000");
    let result = engine.evaluate(&tx);
    assert!(result.is_ok());
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_empty_whitelist_set() {
    // Empty whitelist set (Some(empty HashSet)) should reject all
    let config = PolicyConfig::default().with_whitelist(vec![]);
    let engine = PolicyEngine::new(config);

    let tx = TransactionRequest::new(ChainType::Evm, "0xAnything", "1000");
    assert!(!engine.evaluate(&tx).unwrap().is_approved());
}

#[test]
fn test_zero_value_transaction() {
    let limits = SpendingLimits::with_per_tx(1_000_000_000_000_000_000u128, "ETH");
    let config = PolicyConfig::default().with_spending_limits(ChainType::Evm, limits);
    let engine = PolicyEngine::new(config);

    let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "0");
    assert!(engine.evaluate(&tx).unwrap().is_approved());
}

#[test]
fn test_very_small_value() {
    let limits = SpendingLimits::with_per_tx(1u128, "WEI");
    let config = PolicyConfig::default().with_spending_limits(ChainType::Evm, limits);
    let engine = PolicyEngine::new(config);

    // Exactly at limit
    let tx_at = TransactionRequest::new(ChainType::Evm, "0x1234", "1");
    assert!(engine.evaluate(&tx_at).unwrap().is_approved());

    // Over limit
    let tx_over = TransactionRequest::new(ChainType::Evm, "0x1234", "2");
    assert!(!engine.evaluate(&tx_over).unwrap().is_approved());
}

#[test]
fn test_multiple_chains_different_policies() {
    let evm_limits = SpendingLimits::with_per_tx(1_000_000_000_000_000_000u128, "ETH"); // 1 ETH
    let sol_limits = SpendingLimits::with_per_tx(100_000_000_000u128, "SOL"); // 100 SOL

    let config = PolicyConfig::default()
        .with_spending_limits(ChainType::Evm, evm_limits)
        .with_spending_limits(ChainType::Solana, sol_limits);
    let engine = PolicyEngine::new(config);

    // EVM: 0.5 ETH should pass
    let evm_tx = TransactionRequest::new(ChainType::Evm, "0x1234", "500000000000000000");
    assert!(engine.evaluate(&evm_tx).unwrap().is_approved());

    // Solana: 50 SOL should pass
    let sol_tx = TransactionRequest::new(ChainType::Solana, "SOL123", "50000000000");
    assert!(engine.evaluate(&sol_tx).unwrap().is_approved());
}
