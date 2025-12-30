//! Fuzz tests for Policy Engine
//!
//! Property-based testing to find edge cases in policy enforcement.
//! Uses proptest for generating random test inputs.

use chrono::Timelike;
use mpc_wallet_core::policy::{
    ContractRestriction, PolicyBuilder, PolicyConfig, PolicyEngine, SpendingLimits, TimeBounds,
};
use mpc_wallet_core::types::{ChainType, TransactionRequest};
use proptest::prelude::*;

// ============================================================================
// Strategies for generating test data
// ============================================================================

/// Generate a random Ethereum-like address
fn address_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("0x[a-fA-F0-9]{40}").unwrap()
}

/// Generate a random value string (wei format)
fn value_strategy() -> impl Strategy<Value = String> {
    prop::num::u128::ANY.prop_map(|v| v.to_string())
}

/// Generate a random value string that parses correctly
fn valid_value_strategy() -> impl Strategy<Value = u128> {
    0u128..=1_000_000_000_000_000_000_000u128 // Up to 1000 ETH
}

/// Generate random contract data
fn data_strategy() -> impl Strategy<Value = Option<Vec<u8>>> {
    prop::option::of(prop::collection::vec(any::<u8>(), 0..100))
}

/// Generate a random chain type
fn chain_type_strategy() -> impl Strategy<Value = ChainType> {
    prop_oneof![
        Just(ChainType::Evm),
        Just(ChainType::Solana),
        Just(ChainType::Bitcoin),
    ]
}

/// Generate a random hour (0-23)
fn hour_strategy() -> impl Strategy<Value = u8> {
    0u8..24u8
}

/// Generate random days of week
fn days_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(0u8..7u8, 1..=7).prop_map(|mut v| {
        v.sort();
        v.dedup();
        v
    })
}

// ============================================================================
// Policy Configuration Fuzzing
// ============================================================================

proptest! {
    /// Test that policy engine never panics on any transaction input
    #[test]
    fn policy_never_panics(
        to in address_strategy(),
        value in value_strategy(),
        chain in chain_type_strategy(),
        data in data_strategy(),
    ) {
        let engine = PolicyEngine::new(PolicyConfig::default());
        let mut tx = TransactionRequest::new(chain, &to, &value);
        if let Some(d) = data {
            tx.data = Some(d);
        }

        // Should never panic, regardless of input
        let result = engine.evaluate(&tx);
        prop_assert!(result.is_ok() || result.is_err());
    }

    /// Test that blacklist always rejects blacklisted addresses
    #[test]
    fn blacklist_always_rejects(
        addr in address_strategy(),
        value in value_strategy(),
    ) {
        let config = PolicyConfig::default()
            .with_blacklist(vec![addr.clone()]);
        let engine = PolicyEngine::new(config);

        let tx = TransactionRequest::new(ChainType::Evm, &addr, &value);
        let decision = engine.evaluate(&tx).unwrap();

        prop_assert!(!decision.is_approved(), "Blacklisted address should always be rejected");
    }

    /// Test that whitelist rejects non-whitelisted addresses
    #[test]
    fn whitelist_rejects_others(
        whitelist_addr in address_strategy(),
        other_addr in address_strategy(),
        value in value_strategy(),
    ) {
        prop_assume!(whitelist_addr.to_lowercase() != other_addr.to_lowercase());

        let config = PolicyConfig::default()
            .with_whitelist(vec![whitelist_addr.clone()]);
        let engine = PolicyEngine::new(config);

        // Whitelisted address should pass
        let tx_good = TransactionRequest::new(ChainType::Evm, &whitelist_addr, &value);
        let decision_good = engine.evaluate(&tx_good).unwrap();
        prop_assert!(decision_good.is_approved());

        // Non-whitelisted should fail
        let tx_bad = TransactionRequest::new(ChainType::Evm, &other_addr, &value);
        let decision_bad = engine.evaluate(&tx_bad).unwrap();
        prop_assert!(!decision_bad.is_approved());
    }

    /// Test that per-transaction limit is correctly enforced
    #[test]
    fn per_tx_limit_enforced(
        limit in valid_value_strategy(),
        value in valid_value_strategy(),
    ) {
        let limits = SpendingLimits::with_per_tx(limit, "ETH");
        let config = PolicyConfig::default()
            .with_spending_limits(ChainType::Evm, limits);
        let engine = PolicyEngine::new(config);

        let tx = TransactionRequest::new(ChainType::Evm, "0x1234567890abcdef1234567890abcdef12345678", &value.to_string());
        let decision = engine.evaluate(&tx).unwrap();

        if value <= limit {
            prop_assert!(decision.is_approved(), "Value {} <= limit {} should be approved", value, limit);
        } else {
            prop_assert!(!decision.is_approved(), "Value {} > limit {} should be rejected", value, limit);
        }
    }

    /// Test that disabled policy always approves
    #[test]
    fn disabled_policy_approves_all(
        to in address_strategy(),
        value in value_strategy(),
    ) {
        let engine = PolicyEngine::new(PolicyConfig::disabled());
        let tx = TransactionRequest::new(ChainType::Evm, &to, &value);
        let decision = engine.evaluate(&tx).unwrap();

        prop_assert!(decision.is_approved(), "Disabled policy should approve everything");
    }
}

// ============================================================================
// Time Bounds Fuzzing
// ============================================================================

proptest! {
    /// Test that time bounds handle all hour combinations
    #[test]
    fn time_bounds_valid_hours(
        start in hour_strategy(),
        end in hour_strategy(),
        days in days_strategy(),
    ) {
        let bounds = TimeBounds {
            start_hour: start,
            end_hour: end,
            allowed_days: days,
        };

        // Should never panic when checking any time
        for hour in 0..24 {
            for day in 0..7 {
                let time = chrono::Utc::now()
                    .with_hour(hour)
                    .and_then(|t| t.with_minute(0));
                if let Some(t) = time {
                    let _ = bounds.is_allowed(t);
                }
            }
        }
    }

    /// Test business hours configuration is consistent
    #[test]
    fn business_hours_consistency(_dummy: u8) {
        let bounds = TimeBounds::business_hours();

        // Business hours should be 9-17
        prop_assert_eq!(bounds.start_hour, 9);
        prop_assert_eq!(bounds.end_hour, 17);
        // Should include Mon-Fri
        prop_assert_eq!(bounds.allowed_days.len(), 5);
    }
}

// ============================================================================
// Contract Restriction Fuzzing
// ============================================================================

proptest! {
    /// Test selector blocking is consistent
    #[test]
    fn blocked_selector_always_blocks(
        selector in prop::array::uniform4(any::<u8>()),
    ) {
        let selector_hex = hex::encode(selector);
        let restrictions = ContractRestriction::default()
            .allow_contract("0x1234567890abcdef1234567890abcdef12345678")
            .block_selector(&selector_hex);

        let config = PolicyConfig::default().with_contract_restrictions(restrictions);
        let engine = PolicyEngine::new(config);

        // Create transaction with the blocked selector
        let mut tx = TransactionRequest::new(
            ChainType::Evm,
            "0x1234567890abcdef1234567890abcdef12345678",
            "0"
        );
        tx.data = Some(selector.to_vec());

        let decision = engine.evaluate(&tx).unwrap();
        prop_assert!(!decision.is_approved(), "Blocked selector should be rejected");
    }

    /// Test allowed selector works correctly
    #[test]
    fn allowed_selector_passes(
        selector in prop::array::uniform4(any::<u8>()),
    ) {
        let selector_hex = hex::encode(selector);
        let restrictions = ContractRestriction::default()
            .allow_contract("0x1234567890abcdef1234567890abcdef12345678")
            .allow_selector(&selector_hex);

        let config = PolicyConfig::default().with_contract_restrictions(restrictions);
        let engine = PolicyEngine::new(config);

        // Create transaction with the allowed selector
        let mut tx = TransactionRequest::new(
            ChainType::Evm,
            "0x1234567890abcdef1234567890abcdef12345678",
            "0"
        );
        let mut data = selector.to_vec();
        data.extend_from_slice(&[0u8; 32]); // Add some call data
        tx.data = Some(data);

        let decision = engine.evaluate(&tx).unwrap();
        prop_assert!(decision.is_approved(), "Allowed selector should be approved");
    }
}

// ============================================================================
// Spending Tracker Fuzzing
// ============================================================================

proptest! {
    /// Test spending tracker accumulates correctly
    #[test]
    fn spending_accumulates(
        amounts in prop::collection::vec(valid_value_strategy(), 1..10),
    ) {
        let policy = PolicyEngine::new(
            PolicyConfig::default()
                .with_spending_limits(ChainType::Evm, SpendingLimits::default().daily(u128::MAX))
        );

        let mut total: u128 = 0;
        for amount in amounts {
            let tx = TransactionRequest::new(
                ChainType::Evm,
                "0x1234567890abcdef1234567890abcdef12345678",
                &amount.to_string()
            );
            policy.record_transaction(&tx).unwrap();
            total = total.saturating_add(amount);
        }

        prop_assert_eq!(policy.daily_spending(ChainType::Evm), total);
    }

    /// Test that reset clears spending
    #[test]
    fn spending_reset_clears(
        amounts in prop::collection::vec(valid_value_strategy(), 1..5),
    ) {
        let policy = PolicyEngine::new(
            PolicyConfig::default()
                .with_spending_limits(ChainType::Evm, SpendingLimits::default().daily(u128::MAX))
        );

        // Record some spending
        for amount in amounts {
            let tx = TransactionRequest::new(
                ChainType::Evm,
                "0x1234567890abcdef1234567890abcdef12345678",
                &amount.to_string()
            );
            policy.record_transaction(&tx).unwrap();
        }

        // Reset
        policy.reset_spending();

        // Should be zero
        prop_assert_eq!(policy.daily_spending(ChainType::Evm), 0);
    }
}

// ============================================================================
// Policy Builder Fuzzing
// ============================================================================

proptest! {
    /// Test policy builder creates valid configs
    #[test]
    fn policy_builder_valid(
        per_tx in valid_value_strategy(),
        daily in valid_value_strategy(),
        weekly in valid_value_strategy(),
        whitelist_addrs in prop::collection::vec(address_strategy(), 0..5),
        blacklist_addrs in prop::collection::vec(address_strategy(), 0..5),
    ) {
        let limits = SpendingLimits::with_per_tx(per_tx, "ETH")
            .daily(daily)
            .weekly(weekly);

        let mut builder = PolicyBuilder::new()
            .spending_limits(ChainType::Evm, limits);

        if !whitelist_addrs.is_empty() {
            builder = builder.whitelist(whitelist_addrs.clone());
        }
        if !blacklist_addrs.is_empty() {
            builder = builder.blacklist(blacklist_addrs.clone());
        }

        let config = builder.build();

        // Config should be valid
        let engine = PolicyEngine::new(config);

        // Should be able to evaluate transactions
        let tx = TransactionRequest::new(
            ChainType::Evm,
            "0x1234567890abcdef1234567890abcdef12345678",
            "1000"
        );
        let result = engine.evaluate(&tx);
        prop_assert!(result.is_ok());
    }
}

// ============================================================================
// Additional Approval Threshold Fuzzing
// ============================================================================

proptest! {
    /// Test additional approval threshold boundary
    #[test]
    fn additional_approval_threshold_boundary(
        threshold in valid_value_strategy(),
        value in valid_value_strategy(),
    ) {
        prop_assume!(threshold > 0);

        let config = PolicyConfig::default()
            .with_additional_approval_threshold(threshold);
        let engine = PolicyEngine::new(config);

        let tx = TransactionRequest::new(
            ChainType::Evm,
            "0x1234567890abcdef1234567890abcdef12345678",
            &value.to_string()
        );
        let decision = engine.evaluate(&tx).unwrap();

        if value <= threshold {
            prop_assert!(decision.is_approved(), "Value {} <= threshold {} should be approved", value, threshold);
        } else {
            prop_assert!(
                decision.requires_additional_approval(),
                "Value {} > threshold {} should require additional approval",
                value, threshold
            );
        }
    }
}

// ============================================================================
// Idempotency Tests
// ============================================================================

proptest! {
    /// Test that evaluation is idempotent (same result for same input)
    #[test]
    fn evaluation_idempotent(
        to in address_strategy(),
        value in value_strategy(),
    ) {
        let config = PolicyConfig::default()
            .with_per_tx_limit(1_000_000_000_000_000_000u128, "ETH");
        let engine = PolicyEngine::new(config);

        let tx = TransactionRequest::new(ChainType::Evm, &to, &value);

        // Multiple evaluations should give same result
        let decision1 = engine.evaluate(&tx).unwrap();
        let decision2 = engine.evaluate(&tx).unwrap();
        let decision3 = engine.evaluate(&tx).unwrap();

        prop_assert_eq!(decision1.is_approved(), decision2.is_approved());
        prop_assert_eq!(decision2.is_approved(), decision3.is_approved());
    }
}
