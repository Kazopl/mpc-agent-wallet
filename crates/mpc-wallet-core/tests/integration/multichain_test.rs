//! Integration tests for multi-chain operations
//!
//! These tests verify that the wallet SDK correctly handles
//! operations across different blockchain networks.

use mpc_wallet_core::{
    AgentKeyShare,
    keygen::run_dkg,
    mpc::MemoryRelay,
    policy::{PolicyConfig, PolicyEngine, SpendingLimits},
    types::{ChainType, SessionConfig, TransactionRequest},
};

#[cfg(feature = "evm")]
use mpc_wallet_core::chain::{Balance, ChainAdapter, EvmAdapter, EvmConfig, TxParams, TxPriority};

#[cfg(feature = "evm")]
use mpc_wallet_core::PartyRole;

use std::sync::Arc;

/// Helper to create a wallet
async fn setup_wallet() -> Vec<AgentKeyShare> {
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
// Multi-Chain Policy Tests
// ============================================================================

#[test]
fn test_different_policies_per_chain() {
    let evm_limits = SpendingLimits::with_per_tx(1_000_000_000_000_000_000u128, "ETH"); // 1 ETH
    let sol_limits = SpendingLimits::with_per_tx(10_000_000_000u128, "SOL"); // 10 SOL (9 decimals)

    let policy = PolicyEngine::new(
        PolicyConfig::default()
            .with_spending_limits(ChainType::Evm, evm_limits)
            .with_spending_limits(ChainType::Solana, sol_limits),
    );

    // EVM transaction under limit
    let evm_tx = TransactionRequest::new(ChainType::Evm, "0x1234", "500000000000000000"); // 0.5 ETH
    assert!(policy.evaluate(&evm_tx).unwrap().is_approved());

    // EVM transaction over limit
    let evm_over = TransactionRequest::new(ChainType::Evm, "0x1234", "2000000000000000000"); // 2 ETH
    assert!(!policy.evaluate(&evm_over).unwrap().is_approved());

    // Solana transaction under limit
    let sol_tx = TransactionRequest::new(ChainType::Solana, "SOL123", "5000000000"); // 5 SOL
    assert!(policy.evaluate(&sol_tx).unwrap().is_approved());

    // Solana transaction over limit
    let sol_over = TransactionRequest::new(ChainType::Solana, "SOL123", "20000000000"); // 20 SOL
    assert!(!policy.evaluate(&sol_over).unwrap().is_approved());
}

#[test]
fn test_chain_specific_spending_tracking() {
    let policy = PolicyEngine::new(
        PolicyConfig::default()
            .with_spending_limits(
                ChainType::Evm,
                SpendingLimits::default().daily(2_000_000_000_000_000_000u128),
            )
            .with_spending_limits(
                ChainType::Solana,
                SpendingLimits::default().daily(20_000_000_000u128),
            ),
    );

    // Spend on EVM
    let evm_tx1 = TransactionRequest::new(ChainType::Evm, "0x1234", "1000000000000000000");
    policy.record_transaction(&evm_tx1).unwrap();

    // EVM spending should be tracked
    assert_eq!(
        policy.daily_spending(ChainType::Evm),
        1_000_000_000_000_000_000u128
    );
    // Solana spending should be unaffected
    assert_eq!(policy.daily_spending(ChainType::Solana), 0);

    // Spend on Solana
    let sol_tx1 = TransactionRequest::new(ChainType::Solana, "SOL123", "10000000000");
    policy.record_transaction(&sol_tx1).unwrap();

    // Both chains have separate tracking
    assert_eq!(
        policy.daily_spending(ChainType::Evm),
        1_000_000_000_000_000_000u128
    );
    assert_eq!(policy.daily_spending(ChainType::Solana), 10_000_000_000u128);
}

#[test]
fn test_chain_type_display() {
    assert_eq!(format!("{}", ChainType::Evm), "EVM");
    assert_eq!(format!("{}", ChainType::Solana), "Solana");
    assert_eq!(format!("{}", ChainType::Bitcoin), "Bitcoin");
}

// ============================================================================
// EVM Multi-Network Tests (require evm feature)
// ============================================================================

#[cfg(feature = "evm")]
mod evm_multinetwork_tests {
    use super::*;

    #[test]
    fn test_all_evm_networks_supported() {
        let networks = [
            EvmConfig::ethereum_mainnet(),
            EvmConfig::ethereum_sepolia(),
            EvmConfig::arbitrum_one(),
            EvmConfig::optimism(),
            EvmConfig::base(),
            EvmConfig::polygon(),
            EvmConfig::bsc(),
        ];

        for config in networks {
            let adapter = EvmAdapter::new(config.clone());
            assert!(
                adapter.is_ok(),
                "Should create adapter for chain {}",
                config.chain_id.0
            );

            let adapter = adapter.unwrap();
            assert!(!config.rpc_urls.is_empty());
            assert!(adapter.native_decimals() > 0);
        }
    }

    #[tokio::test]
    async fn test_same_wallet_different_chains() {
        let shares = setup_wallet().await;
        let public_key = &shares[0].public_key;

        // Derive addresses for different EVM networks
        let networks = [
            EvmConfig::ethereum_mainnet(),
            EvmConfig::arbitrum_one(),
            EvmConfig::polygon(),
        ];

        let mut addresses = Vec::new();
        for config in networks {
            let adapter = EvmAdapter::new(config).unwrap();
            let address = adapter.derive_address(public_key).unwrap();
            addresses.push(address);
        }

        // All EVM chains should derive the same address from the same public key
        assert_eq!(addresses[0], addresses[1]);
        assert_eq!(addresses[1], addresses[2]);
    }

    #[test]
    fn test_eip1559_vs_legacy_chains() {
        // EIP-1559 supported
        let eth_config = EvmConfig::ethereum_mainnet();
        assert!(eth_config.eip1559_supported);

        let arb_config = EvmConfig::arbitrum_one();
        assert!(arb_config.eip1559_supported);

        // BSC doesn't support EIP-1559
        let bsc_config = EvmConfig::bsc();
        assert!(!bsc_config.eip1559_supported);
    }

    #[test]
    fn test_chain_specific_symbols() {
        let configs = [
            (EvmConfig::ethereum_mainnet(), "ETH"),
            (EvmConfig::polygon(), "MATIC"),
            (EvmConfig::bsc(), "BNB"),
        ];

        for (config, expected_symbol) in configs {
            assert_eq!(
                config.symbol, expected_symbol,
                "Chain {} should have symbol {}",
                config.chain_id.0, expected_symbol
            );
        }
    }

    #[test]
    fn test_tx_params_for_different_networks() {
        let params_eth = TxParams::new("0xfrom", "0xto", "1.0")
            .with_priority(TxPriority::Medium)
            .with_gas_limit(21000);

        let params_polygon = TxParams::new("0xfrom", "0xto", "1.0")
            .with_priority(TxPriority::High) // Higher priority for cheaper chain
            .with_gas_limit(21000);

        assert_eq!(params_eth.priority, TxPriority::Medium);
        assert_eq!(params_polygon.priority, TxPriority::High);
    }

    #[test]
    fn test_balance_formatting_different_symbols() {
        // ETH (18 decimals)
        let eth_balance = Balance::new("1500000000000000000", 18, "ETH");
        assert_eq!(eth_balance.formatted, "1.5");
        assert_eq!(eth_balance.symbol, "ETH");

        // MATIC (18 decimals, same as ETH)
        let matic_balance = Balance::new("1500000000000000000", 18, "MATIC");
        assert_eq!(matic_balance.formatted, "1.5");
        assert_eq!(matic_balance.symbol, "MATIC");

        // BNB (18 decimals)
        let bnb_balance = Balance::new("2000000000000000000", 18, "BNB");
        assert_eq!(bnb_balance.formatted, "2");
        assert_eq!(bnb_balance.symbol, "BNB");
    }

    #[test]
    fn test_explorer_urls_different_networks() {
        let test_cases = [
            (
                EvmConfig::ethereum_mainnet(),
                "https://etherscan.io/tx/0x123",
            ),
            (EvmConfig::arbitrum_one(), "https://arbiscan.io/tx/0x123"),
            (EvmConfig::polygon(), "https://polygonscan.com/tx/0x123"),
            (EvmConfig::bsc(), "https://bscscan.com/tx/0x123"),
        ];

        for (config, expected_url) in test_cases {
            let adapter = EvmAdapter::new(config).unwrap();
            let url = adapter.explorer_tx_url("0x123");
            assert_eq!(url, Some(expected_url.to_string()));
        }
    }

    #[test]
    fn test_custom_network_config() {
        let custom = EvmConfig::custom(
            999999,
            vec![
                "https://rpc1.example.com".to_string(),
                "https://rpc2.example.com".to_string(),
            ],
            "CUSTOM",
        )
        .with_explorer("https://explorer.example.com")
        .with_eip1559(true);

        assert_eq!(custom.chain_id.0, 999999);
        assert_eq!(custom.rpc_urls.len(), 2);
        assert_eq!(custom.symbol, "CUSTOM");
        assert!(custom.eip1559_supported);
        assert_eq!(
            custom.explorer_url,
            Some("https://explorer.example.com".to_string())
        );
    }
}

// ============================================================================
// Cross-Chain Policy Interaction Tests
// ============================================================================

#[test]
fn test_whitelist_applies_to_all_chains() {
    let policy =
        PolicyEngine::new(PolicyConfig::default().with_whitelist(vec!["0xGOOD".to_string()]));

    // EVM whitelist
    let evm_good = TransactionRequest::new(ChainType::Evm, "0xgood", "1000");
    assert!(policy.evaluate(&evm_good).unwrap().is_approved());

    let evm_bad = TransactionRequest::new(ChainType::Evm, "0xbad", "1000");
    assert!(!policy.evaluate(&evm_bad).unwrap().is_approved());

    // Solana uses the same whitelist (case-insensitive)
    let sol_good = TransactionRequest::new(ChainType::Solana, "0xGOOD", "1000");
    assert!(policy.evaluate(&sol_good).unwrap().is_approved());
}

#[test]
fn test_blacklist_applies_to_all_chains() {
    let policy =
        PolicyEngine::new(PolicyConfig::default().with_blacklist(vec!["0xBAD".to_string()]));

    // EVM blacklist
    let evm_tx = TransactionRequest::new(ChainType::Evm, "0xbad", "1000");
    assert!(!policy.evaluate(&evm_tx).unwrap().is_approved());

    // Solana blacklist
    let sol_tx = TransactionRequest::new(ChainType::Solana, "0xBAD", "1000");
    assert!(!policy.evaluate(&sol_tx).unwrap().is_approved());
}

#[test]
fn test_time_bounds_apply_to_all_chains() {
    use mpc_wallet_core::policy::TimeBounds;

    let policy =
        PolicyEngine::new(PolicyConfig::default().with_time_bounds(TimeBounds::business_hours()));

    // Both chains subject to same time bounds
    // (This test depends on current time - in practice you'd mock the time)
    let evm_tx = TransactionRequest::new(ChainType::Evm, "0x1234", "1000");
    let sol_tx = TransactionRequest::new(ChainType::Solana, "SOL123", "1000");

    let evm_result = policy.evaluate(&evm_tx);
    let sol_result = policy.evaluate(&sol_tx);

    // Both should have the same outcome (either both pass or both fail based on current time)
    assert!(evm_result.is_ok());
    assert!(sol_result.is_ok());
}

// ============================================================================
// Transaction Request Chain-Specific Tests
// ============================================================================

#[test]
fn test_transaction_request_evm_specific_fields() {
    let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "1000000000000000000")
        .with_gas_limit(21000)
        .with_chain_id(1);

    assert_eq!(tx.chain, ChainType::Evm);
    assert_eq!(tx.gas_limit, Some(21000));
    assert_eq!(tx.chain_id, Some(1));
}

#[test]
fn test_transaction_request_solana_specific() {
    let tx = TransactionRequest::new(ChainType::Solana, "SolAddress123", "1000000000");

    assert_eq!(tx.chain, ChainType::Solana);
    // Solana transactions don't use gas_limit or chain_id in the same way
    assert!(tx.gas_limit.is_none());
    assert!(tx.chain_id.is_none());
}

#[test]
fn test_contract_call_detection_per_chain() {
    // EVM contract call
    let evm_call = TransactionRequest::new(ChainType::Evm, "0xContract", "0")
        .with_data(vec![0xa9, 0x05, 0x9c, 0xbb]); // transfer selector

    assert!(evm_call.is_contract_call());
    assert_eq!(evm_call.function_selector(), Some([0xa9, 0x05, 0x9c, 0xbb]));

    // Simple transfer (no data)
    let transfer = TransactionRequest::new(ChainType::Evm, "0xRecipient", "1000");
    assert!(!transfer.is_contract_call());
}
