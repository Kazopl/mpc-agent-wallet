//! Unit tests for Chain Adapters
//!
//! These tests verify the correctness of chain-specific operations including:
//! - Address derivation and validation
//! - Balance formatting
//! - Transaction building
//! - Gas price handling

use mpc_wallet_core::chain::{
    Balance, ChainId, GasPrice, GasPrices, TxParams, TxPriority, TxSummary, UnsignedTx,
};

#[cfg(feature = "evm")]
use mpc_wallet_core::chain::{EvmAdapter, EvmConfig};

// ============================================================================
// ChainId Tests
// ============================================================================

#[test]
fn test_chain_id_evm_chains() {
    assert_eq!(ChainId::ETHEREUM_MAINNET.0, 1);
    assert_eq!(ChainId::ETHEREUM_SEPOLIA.0, 11155111);
    assert_eq!(ChainId::ARBITRUM_ONE.0, 42161);
    assert_eq!(ChainId::OPTIMISM.0, 10);
    assert_eq!(ChainId::BASE.0, 8453);
    assert_eq!(ChainId::POLYGON.0, 137);
    assert_eq!(ChainId::BSC.0, 56);
    assert_eq!(ChainId::AVALANCHE.0, 43114);
}

#[test]
fn test_chain_id_solana_chains() {
    assert_eq!(ChainId::SOLANA_MAINNET.0, 101);
    assert_eq!(ChainId::SOLANA_DEVNET.0, 102);
    assert_eq!(ChainId::SOLANA_TESTNET.0, 103);
}

#[test]
fn test_chain_id_names() {
    assert_eq!(ChainId::ETHEREUM_MAINNET.name(), "Ethereum Mainnet");
    assert_eq!(ChainId::ETHEREUM_SEPOLIA.name(), "Ethereum Sepolia");
    assert_eq!(ChainId::ARBITRUM_ONE.name(), "Arbitrum One");
    assert_eq!(ChainId::OPTIMISM.name(), "Optimism");
    assert_eq!(ChainId::BASE.name(), "Base");
    assert_eq!(ChainId::POLYGON.name(), "Polygon");
    assert_eq!(ChainId::BSC.name(), "BNB Smart Chain");
    assert_eq!(ChainId::AVALANCHE.name(), "Avalanche C-Chain");
    assert_eq!(ChainId::SOLANA_MAINNET.name(), "Solana Mainnet");
}

#[test]
fn test_chain_id_is_evm() {
    assert!(ChainId::ETHEREUM_MAINNET.is_evm());
    assert!(ChainId::ARBITRUM_ONE.is_evm());
    assert!(ChainId::POLYGON.is_evm());
    assert!(!ChainId::SOLANA_MAINNET.is_evm());
    assert!(!ChainId::SOLANA_DEVNET.is_evm());
}

#[test]
fn test_chain_id_is_solana() {
    assert!(ChainId::SOLANA_MAINNET.is_solana());
    assert!(ChainId::SOLANA_DEVNET.is_solana());
    assert!(ChainId::SOLANA_TESTNET.is_solana());
    assert!(!ChainId::ETHEREUM_MAINNET.is_solana());
    assert!(!ChainId::ARBITRUM_ONE.is_solana());
}

#[test]
fn test_chain_id_from_u64() {
    let chain_id: ChainId = 1u64.into();
    assert_eq!(chain_id.0, 1);

    let chain_id: ChainId = 42161u64.into();
    assert_eq!(chain_id.0, 42161);
}

#[test]
fn test_chain_id_display() {
    let display = format!("{}", ChainId::ETHEREUM_MAINNET);
    assert!(display.contains("Ethereum Mainnet"));
    assert!(display.contains("1"));
}

// ============================================================================
// Balance Tests
// ============================================================================

#[test]
fn test_balance_formatting_eth() {
    // 1 ETH = 10^18 wei
    let balance = Balance::new("1000000000000000000", 18, "ETH");
    assert_eq!(balance.formatted, "1");
    assert_eq!(balance.symbol, "ETH");
    assert_eq!(balance.decimals, 18);
}

#[test]
fn test_balance_formatting_fractional() {
    // 1.5 ETH
    let balance = Balance::new("1500000000000000000", 18, "ETH");
    assert_eq!(balance.formatted, "1.5");

    // 0.001 ETH
    let balance = Balance::new("1000000000000000", 18, "ETH");
    assert_eq!(balance.formatted, "0.001");

    // 0.123456789 ETH
    let balance = Balance::new("123456789000000000", 18, "ETH");
    assert_eq!(balance.formatted, "0.123456789");
}

#[test]
fn test_balance_formatting_zero() {
    let balance = Balance::new("0", 18, "ETH");
    assert_eq!(balance.formatted, "0");
}

#[test]
fn test_balance_formatting_small_decimals() {
    // USDC has 6 decimals
    let balance = Balance::new("1000000", 6, "USDC");
    assert_eq!(balance.formatted, "1");

    let balance = Balance::new("1500000", 6, "USDC");
    assert_eq!(balance.formatted, "1.5");
}

#[test]
fn test_balance_is_zero() {
    let zero = Balance::new("0", 18, "ETH");
    assert!(zero.is_zero());

    let empty = Balance::new("", 18, "ETH");
    assert!(empty.is_zero());

    let nonzero = Balance::new("1", 18, "ETH");
    assert!(!nonzero.is_zero());
}

#[test]
fn test_balance_raw_value() {
    let balance = Balance::new("1500000000000000000", 18, "ETH");
    assert_eq!(balance.raw_value(), 1500000000000000000u128);

    let zero = Balance::new("0", 18, "ETH");
    assert_eq!(zero.raw_value(), 0u128);
}

// ============================================================================
// TxParams Tests
// ============================================================================

#[test]
fn test_tx_params_basic() {
    let params = TxParams::new("0xfrom", "0xto", "1.0");

    assert_eq!(params.from, "0xfrom");
    assert_eq!(params.to, "0xto");
    assert_eq!(params.value, "1.0");
    assert!(params.data.is_none());
    assert!(params.gas_limit.is_none());
    assert!(params.nonce.is_none());
    assert_eq!(params.priority, TxPriority::Medium);
}

#[test]
fn test_tx_params_with_data() {
    let data = vec![0xa9, 0x05, 0x9c, 0xbb];
    let params = TxParams::new("0xfrom", "0xto", "0").with_data(data.clone());

    assert_eq!(params.data, Some(data));
}

#[test]
fn test_tx_params_with_gas_limit() {
    let params = TxParams::new("0xfrom", "0xto", "1.0").with_gas_limit(21000);

    assert_eq!(params.gas_limit, Some(21000));
}

#[test]
fn test_tx_params_with_nonce() {
    let params = TxParams::new("0xfrom", "0xto", "1.0").with_nonce(42);

    assert_eq!(params.nonce, Some(42));
}

#[test]
fn test_tx_params_with_priority() {
    let low = TxParams::new("0xfrom", "0xto", "1.0").with_priority(TxPriority::Low);
    assert_eq!(low.priority, TxPriority::Low);

    let high = TxParams::new("0xfrom", "0xto", "1.0").with_priority(TxPriority::High);
    assert_eq!(high.priority, TxPriority::High);

    let urgent = TxParams::new("0xfrom", "0xto", "1.0").with_priority(TxPriority::Urgent);
    assert_eq!(urgent.priority, TxPriority::Urgent);
}

#[test]
fn test_tx_params_chained() {
    let params = TxParams::new("0xfrom", "0xto", "1.0")
        .with_data(vec![0x12, 0x34])
        .with_gas_limit(100000)
        .with_nonce(5)
        .with_priority(TxPriority::High);

    assert_eq!(params.data, Some(vec![0x12, 0x34]));
    assert_eq!(params.gas_limit, Some(100000));
    assert_eq!(params.nonce, Some(5));
    assert_eq!(params.priority, TxPriority::High);
}

// ============================================================================
// TxPriority Tests
// ============================================================================

#[test]
fn test_tx_priority_default() {
    let priority = TxPriority::default();
    assert_eq!(priority, TxPriority::Medium);
}

#[test]
fn test_tx_priority_equality() {
    assert_eq!(TxPriority::Low, TxPriority::Low);
    assert_eq!(TxPriority::Medium, TxPriority::Medium);
    assert_eq!(TxPriority::High, TxPriority::High);
    assert_eq!(TxPriority::Urgent, TxPriority::Urgent);

    assert_ne!(TxPriority::Low, TxPriority::High);
}

// ============================================================================
// GasPrice Tests
// ============================================================================

#[test]
fn test_gas_prices_structure() {
    let prices = GasPrices {
        low: GasPrice {
            max_fee: 10_000_000_000,
            max_priority_fee: 1_000_000_000,
            estimated_wait_secs: Some(60),
        },
        medium: GasPrice {
            max_fee: 20_000_000_000,
            max_priority_fee: 2_000_000_000,
            estimated_wait_secs: Some(30),
        },
        high: GasPrice {
            max_fee: 30_000_000_000,
            max_priority_fee: 5_000_000_000,
            estimated_wait_secs: Some(15),
        },
        base_fee: Some(8_000_000_000),
    };

    assert!(prices.low.max_fee < prices.medium.max_fee);
    assert!(prices.medium.max_fee < prices.high.max_fee);
    assert!(prices.low.estimated_wait_secs.unwrap() > prices.high.estimated_wait_secs.unwrap());
}

// ============================================================================
// EVM Adapter Tests (require evm feature)
// ============================================================================

#[cfg(feature = "evm")]
mod evm_tests {
    use super::*;
    use mpc_wallet_core::chain::ChainAdapter;

    #[test]
    fn test_evm_config_ethereum_mainnet() {
        let config = EvmConfig::ethereum_mainnet();

        assert_eq!(config.chain_id.0, 1);
        assert_eq!(config.symbol, "ETH");
        assert_eq!(config.decimals, 18);
        assert!(config.eip1559_supported);
        assert!(!config.rpc_urls.is_empty());
        assert!(config.explorer_url.is_some());
    }

    #[test]
    fn test_evm_config_sepolia() {
        let config = EvmConfig::ethereum_sepolia();

        assert_eq!(config.chain_id.0, 11155111);
        assert_eq!(config.symbol, "ETH");
        assert!(config.eip1559_supported);
    }

    #[test]
    fn test_evm_config_arbitrum() {
        let config = EvmConfig::arbitrum_one();

        assert_eq!(config.chain_id.0, 42161);
        assert_eq!(config.symbol, "ETH");
        assert!(config.eip1559_supported);
    }

    #[test]
    fn test_evm_config_base() {
        let config = EvmConfig::base();

        assert_eq!(config.chain_id.0, 8453);
        assert_eq!(config.symbol, "ETH");
    }

    #[test]
    fn test_evm_config_optimism() {
        let config = EvmConfig::optimism();

        assert_eq!(config.chain_id.0, 10);
        assert_eq!(config.symbol, "ETH");
    }

    #[test]
    fn test_evm_config_polygon() {
        let config = EvmConfig::polygon();

        assert_eq!(config.chain_id.0, 137);
        assert_eq!(config.symbol, "MATIC");
    }

    #[test]
    fn test_evm_config_bsc() {
        let config = EvmConfig::bsc();

        assert_eq!(config.chain_id.0, 56);
        assert_eq!(config.symbol, "BNB");
        assert!(!config.eip1559_supported); // BSC doesn't support EIP-1559
    }

    #[test]
    fn test_evm_config_custom() {
        let config =
            EvmConfig::custom(12345, vec!["https://rpc.example.com".to_string()], "CUSTOM");

        assert_eq!(config.chain_id.0, 12345);
        assert_eq!(config.symbol, "CUSTOM");
        assert_eq!(config.rpc_urls.len(), 1);
    }

    #[test]
    fn test_evm_config_with_explorer() {
        let config = EvmConfig::custom(1, vec!["https://rpc.example.com".to_string()], "ETH")
            .with_explorer("https://explorer.example.com");

        assert_eq!(
            config.explorer_url,
            Some("https://explorer.example.com".to_string())
        );
    }

    #[test]
    fn test_evm_config_with_eip1559() {
        let config = EvmConfig::custom(1, vec!["https://rpc.example.com".to_string()], "ETH")
            .with_eip1559(false);

        assert!(!config.eip1559_supported);
    }

    #[test]
    fn test_evm_adapter_creation() {
        let config = EvmConfig::ethereum_mainnet();
        let adapter = EvmAdapter::new(config);

        assert!(adapter.is_ok());
    }

    #[test]
    fn test_evm_adapter_chain_id() {
        let adapter = EvmAdapter::new(EvmConfig::ethereum_mainnet()).unwrap();

        assert_eq!(adapter.chain_id().0, 1);
    }

    #[test]
    fn test_evm_adapter_native_symbol() {
        let eth_adapter = EvmAdapter::new(EvmConfig::ethereum_mainnet()).unwrap();
        assert_eq!(eth_adapter.native_symbol(), "ETH");

        let polygon_adapter = EvmAdapter::new(EvmConfig::polygon()).unwrap();
        assert_eq!(polygon_adapter.native_symbol(), "MATIC");
    }

    #[test]
    fn test_evm_adapter_native_decimals() {
        let adapter = EvmAdapter::new(EvmConfig::ethereum_mainnet()).unwrap();
        assert_eq!(adapter.native_decimals(), 18);
    }

    #[test]
    fn test_evm_address_validation_valid() {
        let adapter = EvmAdapter::new(EvmConfig::ethereum_mainnet()).unwrap();

        assert!(adapter.is_valid_address("0x742d35Cc6634C0532925a3b844Bc9e7595f4e123"));
        assert!(adapter.is_valid_address("0x0000000000000000000000000000000000000000"));
        assert!(adapter.is_valid_address("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));
    }

    #[test]
    fn test_evm_address_validation_invalid() {
        let adapter = EvmAdapter::new(EvmConfig::ethereum_mainnet()).unwrap();

        // Too short
        assert!(!adapter.is_valid_address("0x742d35Cc"));

        // No 0x prefix
        assert!(!adapter.is_valid_address("742d35Cc6634C0532925a3b844Bc9e7595f4e123"));

        // Invalid hex characters
        assert!(!adapter.is_valid_address("0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"));

        // Too long
        assert!(!adapter.is_valid_address("0x742d35Cc6634C0532925a3b844Bc9e7595f4e12300"));

        // Empty
        assert!(!adapter.is_valid_address(""));
        assert!(!adapter.is_valid_address("0x"));
    }

    #[test]
    fn test_evm_derive_address_uncompressed() {
        let adapter = EvmAdapter::new(EvmConfig::ethereum_mainnet()).unwrap();

        // Test with uncompressed public key (65 bytes)
        let pk = hex::decode(
            "04e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39"
        ).unwrap();

        let address = adapter.derive_address(&pk).unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
        assert!(adapter.is_valid_address(&address));
    }

    #[test]
    fn test_evm_derive_address_compressed() {
        let adapter = EvmAdapter::new(EvmConfig::ethereum_mainnet()).unwrap();

        // Test with compressed public key (33 bytes)
        let pk = hex::decode("02e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606")
            .unwrap();

        let address = adapter.derive_address(&pk).unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_evm_derive_address_invalid_length() {
        let adapter = EvmAdapter::new(EvmConfig::ethereum_mainnet()).unwrap();

        // Invalid length (should be 33 or 65, not 32)
        let invalid_pk = vec![0u8; 32];
        let result = adapter.derive_address(&invalid_pk);

        assert!(result.is_err());
    }

    #[test]
    fn test_evm_explorer_urls() {
        let adapter = EvmAdapter::new(EvmConfig::ethereum_mainnet()).unwrap();

        let tx_url = adapter.explorer_tx_url("0x123abc");
        assert_eq!(tx_url, Some("https://etherscan.io/tx/0x123abc".to_string()));

        let addr_url = adapter.explorer_address_url("0x456def");
        assert_eq!(
            addr_url,
            Some("https://etherscan.io/address/0x456def".to_string())
        );
    }

    #[test]
    fn test_evm_explorer_urls_no_explorer() {
        let config = EvmConfig::custom(12345, vec!["https://rpc.example.com".to_string()], "TEST");
        let adapter = EvmAdapter::new(config).unwrap();

        assert!(adapter.explorer_tx_url("0x123").is_none());
        assert!(adapter.explorer_address_url("0x456").is_none());
    }
}

// ============================================================================
// TxSummary Tests
// ============================================================================

#[test]
fn test_tx_summary_structure() {
    let summary = TxSummary {
        tx_type: "Transfer".to_string(),
        from: "0xfrom".to_string(),
        to: "0xto".to_string(),
        value: "1.0 ETH".to_string(),
        estimated_fee: "0.001 ETH".to_string(),
        details: Some("Test transaction".to_string()),
    };

    assert_eq!(summary.tx_type, "Transfer");
    assert_eq!(summary.from, "0xfrom");
    assert_eq!(summary.to, "0xto");
    assert!(summary.details.is_some());
}

#[test]
fn test_tx_summary_no_details() {
    let summary = TxSummary {
        tx_type: "Contract Call".to_string(),
        from: "0xfrom".to_string(),
        to: "0xcontract".to_string(),
        value: "0 ETH".to_string(),
        estimated_fee: "0.005 ETH".to_string(),
        details: None,
    };

    assert!(summary.details.is_none());
}

// ============================================================================
// UnsignedTx Tests
// ============================================================================

#[test]
fn test_unsigned_tx_structure() {
    let unsigned = UnsignedTx {
        chain_id: ChainId::ETHEREUM_MAINNET,
        signing_payload: vec![1, 2, 3, 4],
        raw_tx: vec![5, 6, 7, 8],
        summary: TxSummary {
            tx_type: "Transfer".to_string(),
            from: "0xfrom".to_string(),
            to: "0xto".to_string(),
            value: "1.0 ETH".to_string(),
            estimated_fee: "0.001 ETH".to_string(),
            details: None,
        },
    };

    assert_eq!(unsigned.chain_id.0, 1);
    assert!(!unsigned.signing_payload.is_empty());
    assert!(!unsigned.raw_tx.is_empty());
}
