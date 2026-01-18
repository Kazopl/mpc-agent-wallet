//! Integration tests for Base chain support
//!
//! Tests Base mainnet and Base Sepolia testnet configurations

use mpc_wallet_core::chain::{ChainAdapter, ChainId, EvmAdapter, EvmConfig};

/// Test Base Sepolia configuration
#[test]
fn test_base_sepolia_config() {
    let config = EvmConfig::base_sepolia();

    assert_eq!(config.chain_id.0, 84532);
    assert_eq!(config.symbol, "ETH");
    assert_eq!(config.decimals, 18);
    assert!(config.eip1559_supported);
    assert_eq!(
        config.explorer_url,
        Some("https://sepolia.basescan.org".to_string())
    );
    assert!(!config.rpc_urls.is_empty());
}

/// Test Base mainnet configuration
#[test]
fn test_base_mainnet_config() {
    let config = EvmConfig::base();

    assert_eq!(config.chain_id.0, 8453);
    assert_eq!(config.symbol, "ETH");
    assert_eq!(config.decimals, 18);
    assert!(config.eip1559_supported);
    assert_eq!(
        config.explorer_url,
        Some("https://basescan.org".to_string())
    );
}

/// Test Base chain ID constants
#[test]
fn test_base_chain_id_constants() {
    assert_eq!(ChainId::BASE.0, 8453);
    assert_eq!(ChainId::BASE_SEPOLIA.0, 84532);

    // Verify names
    assert_eq!(ChainId::BASE.name(), "Base");
    assert_eq!(ChainId::BASE_SEPOLIA.name(), "Base Sepolia");

    // Both should be EVM chains
    assert!(ChainId::BASE.is_evm());
    assert!(ChainId::BASE_SEPOLIA.is_evm());
    assert!(!ChainId::BASE.is_solana());
    assert!(!ChainId::BASE_SEPOLIA.is_solana());
}

/// Test creating Base Sepolia adapter
#[test]
fn test_base_sepolia_adapter_creation() {
    let config = EvmConfig::base_sepolia();
    let adapter = EvmAdapter::new(config).expect("Failed to create Base Sepolia adapter");

    assert_eq!(adapter.chain_id().0, 84532);
    assert_eq!(adapter.native_symbol(), "ETH");
    assert_eq!(adapter.native_decimals(), 18);
}

/// Test creating Base mainnet adapter
#[test]
fn test_base_mainnet_adapter_creation() {
    let config = EvmConfig::base();
    let adapter = EvmAdapter::new(config).expect("Failed to create Base adapter");

    assert_eq!(adapter.chain_id().0, 8453);
    assert_eq!(adapter.native_symbol(), "ETH");
    assert_eq!(adapter.native_decimals(), 18);
}

/// Test Base Sepolia address validation
#[test]
fn test_base_sepolia_address_validation() {
    let config = EvmConfig::base_sepolia();
    let adapter = EvmAdapter::new(config).unwrap();

    // Valid addresses
    assert!(adapter.is_valid_address("0x742d35Cc6634C0532925a3b844Bc9e7595f4e123"));
    assert!(adapter.is_valid_address("0x0000000000000000000000000000000000000000"));

    // Invalid addresses
    assert!(!adapter.is_valid_address("0x742d35Cc")); // Too short
    assert!(!adapter.is_valid_address("742d35Cc6634C0532925a3b844Bc9e7595f4e123")); // No prefix
    assert!(!adapter.is_valid_address("0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG")); // Invalid hex
}

/// Test Base Sepolia explorer URLs
#[test]
fn test_base_sepolia_explorer_urls() {
    let config = EvmConfig::base_sepolia();
    let adapter = EvmAdapter::new(config).unwrap();

    let tx_url = adapter.explorer_tx_url("0x1234567890abcdef");
    assert_eq!(
        tx_url,
        Some("https://sepolia.basescan.org/tx/0x1234567890abcdef".to_string())
    );

    let addr_url = adapter.explorer_address_url("0x742d35Cc6634C0532925a3b844Bc9e7595f4e123");
    assert_eq!(
        addr_url,
        Some("https://sepolia.basescan.org/address/0x742d35Cc6634C0532925a3b844Bc9e7595f4e123".to_string())
    );
}

/// Test Base mainnet explorer URLs
#[test]
fn test_base_mainnet_explorer_urls() {
    let config = EvmConfig::base();
    let adapter = EvmAdapter::new(config).unwrap();

    let tx_url = adapter.explorer_tx_url("0x1234567890abcdef");
    assert_eq!(
        tx_url,
        Some("https://basescan.org/tx/0x1234567890abcdef".to_string())
    );

    let addr_url = adapter.explorer_address_url("0x742d35Cc6634C0532925a3b844Bc9e7595f4e123");
    assert_eq!(
        addr_url,
        Some("https://basescan.org/address/0x742d35Cc6634C0532925a3b844Bc9e7595f4e123".to_string())
    );
}

/// Test address derivation works on Base chains
#[test]
fn test_base_address_derivation() {
    let config = EvmConfig::base_sepolia();
    let adapter = EvmAdapter::new(config).unwrap();

    // Test with an uncompressed public key (65 bytes with 0x04 prefix)
    let pk = hex::decode(
        "04e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39"
    ).unwrap();

    let address = adapter.derive_address(&pk).unwrap();

    // Verify it's a valid address format
    assert!(address.starts_with("0x"));
    assert_eq!(address.len(), 42);
    assert!(adapter.is_valid_address(&address));
}

// ============================================================================
// Network Tests (require actual RPC connection)
// ============================================================================

#[cfg(feature = "integration-tests")]
mod network_tests {
    use super::*;

    /// Test actual RPC connection to Base Sepolia
    #[tokio::test]
    async fn test_base_sepolia_rpc_connection() {
        let config = EvmConfig::base_sepolia();
        let adapter = EvmAdapter::new(config).unwrap();

        // Try to get balance of a known address (zero address for simplicity)
        let balance = adapter
            .get_balance("0x0000000000000000000000000000000000000000")
            .await;

        // Should succeed (might be zero balance, but connection should work)
        assert!(balance.is_ok(), "Failed to connect to Base Sepolia RPC");
    }

    /// Test actual RPC connection to Base mainnet
    #[tokio::test]
    async fn test_base_mainnet_rpc_connection() {
        let config = EvmConfig::base();
        let adapter = EvmAdapter::new(config).unwrap();

        // Try to get balance of a known address
        let balance = adapter
            .get_balance("0x0000000000000000000000000000000000000000")
            .await;

        assert!(balance.is_ok(), "Failed to connect to Base mainnet RPC");
    }

    /// Test gas price fetching on Base Sepolia
    #[tokio::test]
    async fn test_base_sepolia_gas_prices() {
        let config = EvmConfig::base_sepolia();
        let adapter = EvmAdapter::new(config).unwrap();

        let gas_prices = adapter.get_gas_prices().await;

        assert!(gas_prices.is_ok(), "Failed to fetch gas prices");
        let prices = gas_prices.unwrap();

        // Base supports EIP-1559, so base_fee should be present
        assert!(prices.base_fee.is_some());
    }
}
