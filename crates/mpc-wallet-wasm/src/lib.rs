//! WASM bindings for MPC Agent Wallet
//!
//! This crate provides WebAssembly bindings for the MPC wallet core,
//! enabling use in browsers and Node.js environments.
//!
//! ## Features
//!
//! - `generateKeyShares()` - Distributed key generation ceremony
//! - `signTransaction(txParams, policyContext)` - MPC threshold signing
//! - `refreshShares()` - Proactive share refresh
//! - `deriveChildKey(path)` - BIP32 derivation
//!
//! ## Usage (JavaScript/TypeScript)
//!
//! ```javascript
//! import init, { MpcWallet, PolicyConfig } from 'mpc-wallet-wasm';
//!
//! await init();
//!
//! // Create a new wallet
//! const wallet = new MpcWallet();
//!
//! // Configure policy
//! const policy = PolicyConfig.withDailyLimit("1000000000000000000"); // 1 ETH
//!
//! // Sign a transaction (requires 2-of-3 parties)
//! const signature = await wallet.signMessage(messageHash);
//! ```

use serde::Serialize;
use wasm_bindgen::prelude::*;

mod error;
mod keygen;
mod policy;
mod signing;
mod storage;
mod types;
mod utils;

pub use error::WasmError;
pub use keygen::*;
pub use policy::*;
pub use signing::*;
pub use storage::*;
pub use types::*;

/// Initialize the WASM module with optional panic hook
#[wasm_bindgen(start)]
pub fn init() {
    utils::set_panic_hook();
}

/// Get the SDK version
#[wasm_bindgen(js_name = getVersion)]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Get the protocol version
#[wasm_bindgen(js_name = getProtocolVersion)]
pub fn get_protocol_version() -> String {
    "2-of-3-threshold-ecdsa".to_string()
}

// Re-export core types with JS-friendly names
#[wasm_bindgen]
pub struct WasmResult {
    success: bool,
    data: Option<String>,
    error: Option<String>,
}

#[wasm_bindgen]
impl WasmResult {
    #[wasm_bindgen(getter)]
    pub fn success(&self) -> bool {
        self.success
    }

    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Option<String> {
        self.data.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn error(&self) -> Option<String> {
        self.error.clone()
    }

    pub(crate) fn ok(data: impl Serialize) -> Self {
        Self {
            success: true,
            data: serde_json::to_string(&data).ok(),
            error: None,
        }
    }

    pub(crate) fn err(error: impl ToString) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error.to_string()),
        }
    }
}

/// Utility function to convert hex string to bytes
#[wasm_bindgen(js_name = hexToBytes)]
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, JsValue> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    hex::decode(hex).map_err(|e| JsValue::from_str(&format!("Invalid hex: {}", e)))
}

/// Utility function to convert bytes to hex string
#[wasm_bindgen(js_name = bytesToHex)]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Generate a random 32-byte seed for key generation
#[wasm_bindgen(js_name = generateRandomSeed)]
pub fn generate_random_seed() -> Vec<u8> {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    seed.to_vec()
}

/// Hash a message using Keccak256 (for Ethereum signing)
#[wasm_bindgen(js_name = keccak256)]
pub fn keccak256(data: &[u8]) -> Vec<u8> {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Hash a message with Ethereum prefix ("\x19Ethereum Signed Message:\n")
#[wasm_bindgen(js_name = hashEthMessage)]
pub fn hash_eth_message(message: &[u8]) -> Vec<u8> {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut data = prefix.into_bytes();
    data.extend_from_slice(message);
    keccak256(&data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_version() {
        let version = get_version();
        assert!(!version.is_empty());
    }

    #[wasm_bindgen_test]
    fn test_hex_conversion() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "0xdeadbeef");

        let decoded = hex_to_bytes(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[wasm_bindgen_test]
    fn test_random_seed() {
        let seed1 = generate_random_seed();
        let seed2 = generate_random_seed();
        assert_eq!(seed1.len(), 32);
        assert_ne!(seed1, seed2);
    }
}
