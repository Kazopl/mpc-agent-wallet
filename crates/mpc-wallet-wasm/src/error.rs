//! WASM-compatible error types

use thiserror::Error;
use wasm_bindgen::prelude::*;

/// Errors that can occur in WASM operations
#[derive(Debug, Error)]
pub enum WasmError {
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Key generation error: {0}")]
    KeyGeneration(String),

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Invalid key share: {0}")]
    InvalidKeyShare(String),

    #[error("Threshold not met: required {required}, got {actual}")]
    ThresholdNotMet { required: usize, actual: usize },

    #[error("Core error: {0}")]
    Core(String),
}

impl From<WasmError> for JsValue {
    fn from(err: WasmError) -> Self {
        JsValue::from_str(&err.to_string())
    }
}

impl From<mpc_wallet_core::Error> for WasmError {
    fn from(err: mpc_wallet_core::Error) -> Self {
        WasmError::Core(err.to_string())
    }
}

impl From<serde_json::Error> for WasmError {
    fn from(err: serde_json::Error) -> Self {
        WasmError::Serialization(err.to_string())
    }
}

/// Convert a Result to JsValue for WASM compatibility
pub fn to_js_result<T: serde::Serialize>(result: Result<T, WasmError>) -> Result<JsValue, JsValue> {
    match result {
        Ok(value) => {
            serde_wasm_bindgen::to_value(&value).map_err(|e| JsValue::from_str(&e.to_string()))
        }
        Err(err) => Err(JsValue::from(err)),
    }
}
