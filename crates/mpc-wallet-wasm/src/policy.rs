//! WASM bindings for policy engine

use crate::error::WasmError;
use crate::types::{ChainType, TransactionRequest};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Policy decision result
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Whether the transaction is approved
    pub approved: bool,
    /// Whether additional approval is required
    #[wasm_bindgen(js_name = requiresAdditionalApproval)]
    pub requires_additional_approval: bool,
    /// Reason for rejection (if any)
    pub reason: Option<String>,
}

#[wasm_bindgen]
impl PolicyDecision {
    /// Check if transaction should proceed
    #[wasm_bindgen(js_name = canProceed)]
    pub fn can_proceed(&self) -> bool {
        self.approved || self.requires_additional_approval
    }

    /// Get as JSON
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

impl From<mpc_wallet_core::PolicyDecision> for PolicyDecision {
    fn from(decision: mpc_wallet_core::PolicyDecision) -> Self {
        match decision {
            mpc_wallet_core::PolicyDecision::Approve => PolicyDecision {
                approved: true,
                requires_additional_approval: false,
                reason: None,
            },
            mpc_wallet_core::PolicyDecision::Reject { reason } => PolicyDecision {
                approved: false,
                requires_additional_approval: false,
                reason: Some(reason),
            },
            mpc_wallet_core::PolicyDecision::RequireAdditionalApproval { reason } => {
                PolicyDecision {
                    approved: false,
                    requires_additional_approval: true,
                    reason: Some(reason),
                }
            }
        }
    }
}

/// Spending limits configuration
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpendingLimits {
    /// Per-transaction limit (in wei/smallest unit)
    #[wasm_bindgen(js_name = perTransaction)]
    pub per_transaction: Option<String>,
    /// Daily limit
    pub daily: Option<String>,
    /// Weekly limit
    pub weekly: Option<String>,
    /// Currency symbol
    pub currency: String,
}

#[wasm_bindgen]
impl SpendingLimits {
    /// Create new spending limits
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            per_transaction: None,
            daily: None,
            weekly: None,
            currency: "ETH".to_string(),
        }
    }

    /// Set per-transaction limit
    #[wasm_bindgen(js_name = withPerTxLimit)]
    pub fn with_per_tx_limit(mut self, limit: String) -> Self {
        self.per_transaction = Some(limit);
        self
    }

    /// Set daily limit
    #[wasm_bindgen(js_name = withDailyLimit)]
    pub fn with_daily_limit(mut self, limit: String) -> Self {
        self.daily = Some(limit);
        self
    }

    /// Set weekly limit
    #[wasm_bindgen(js_name = withWeeklyLimit)]
    pub fn with_weekly_limit(mut self, limit: String) -> Self {
        self.weekly = Some(limit);
        self
    }

    /// Set currency
    #[wasm_bindgen(js_name = withCurrency)]
    pub fn with_currency(mut self, currency: String) -> Self {
        self.currency = currency;
        self
    }
}

/// Time window restriction
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBounds {
    /// Start hour (0-23, UTC)
    start_hour: u8,
    /// End hour (0-23, UTC)
    end_hour: u8,
    /// Allowed days (0=Sunday, 6=Saturday)
    allowed_days: Vec<u8>,
}

#[wasm_bindgen]
impl TimeBounds {
    /// Create default time bounds (all times allowed)
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            start_hour: 0,
            end_hour: 24,
            allowed_days: vec![0, 1, 2, 3, 4, 5, 6],
        }
    }

    /// Get start hour
    #[wasm_bindgen(getter, js_name = startHour)]
    pub fn start_hour(&self) -> u8 {
        self.start_hour
    }

    /// Get end hour
    #[wasm_bindgen(getter, js_name = endHour)]
    pub fn end_hour(&self) -> u8 {
        self.end_hour
    }

    /// Get allowed days
    #[wasm_bindgen(getter, js_name = allowedDays)]
    pub fn allowed_days(&self) -> Vec<u8> {
        self.allowed_days.clone()
    }

    /// Create business hours restriction (9 AM - 5 PM UTC, weekdays)
    #[wasm_bindgen(js_name = businessHours)]
    pub fn business_hours() -> Self {
        Self {
            start_hour: 9,
            end_hour: 17,
            allowed_days: vec![1, 2, 3, 4, 5],
        }
    }

    /// Set start hour
    #[wasm_bindgen(js_name = withStartHour)]
    pub fn with_start_hour(mut self, hour: u8) -> Self {
        self.start_hour = hour;
        self
    }

    /// Set end hour
    #[wasm_bindgen(js_name = withEndHour)]
    pub fn with_end_hour(mut self, hour: u8) -> Self {
        self.end_hour = hour;
        self
    }

    /// Set allowed days
    #[wasm_bindgen(js_name = withAllowedDays)]
    pub fn with_allowed_days(mut self, days: Vec<u8>) -> Self {
        self.allowed_days = days;
        self
    }
}

impl Default for TimeBounds {
    fn default() -> Self {
        Self::new()
    }
}

/// Policy configuration
#[wasm_bindgen]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Spending limits (per chain type)
    spending_limits: Option<SpendingLimits>,
    /// Whitelisted addresses (JSON array)
    whitelist: Option<String>,
    /// Blacklisted addresses (JSON array)
    blacklist: Option<String>,
    /// Time restrictions
    time_bounds: Option<TimeBounds>,
    /// Additional approval threshold (in wei)
    additional_approval_threshold: Option<String>,
    /// Whether policy is enabled
    enabled: bool,
}

#[wasm_bindgen]
impl PolicyConfig {
    /// Create a new policy config
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            spending_limits: None,
            whitelist: None,
            blacklist: None,
            time_bounds: None,
            additional_approval_threshold: None,
            enabled: true,
        }
    }

    /// Create a disabled policy (all transactions allowed)
    #[wasm_bindgen]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Set spending limits
    #[wasm_bindgen(js_name = withSpendingLimits)]
    pub fn with_spending_limits(mut self, limits: SpendingLimits) -> Self {
        self.spending_limits = Some(limits);
        self
    }

    /// Set whitelist (JSON array of addresses)
    #[wasm_bindgen(js_name = withWhitelist)]
    pub fn with_whitelist(mut self, addresses: String) -> Self {
        self.whitelist = Some(addresses);
        self
    }

    /// Set blacklist (JSON array of addresses)
    #[wasm_bindgen(js_name = withBlacklist)]
    pub fn with_blacklist(mut self, addresses: String) -> Self {
        self.blacklist = Some(addresses);
        self
    }

    /// Set time bounds
    #[wasm_bindgen(js_name = withTimeBounds)]
    pub fn with_time_bounds(mut self, bounds: TimeBounds) -> Self {
        self.time_bounds = Some(bounds);
        self
    }

    /// Set additional approval threshold
    #[wasm_bindgen(js_name = withAdditionalApprovalThreshold)]
    pub fn with_additional_approval_threshold(mut self, threshold: String) -> Self {
        self.additional_approval_threshold = Some(threshold);
        self
    }

    /// Convert to JSON
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Create from JSON
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(json: &str) -> Result<PolicyConfig, JsValue> {
        serde_json::from_str(json).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Check if policy is enabled
    #[wasm_bindgen(js_name = isEnabled)]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl TryFrom<&PolicyConfig> for mpc_wallet_core::PolicyConfig {
    type Error = WasmError;

    fn try_from(config: &PolicyConfig) -> Result<Self, Self::Error> {
        let mut core_config = mpc_wallet_core::PolicyConfig::new();
        core_config.enabled = config.enabled;

        if let Some(ref limits) = config.spending_limits {
            let mut core_limits = mpc_wallet_core::policy::SpendingLimits::default();
            core_limits.currency = limits.currency.clone();

            if let Some(ref per_tx) = limits.per_transaction {
                core_limits.per_transaction = per_tx.parse().ok();
            }
            if let Some(ref daily) = limits.daily {
                core_limits.daily = daily.parse().ok();
            }
            if let Some(ref weekly) = limits.weekly {
                core_limits.weekly = weekly.parse().ok();
            }

            core_config =
                core_config.with_spending_limits(mpc_wallet_core::ChainType::Evm, core_limits);
        }

        if let Some(ref whitelist) = config.whitelist {
            let addresses: Vec<String> = serde_json::from_str(whitelist)
                .map_err(|e| WasmError::Deserialization(e.to_string()))?;
            core_config = core_config.with_whitelist(addresses);
        }

        if let Some(ref blacklist) = config.blacklist {
            let addresses: Vec<String> = serde_json::from_str(blacklist)
                .map_err(|e| WasmError::Deserialization(e.to_string()))?;
            core_config = core_config.with_blacklist(addresses);
        }

        if let Some(ref bounds) = config.time_bounds {
            let core_bounds = mpc_wallet_core::policy::TimeBounds {
                start_hour: bounds.start_hour,
                end_hour: bounds.end_hour,
                allowed_days: bounds.allowed_days.clone(),
            };
            core_config = core_config.with_time_bounds(core_bounds);
        }

        if let Some(ref threshold) = config.additional_approval_threshold {
            if let Ok(value) = threshold.parse::<u128>() {
                core_config = core_config.with_additional_approval_threshold(value);
            }
        }

        Ok(core_config)
    }
}

/// Policy engine for evaluating transactions
#[wasm_bindgen]
pub struct PolicyEngine {
    inner: mpc_wallet_core::PolicyEngine,
}

#[wasm_bindgen]
impl PolicyEngine {
    /// Create a new policy engine
    #[wasm_bindgen(constructor)]
    pub fn new(config: &PolicyConfig) -> Result<PolicyEngine, JsValue> {
        let core_config: mpc_wallet_core::PolicyConfig = config
            .try_into()
            .map_err(|e: WasmError| JsValue::from_str(&e.to_string()))?;

        Ok(PolicyEngine {
            inner: mpc_wallet_core::PolicyEngine::new(core_config),
        })
    }

    /// Evaluate a transaction request
    #[wasm_bindgen]
    pub fn evaluate(&self, tx: &TransactionRequest) -> Result<PolicyDecision, JsValue> {
        let core_tx: mpc_wallet_core::TransactionRequest = tx.into();
        let decision = self
            .inner
            .evaluate(&core_tx)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(decision.into())
    }

    /// Record a transaction (for spending tracking)
    #[wasm_bindgen(js_name = recordTransaction)]
    pub fn record_transaction(&self, tx: &TransactionRequest) -> Result<(), JsValue> {
        let core_tx: mpc_wallet_core::TransactionRequest = tx.into();
        self.inner
            .record_transaction(&core_tx)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Get daily spending for a chain
    #[wasm_bindgen(js_name = getDailySpending)]
    pub fn get_daily_spending(&self, chain: ChainType) -> String {
        self.inner.daily_spending(chain.into()).to_string()
    }

    /// Get weekly spending for a chain
    #[wasm_bindgen(js_name = getWeeklySpending)]
    pub fn get_weekly_spending(&self, chain: ChainType) -> String {
        self.inner.weekly_spending(chain.into()).to_string()
    }

    /// Reset spending trackers
    #[wasm_bindgen(js_name = resetSpending)]
    pub fn reset_spending(&self) {
        self.inner.reset_spending();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_policy_config() {
        let limits = SpendingLimits::new()
            .with_per_tx_limit("1000000000000000000".to_string())
            .with_daily_limit("10000000000000000000".to_string());

        let config = PolicyConfig::new().with_spending_limits(limits);

        assert!(config.is_enabled());
    }

    #[wasm_bindgen_test]
    fn test_time_bounds() {
        let bounds = TimeBounds::business_hours();
        assert_eq!(bounds.start_hour(), 9);
        assert_eq!(bounds.end_hour(), 17);
        assert_eq!(bounds.allowed_days(), vec![1, 2, 3, 4, 5]);
    }

    #[wasm_bindgen_test]
    fn test_policy_decision() {
        let decision = PolicyDecision {
            approved: true,
            requires_additional_approval: false,
            reason: None,
        };
        assert!(decision.can_proceed());

        let rejected = PolicyDecision {
            approved: false,
            requires_additional_approval: false,
            reason: Some("Limit exceeded".to_string()),
        };
        assert!(!rejected.can_proceed());
    }
}
