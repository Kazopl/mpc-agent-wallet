//! Policy Engine for MPC Agent Wallet
//!
//! The policy engine enforces configurable rules before any signing operation.
//! This provides an additional layer of security beyond the MPC threshold,
//! ensuring transactions comply with user-defined limits and restrictions.
//!
//! ## Supported Policies
//!
//! - **Spending Limits**: Per-transaction, daily, and weekly limits
//! - **Address Whitelist/Blacklist**: Control allowed recipients
//! - **Time Bounds**: Restrict transactions to specific time windows
//! - **Contract Restrictions**: Limit allowed contract interactions by selector
//!
//! ## Example
//!
//! ```rust,ignore
//! use mpc_wallet_core::policy::{PolicyConfig, PolicyEngine, SpendingLimits};
//!
//! let policy = PolicyConfig::default()
//!     .with_per_tx_limit("1.0", "ETH")
//!     .with_daily_limit("10.0", "ETH")
//!     .with_whitelist(vec!["0x..."]);
//!
//! let engine = PolicyEngine::new(policy);
//! let decision = engine.evaluate(&transaction_request)?;
//! ```

use crate::{ChainType, Error, Result, TransactionRequest};
use chrono::{DateTime, Datelike, Timelike, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Decision from policy evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyDecision {
    /// Transaction is approved
    Approve,
    /// Transaction is rejected with reason
    Reject { reason: String },
    /// Transaction requires additional approval (e.g., from recovery guardian)
    RequireAdditionalApproval { reason: String },
}

impl PolicyDecision {
    /// Check if the decision is an approval
    pub fn is_approved(&self) -> bool {
        matches!(self, PolicyDecision::Approve)
    }

    /// Check if the decision requires additional approval
    pub fn requires_additional_approval(&self) -> bool {
        matches!(self, PolicyDecision::RequireAdditionalApproval { .. })
    }
}

/// Spending limits configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingLimits {
    /// Maximum amount per transaction (in smallest unit, e.g., wei)
    pub per_transaction: Option<u128>,
    /// Maximum total amount per day
    pub daily: Option<u128>,
    /// Maximum total amount per week
    pub weekly: Option<u128>,
    /// Currency/token for these limits
    pub currency: String,
}

impl Default for SpendingLimits {
    fn default() -> Self {
        Self {
            per_transaction: None,
            daily: None,
            weekly: None,
            currency: "ETH".to_string(),
        }
    }
}

impl SpendingLimits {
    /// Create spending limits with a per-transaction limit
    pub fn with_per_tx(amount: u128, currency: impl Into<String>) -> Self {
        Self {
            per_transaction: Some(amount),
            daily: None,
            weekly: None,
            currency: currency.into(),
        }
    }

    /// Set daily limit
    pub fn daily(mut self, amount: u128) -> Self {
        self.daily = Some(amount);
        self
    }

    /// Set weekly limit
    pub fn weekly(mut self, amount: u128) -> Self {
        self.weekly = Some(amount);
        self
    }
}

/// Time window restriction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBounds {
    /// Start hour (0-23, UTC)
    pub start_hour: u8,
    /// End hour (0-23, UTC)
    pub end_hour: u8,
    /// Allowed days of week (0=Sunday, 6=Saturday)
    pub allowed_days: Vec<u8>,
}

impl Default for TimeBounds {
    fn default() -> Self {
        Self {
            start_hour: 0,
            end_hour: 24,
            allowed_days: vec![0, 1, 2, 3, 4, 5, 6], // All days
        }
    }
}

impl TimeBounds {
    /// Create business hours restriction (9 AM - 5 PM UTC, weekdays)
    pub fn business_hours() -> Self {
        Self {
            start_hour: 9,
            end_hour: 17,
            allowed_days: vec![1, 2, 3, 4, 5], // Monday-Friday
        }
    }

    /// Check if a timestamp falls within the time bounds
    pub fn is_allowed(&self, timestamp: DateTime<Utc>) -> bool {
        let hour = timestamp.hour() as u8;
        let day = timestamp.weekday().num_days_from_sunday() as u8;

        let hour_ok = if self.start_hour <= self.end_hour {
            hour >= self.start_hour && hour < self.end_hour
        } else {
            // Handles wrap-around (e.g., 22:00 - 06:00)
            hour >= self.start_hour || hour < self.end_hour
        };

        hour_ok && self.allowed_days.contains(&day)
    }
}

/// Contract interaction restriction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRestriction {
    /// Allowed contract addresses (empty = all allowed)
    pub allowed_contracts: HashSet<String>,
    /// Allowed function selectors (4 bytes, hex-encoded)
    pub allowed_selectors: HashSet<String>,
    /// Blocked function selectors
    pub blocked_selectors: HashSet<String>,
}

impl Default for ContractRestriction {
    fn default() -> Self {
        Self {
            allowed_contracts: HashSet::new(),
            allowed_selectors: HashSet::new(),
            blocked_selectors: HashSet::new(),
        }
    }
}

impl ContractRestriction {
    /// Add an allowed contract
    pub fn allow_contract(mut self, address: impl Into<String>) -> Self {
        self.allowed_contracts.insert(address.into().to_lowercase());
        self
    }

    /// Add an allowed function selector
    pub fn allow_selector(mut self, selector: impl Into<String>) -> Self {
        self.allowed_selectors
            .insert(selector.into().to_lowercase());
        self
    }

    /// Block a function selector
    pub fn block_selector(mut self, selector: impl Into<String>) -> Self {
        self.blocked_selectors
            .insert(selector.into().to_lowercase());
        self
    }
}

/// Complete policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Spending limits per chain type
    pub spending_limits: HashMap<ChainType, SpendingLimits>,
    /// Whitelisted addresses (if set, only these addresses are allowed)
    pub whitelist: Option<HashSet<String>>,
    /// Blacklisted addresses (always rejected)
    pub blacklist: HashSet<String>,
    /// Time restrictions
    pub time_bounds: Option<TimeBounds>,
    /// Contract interaction restrictions
    pub contract_restrictions: Option<ContractRestriction>,
    /// Whether to require additional approval for amounts exceeding a threshold
    pub additional_approval_threshold: Option<u128>,
    /// Maximum pending requests at any time
    pub max_pending_requests: usize,
    /// Whether the policy is enabled
    pub enabled: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            spending_limits: HashMap::new(),
            whitelist: None,
            blacklist: HashSet::new(),
            time_bounds: None,
            contract_restrictions: None,
            additional_approval_threshold: None,
            max_pending_requests: 10,
            enabled: true,
        }
    }
}

impl PolicyConfig {
    /// Create a new policy config with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable all policy checks (use with caution!)
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Set spending limits for a chain
    pub fn with_spending_limits(mut self, chain: ChainType, limits: SpendingLimits) -> Self {
        self.spending_limits.insert(chain, limits);
        self
    }

    /// Set per-transaction limit (convenience method for EVM)
    pub fn with_per_tx_limit(mut self, amount: u128, currency: impl Into<String>) -> Self {
        let limits = self
            .spending_limits
            .entry(ChainType::Evm)
            .or_insert_with(SpendingLimits::default);
        limits.per_transaction = Some(amount);
        limits.currency = currency.into();
        self
    }

    /// Set daily limit (convenience method for EVM)
    pub fn with_daily_limit(mut self, amount: u128) -> Self {
        let limits = self
            .spending_limits
            .entry(ChainType::Evm)
            .or_insert_with(SpendingLimits::default);
        limits.daily = Some(amount);
        self
    }

    /// Set weekly limit (convenience method for EVM)
    pub fn with_weekly_limit(mut self, amount: u128) -> Self {
        let limits = self
            .spending_limits
            .entry(ChainType::Evm)
            .or_insert_with(SpendingLimits::default);
        limits.weekly = Some(amount);
        self
    }

    /// Set address whitelist
    pub fn with_whitelist(mut self, addresses: Vec<String>) -> Self {
        self.whitelist = Some(addresses.into_iter().map(|a| a.to_lowercase()).collect());
        self
    }

    /// Add address to blacklist
    pub fn with_blacklist(mut self, addresses: Vec<String>) -> Self {
        self.blacklist = addresses.into_iter().map(|a| a.to_lowercase()).collect();
        self
    }

    /// Set time bounds
    pub fn with_time_bounds(mut self, bounds: TimeBounds) -> Self {
        self.time_bounds = Some(bounds);
        self
    }

    /// Set contract restrictions
    pub fn with_contract_restrictions(mut self, restrictions: ContractRestriction) -> Self {
        self.contract_restrictions = Some(restrictions);
        self
    }

    /// Set additional approval threshold
    pub fn with_additional_approval_threshold(mut self, amount: u128) -> Self {
        self.additional_approval_threshold = Some(amount);
        self
    }
}

/// Spending tracker for limit enforcement
#[derive(Debug, Default)]
struct SpendingTracker {
    /// Daily spending: (date_string, amount)
    daily: HashMap<String, u128>,
    /// Weekly spending: (week_string, amount)
    weekly: HashMap<String, u128>,
}

impl SpendingTracker {
    fn new() -> Self {
        Self::default()
    }

    fn get_daily_spent(&self, date: &str) -> u128 {
        *self.daily.get(date).unwrap_or(&0)
    }

    fn get_weekly_spent(&self, week: &str) -> u128 {
        *self.weekly.get(week).unwrap_or(&0)
    }

    fn record_spending(&mut self, date: &str, week: &str, amount: u128) {
        *self.daily.entry(date.to_string()).or_insert(0) += amount;
        *self.weekly.entry(week.to_string()).or_insert(0) += amount;
    }

    fn cleanup_old_entries(&mut self, current_date: &str, current_week: &str) {
        self.daily.retain(|k, _| k == current_date);
        self.weekly.retain(|k, _| k == current_week);
    }
}

/// Policy engine for evaluating transaction requests
#[derive(Debug)]
pub struct PolicyEngine {
    /// Policy configuration
    config: PolicyConfig,
    /// Spending tracker (per chain)
    spending: Arc<RwLock<HashMap<ChainType, SpendingTracker>>>,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            config,
            spending: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the current policy configuration
    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// Update the policy configuration
    pub fn update_config(&mut self, config: PolicyConfig) {
        self.config = config;
    }

    /// Evaluate a transaction request against the policy
    pub fn evaluate(&self, tx: &TransactionRequest) -> Result<PolicyDecision> {
        // Skip evaluation if policy is disabled
        if !self.config.enabled {
            return Ok(PolicyDecision::Approve);
        }

        // Check blacklist first (always reject)
        if self.config.blacklist.contains(&tx.to.to_lowercase()) {
            return Ok(PolicyDecision::Reject {
                reason: format!("Address {} is blacklisted", tx.to),
            });
        }

        // Check whitelist (if set)
        if let Some(ref whitelist) = self.config.whitelist {
            if !whitelist.contains(&tx.to.to_lowercase()) {
                return Ok(PolicyDecision::Reject {
                    reason: format!("Address {} is not whitelisted", tx.to),
                });
            }
        }

        // Check time bounds
        if let Some(ref bounds) = self.config.time_bounds {
            let now = Utc::now();
            if !bounds.is_allowed(now) {
                return Ok(PolicyDecision::Reject {
                    reason: format!(
                        "Transaction outside allowed time window ({}:00-{}:00 UTC)",
                        bounds.start_hour, bounds.end_hour
                    ),
                });
            }
        }

        // Check contract restrictions
        if tx.is_contract_call() {
            if let Some(ref restrictions) = self.config.contract_restrictions {
                // Check allowed contracts
                if !restrictions.allowed_contracts.is_empty()
                    && !restrictions
                        .allowed_contracts
                        .contains(&tx.to.to_lowercase())
                {
                    return Ok(PolicyDecision::Reject {
                        reason: format!("Contract {} is not in allowed list", tx.to),
                    });
                }

                // Check function selectors
                if let Some(selector) = tx.function_selector() {
                    let selector_hex = hex::encode(selector);

                    // Check blocked selectors
                    if restrictions.blocked_selectors.contains(&selector_hex) {
                        return Ok(PolicyDecision::Reject {
                            reason: format!("Function selector 0x{} is blocked", selector_hex),
                        });
                    }

                    // Check allowed selectors (if set)
                    if !restrictions.allowed_selectors.is_empty()
                        && !restrictions.allowed_selectors.contains(&selector_hex)
                    {
                        return Ok(PolicyDecision::Reject {
                            reason: format!(
                                "Function selector 0x{} is not in allowed list",
                                selector_hex
                            ),
                        });
                    }
                }
            }
        }

        // Parse transaction value
        let value = self.parse_value(&tx.value)?;

        // Check spending limits
        if let Some(limits) = self.config.spending_limits.get(&tx.chain) {
            // Per-transaction limit
            if let Some(per_tx) = limits.per_transaction {
                if value > per_tx {
                    return Ok(PolicyDecision::Reject {
                        reason: format!(
                            "Transaction value {} exceeds per-transaction limit {}",
                            tx.value, per_tx
                        ),
                    });
                }
            }

            // Daily and weekly limits
            let now = Utc::now();
            let date_key = now.format("%Y-%m-%d").to_string();
            let week_key = now.format("%Y-W%W").to_string();

            let spending = self.spending.read();
            if let Some(tracker) = spending.get(&tx.chain) {
                // Daily limit
                if let Some(daily_limit) = limits.daily {
                    let spent = tracker.get_daily_spent(&date_key);
                    if spent + value > daily_limit {
                        return Ok(PolicyDecision::Reject {
                            reason: format!(
                                "Transaction would exceed daily limit of {} {} (already spent: {})",
                                daily_limit, limits.currency, spent
                            ),
                        });
                    }
                }

                // Weekly limit
                if let Some(weekly_limit) = limits.weekly {
                    let spent = tracker.get_weekly_spent(&week_key);
                    if spent + value > weekly_limit {
                        return Ok(PolicyDecision::Reject {
                            reason: format!(
                                "Transaction would exceed weekly limit of {} {} (already spent: {})",
                                weekly_limit, limits.currency, spent
                            ),
                        });
                    }
                }
            }
        }

        // Check if additional approval is needed
        if let Some(threshold) = self.config.additional_approval_threshold {
            if value > threshold {
                return Ok(PolicyDecision::RequireAdditionalApproval {
                    reason: format!(
                        "Transaction value {} exceeds additional approval threshold {}",
                        tx.value, threshold
                    ),
                });
            }
        }

        Ok(PolicyDecision::Approve)
    }

    /// Record a successful transaction for spending tracking
    pub fn record_transaction(&self, tx: &TransactionRequest) -> Result<()> {
        let value = self.parse_value(&tx.value)?;
        let now = Utc::now();
        let date_key = now.format("%Y-%m-%d").to_string();
        let week_key = now.format("%Y-W%W").to_string();

        let mut spending = self.spending.write();
        let tracker = spending
            .entry(tx.chain)
            .or_insert_with(SpendingTracker::new);

        // Cleanup old entries
        tracker.cleanup_old_entries(&date_key, &week_key);

        // Record the spending
        tracker.record_spending(&date_key, &week_key, value);

        Ok(())
    }

    /// Parse a value string to u128
    fn parse_value(&self, value: &str) -> Result<u128> {
        // Handle decimal values (e.g., "1.5" ETH -> wei)
        if value.contains('.') {
            let parts: Vec<&str> = value.split('.').collect();
            if parts.len() != 2 {
                return Err(Error::PolicyViolation(format!(
                    "Invalid value format: {}",
                    value
                )));
            }

            let whole: u128 = parts[0]
                .parse()
                .map_err(|_| Error::PolicyViolation(format!("Invalid value: {}", value)))?;

            let mut decimal_str = parts[1].to_string();
            // Pad to 18 decimals (ETH)
            while decimal_str.len() < 18 {
                decimal_str.push('0');
            }
            decimal_str.truncate(18);

            let decimal: u128 = decimal_str
                .parse()
                .map_err(|_| Error::PolicyViolation(format!("Invalid value: {}", value)))?;

            Ok(whole * 10u128.pow(18) + decimal)
        } else {
            value
                .parse()
                .map_err(|_| Error::PolicyViolation(format!("Invalid value: {}", value)))
        }
    }

    /// Get current daily spending for a chain
    pub fn daily_spending(&self, chain: ChainType) -> u128 {
        let date_key = Utc::now().format("%Y-%m-%d").to_string();
        let spending = self.spending.read();
        spending
            .get(&chain)
            .map(|t| t.get_daily_spent(&date_key))
            .unwrap_or(0)
    }

    /// Get current weekly spending for a chain
    pub fn weekly_spending(&self, chain: ChainType) -> u128 {
        let week_key = Utc::now().format("%Y-W%W").to_string();
        let spending = self.spending.read();
        spending
            .get(&chain)
            .map(|t| t.get_weekly_spent(&week_key))
            .unwrap_or(0)
    }

    /// Reset all spending trackers
    pub fn reset_spending(&self) {
        let mut spending = self.spending.write();
        spending.clear();
    }
}

/// Builder for creating complex policies
#[derive(Default)]
pub struct PolicyBuilder {
    config: PolicyConfig,
}

impl PolicyBuilder {
    /// Create a new policy builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set spending limits
    pub fn spending_limits(mut self, chain: ChainType, limits: SpendingLimits) -> Self {
        self.config.spending_limits.insert(chain, limits);
        self
    }

    /// Add whitelist addresses
    pub fn whitelist(mut self, addresses: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let set: HashSet<String> = addresses
            .into_iter()
            .map(|a| a.into().to_lowercase())
            .collect();
        self.config.whitelist = Some(set);
        self
    }

    /// Add blacklist addresses
    pub fn blacklist(mut self, addresses: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.config.blacklist = addresses
            .into_iter()
            .map(|a| a.into().to_lowercase())
            .collect();
        self
    }

    /// Set time bounds
    pub fn time_bounds(mut self, bounds: TimeBounds) -> Self {
        self.config.time_bounds = Some(bounds);
        self
    }

    /// Set contract restrictions
    pub fn contract_restrictions(mut self, restrictions: ContractRestriction) -> Self {
        self.config.contract_restrictions = Some(restrictions);
        self
    }

    /// Set additional approval threshold
    pub fn additional_approval_threshold(mut self, amount: u128) -> Self {
        self.config.additional_approval_threshold = Some(amount);
        self
    }

    /// Build the policy config
    pub fn build(self) -> PolicyConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_approve_basic() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "1000000000000000000");

        let decision = engine.evaluate(&tx).unwrap();
        assert!(decision.is_approved());
    }

    #[test]
    fn test_policy_disabled() {
        let engine = PolicyEngine::new(PolicyConfig::disabled());
        let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "999999999999999999999999");

        let decision = engine.evaluate(&tx).unwrap();
        assert!(decision.is_approved());
    }

    #[test]
    fn test_blacklist_rejection() {
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
    fn test_whitelist_rejection() {
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
    fn test_whitelist_approval() {
        let config = PolicyConfig::default().with_whitelist(vec!["0xGOOD".to_string()]);
        let engine = PolicyEngine::new(config);
        let tx = TransactionRequest::new(ChainType::Evm, "0xgood", "1000");

        let decision = engine.evaluate(&tx).unwrap();
        assert!(decision.is_approved());
    }

    #[test]
    fn test_per_tx_limit() {
        let limits = SpendingLimits::with_per_tx(1_000_000_000_000_000_000u128, "ETH"); // 1 ETH
        let config = PolicyConfig::default().with_spending_limits(ChainType::Evm, limits);
        let engine = PolicyEngine::new(config);

        // Under limit
        let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "500000000000000000");
        assert!(engine.evaluate(&tx).unwrap().is_approved());

        // Over limit
        let tx_over = TransactionRequest::new(ChainType::Evm, "0x1234", "2000000000000000000");
        assert!(!engine.evaluate(&tx_over).unwrap().is_approved());
    }

    #[test]
    fn test_daily_limit() {
        let limits = SpendingLimits::default().daily(2_000_000_000_000_000_000u128); // 2 ETH daily
        let config = PolicyConfig::default().with_spending_limits(ChainType::Evm, limits);
        let engine = PolicyEngine::new(config);

        // First transaction
        let tx1 = TransactionRequest::new(ChainType::Evm, "0x1234", "1000000000000000000");
        assert!(engine.evaluate(&tx1).unwrap().is_approved());
        engine.record_transaction(&tx1).unwrap();

        // Second transaction (should still be under limit)
        let tx2 = TransactionRequest::new(ChainType::Evm, "0x1234", "500000000000000000");
        assert!(engine.evaluate(&tx2).unwrap().is_approved());
        engine.record_transaction(&tx2).unwrap();

        // Third transaction (would exceed daily limit)
        let tx3 = TransactionRequest::new(ChainType::Evm, "0x1234", "1000000000000000000");
        assert!(!engine.evaluate(&tx3).unwrap().is_approved());
    }

    #[test]
    fn test_additional_approval_threshold() {
        let config = PolicyConfig::default()
            .with_additional_approval_threshold(5_000_000_000_000_000_000u128); // 5 ETH
        let engine = PolicyEngine::new(config);

        // Under threshold
        let tx = TransactionRequest::new(ChainType::Evm, "0x1234", "1000000000000000000");
        assert!(engine.evaluate(&tx).unwrap().is_approved());

        // Over threshold
        let tx_over = TransactionRequest::new(ChainType::Evm, "0x1234", "10000000000000000000");
        let decision = engine.evaluate(&tx_over).unwrap();
        assert!(decision.requires_additional_approval());
    }

    #[test]
    fn test_time_bounds() {
        let bounds = TimeBounds::business_hours();
        assert!(bounds.start_hour == 9);
        assert!(bounds.end_hour == 17);
        assert_eq!(bounds.allowed_days, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_contract_restrictions() {
        let restrictions = ContractRestriction::default()
            .allow_contract("0xUniswap")
            .block_selector("a9059cbb"); // transfer (no 0x prefix - hex::encode doesn't include it)

        let config = PolicyConfig::default().with_contract_restrictions(restrictions);
        let engine = PolicyEngine::new(config);

        // Contract call to allowed contract with allowed selector
        let mut tx = TransactionRequest::new(ChainType::Evm, "0xuniswap", "0");
        tx.data = Some(vec![0x12, 0x34, 0x56, 0x78]); // Some non-blocked selector
        assert!(engine.evaluate(&tx).unwrap().is_approved());

        // Contract call with blocked selector
        let mut tx_blocked = TransactionRequest::new(ChainType::Evm, "0xuniswap", "0");
        tx_blocked.data = Some(vec![0xa9, 0x05, 0x9c, 0xbb, 0x00]); // transfer selector
        assert!(!engine.evaluate(&tx_blocked).unwrap().is_approved());
    }

    #[test]
    fn test_policy_builder() {
        let policy = PolicyBuilder::new()
            .spending_limits(
                ChainType::Evm,
                SpendingLimits::with_per_tx(1_000_000_000_000_000_000, "ETH"),
            )
            .whitelist(["0x1234", "0x5678"])
            .blacklist(["0xBAD"])
            .time_bounds(TimeBounds::business_hours())
            .additional_approval_threshold(10_000_000_000_000_000_000)
            .build();

        assert!(policy.whitelist.is_some());
        assert!(policy.blacklist.contains("0xbad"));
        assert!(policy.time_bounds.is_some());
    }

    #[test]
    fn test_parse_decimal_value() {
        let engine = PolicyEngine::new(PolicyConfig::default());

        // Test parsing "1.5" ETH
        let value = engine.parse_value("1.5").unwrap();
        assert_eq!(value, 1_500_000_000_000_000_000u128);

        // Test parsing "0.001" ETH
        let value = engine.parse_value("0.001").unwrap();
        assert_eq!(value, 1_000_000_000_000_000u128);

        // Test parsing whole number
        let value = engine.parse_value("1000000000000000000").unwrap();
        assert_eq!(value, 1_000_000_000_000_000_000u128);
    }
}
