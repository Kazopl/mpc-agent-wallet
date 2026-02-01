//! Reputation Module for ERC-8004 Integration
//!
//! Provides feedback signal management and reputation querying for the
//! ERC-8004 Reputation Registry.
//!
//! ## Overview
//!
//! The Reputation Registry enables on-chain composable reputation with tagged
//! feedback signals. Feedback can be filtered by reviewer, tags, and aggregated
//! into summaries.
//!
//! ## Example
//!
//! ```rust,ignore
//! use mpc_wallet_core::reputation::{ReputationManager, FeedbackParams};
//!
//! let manager = ReputationManager::new();
//!
//! // Submit feedback
//! let params = FeedbackParams::new(agent_id, 100, 2)
//!     .with_tag1("quality")
//!     .with_tag2("speed")
//!     .with_proof_of_payment(tx_hash);
//!
//! let calldata = manager.encode_give_feedback_calldata(&params)?;
//! ```

use crate::{Error, Result};
use serde::{Deserialize, Serialize};

pub const REPUTATION_REGISTRY_ADDRESS: &str = "0xB5048e3ef1DA4E04deB6f7d0423D06F63869e322";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackSignal {
    pub agent_id: u64,
    pub reviewer: String,
    pub value: i128,
    pub decimals: u8,
    pub tag1: String,
    pub tag2: String,
    pub proof_of_payment: Option<[u8; 32]>,
    pub timestamp: u64,
    pub feedback_index: u64,
    pub revoked: bool,
}

impl FeedbackSignal {
    pub fn is_positive(&self) -> bool {
        self.value > 0
    }

    pub fn is_negative(&self) -> bool {
        self.value < 0
    }

    pub fn normalized_value(&self) -> f64 {
        self.value as f64 / 10f64.powi(self.decimals as i32)
    }

    pub fn has_proof_of_payment(&self) -> bool {
        self.proof_of_payment.is_some()
            && self.proof_of_payment != Some([0u8; 32])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationSummary {
    pub agent_id: u64,
    pub feedback_count: u64,
    pub aggregate_value: i128,
    pub decimals: u8,
    pub filters_applied: SummaryFilters,
}

impl ReputationSummary {
    pub fn normalized_aggregate(&self) -> f64 {
        self.aggregate_value as f64 / 10f64.powi(self.decimals as i32)
    }

    pub fn average_score(&self) -> Option<f64> {
        if self.feedback_count == 0 {
            return None;
        }
        Some(self.normalized_aggregate() / self.feedback_count as f64)
    }

    pub fn is_positive(&self) -> bool {
        self.aggregate_value > 0
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SummaryFilters {
    pub reviewers: Vec<String>,
    pub tag1: Option<String>,
    pub tag2: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FeedbackParams {
    pub agent_id: u64,
    pub value: i128,
    pub decimals: u8,
    pub tag1: String,
    pub tag2: String,
    pub proof_of_payment: [u8; 32],
}

impl FeedbackParams {
    pub fn new(agent_id: u64, value: i128, decimals: u8) -> Self {
        Self {
            agent_id,
            value,
            decimals,
            tag1: String::new(),
            tag2: String::new(),
            proof_of_payment: [0u8; 32],
        }
    }

    pub fn with_tag1(mut self, tag: impl Into<String>) -> Self {
        self.tag1 = tag.into();
        self
    }

    pub fn with_tag2(mut self, tag: impl Into<String>) -> Self {
        self.tag2 = tag.into();
        self
    }

    pub fn with_tags(mut self, tag1: impl Into<String>, tag2: impl Into<String>) -> Self {
        self.tag1 = tag1.into();
        self.tag2 = tag2.into();
        self
    }

    pub fn with_proof_of_payment(mut self, proof: [u8; 32]) -> Self {
        self.proof_of_payment = proof;
        self
    }

    pub fn with_proof_of_payment_hex(mut self, proof_hex: &str) -> Result<Self> {
        let proof_hex = proof_hex.strip_prefix("0x").unwrap_or(proof_hex);
        if proof_hex.len() != 64 {
            return Err(Error::InvalidConfig(format!(
                "Invalid proof of payment length: expected 64 hex chars, got {}",
                proof_hex.len()
            )));
        }
        let bytes = hex::decode(proof_hex)?;
        self.proof_of_payment.copy_from_slice(&bytes);
        Ok(self)
    }
}

#[derive(Debug, Clone)]
pub struct SummaryQueryParams {
    pub agent_id: u64,
    pub reviewers: Vec<String>,
    pub tag1: String,
    pub tag2: String,
}

impl SummaryQueryParams {
    pub fn new(agent_id: u64) -> Self {
        Self {
            agent_id,
            reviewers: Vec::new(),
            tag1: String::new(),
            tag2: String::new(),
        }
    }

    pub fn with_reviewer(mut self, reviewer: impl Into<String>) -> Self {
        self.reviewers.push(reviewer.into());
        self
    }

    pub fn with_reviewers(mut self, reviewers: Vec<String>) -> Self {
        self.reviewers = reviewers;
        self
    }

    pub fn with_tag1(mut self, tag: impl Into<String>) -> Self {
        self.tag1 = tag.into();
        self
    }

    pub fn with_tag2(mut self, tag: impl Into<String>) -> Self {
        self.tag2 = tag.into();
        self
    }
}

#[derive(Debug, Clone)]
pub struct ReputationManager {
    reputation_registry: String,
}

impl ReputationManager {
    pub fn new() -> Self {
        Self {
            reputation_registry: REPUTATION_REGISTRY_ADDRESS.to_string(),
        }
    }

    pub fn with_registry_address(mut self, address: impl Into<String>) -> Self {
        self.reputation_registry = address.into();
        self
    }

    pub fn registry_address(&self) -> &str {
        &self.reputation_registry
    }

    pub fn encode_give_feedback_calldata(&self, params: &FeedbackParams) -> Result<Vec<u8>> {
        self.validate_feedback_params(params)?;

        let function_selector = [0x62, 0x3c, 0x48, 0x71];

        let tag1_bytes = params.tag1.as_bytes();
        let tag2_bytes = params.tag2.as_bytes();
        let tag1_padded_len = ((tag1_bytes.len() + 31) / 32) * 32;
        let tag2_padded_len = ((tag2_bytes.len() + 31) / 32) * 32;

        let mut calldata = Vec::with_capacity(
            4 + 32 + 32 + 32 + 32 + 32 + 32 + 32 + tag1_padded_len + 32 + tag2_padded_len,
        );
        calldata.extend_from_slice(&function_selector);

        let mut agent_id_bytes = [0u8; 32];
        agent_id_bytes[24..32].copy_from_slice(&params.agent_id.to_be_bytes());
        calldata.extend_from_slice(&agent_id_bytes);

        let mut value_bytes = [0u8; 32];
        let value_i128_bytes = params.value.to_be_bytes();
        if params.value >= 0 {
            value_bytes[16..32].copy_from_slice(&value_i128_bytes);
        } else {
            value_bytes.fill(0xff);
            value_bytes[16..32].copy_from_slice(&value_i128_bytes);
        }
        calldata.extend_from_slice(&value_bytes);

        let mut decimals_bytes = [0u8; 32];
        decimals_bytes[31] = params.decimals;
        calldata.extend_from_slice(&decimals_bytes);

        let tag1_offset: u64 = 0xc0;
        let mut tag1_offset_bytes = [0u8; 32];
        tag1_offset_bytes[24..32].copy_from_slice(&tag1_offset.to_be_bytes());
        calldata.extend_from_slice(&tag1_offset_bytes);

        let tag2_offset: u64 = 0xc0 + 32 + tag1_padded_len as u64;
        let mut tag2_offset_bytes = [0u8; 32];
        tag2_offset_bytes[24..32].copy_from_slice(&tag2_offset.to_be_bytes());
        calldata.extend_from_slice(&tag2_offset_bytes);

        let mut proof_bytes = [0u8; 32];
        proof_bytes.copy_from_slice(&params.proof_of_payment);
        calldata.extend_from_slice(&proof_bytes);

        let mut tag1_len = [0u8; 32];
        tag1_len[24..32].copy_from_slice(&(tag1_bytes.len() as u64).to_be_bytes());
        calldata.extend_from_slice(&tag1_len);

        let mut tag1_padded = vec![0u8; tag1_padded_len.max(32)];
        tag1_padded[..tag1_bytes.len()].copy_from_slice(tag1_bytes);
        calldata.extend_from_slice(&tag1_padded);

        let mut tag2_len = [0u8; 32];
        tag2_len[24..32].copy_from_slice(&(tag2_bytes.len() as u64).to_be_bytes());
        calldata.extend_from_slice(&tag2_len);

        if tag2_padded_len > 0 {
            let mut tag2_padded = vec![0u8; tag2_padded_len];
            tag2_padded[..tag2_bytes.len()].copy_from_slice(tag2_bytes);
            calldata.extend_from_slice(&tag2_padded);
        }

        Ok(calldata)
    }

    pub fn encode_revoke_feedback_calldata(
        &self,
        agent_id: u64,
        feedback_index: u64,
    ) -> Result<Vec<u8>> {
        let function_selector = [0x87, 0x23, 0x5a, 0x4b];

        let mut calldata = Vec::with_capacity(4 + 32 + 32);
        calldata.extend_from_slice(&function_selector);

        let mut agent_id_bytes = [0u8; 32];
        agent_id_bytes[24..32].copy_from_slice(&agent_id.to_be_bytes());
        calldata.extend_from_slice(&agent_id_bytes);

        let mut index_bytes = [0u8; 32];
        index_bytes[24..32].copy_from_slice(&feedback_index.to_be_bytes());
        calldata.extend_from_slice(&index_bytes);

        Ok(calldata)
    }

    pub fn encode_get_summary_calldata(&self, params: &SummaryQueryParams) -> Result<Vec<u8>> {
        let function_selector = [0x5b, 0x5e, 0x13, 0x9f];

        let tag1_bytes = params.tag1.as_bytes();
        let tag2_bytes = params.tag2.as_bytes();
        let tag1_padded_len = ((tag1_bytes.len() + 31) / 32) * 32;
        let tag2_padded_len = ((tag2_bytes.len() + 31) / 32) * 32;
        let reviewers_len = params.reviewers.len();

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&function_selector);

        let mut agent_id_bytes = [0u8; 32];
        agent_id_bytes[24..32].copy_from_slice(&params.agent_id.to_be_bytes());
        calldata.extend_from_slice(&agent_id_bytes);

        let reviewers_offset: u64 = 0x80;
        let mut reviewers_offset_bytes = [0u8; 32];
        reviewers_offset_bytes[24..32].copy_from_slice(&reviewers_offset.to_be_bytes());
        calldata.extend_from_slice(&reviewers_offset_bytes);

        let tag1_offset: u64 = reviewers_offset + 32 + (reviewers_len as u64 * 32);
        let mut tag1_offset_bytes = [0u8; 32];
        tag1_offset_bytes[24..32].copy_from_slice(&tag1_offset.to_be_bytes());
        calldata.extend_from_slice(&tag1_offset_bytes);

        let tag2_offset: u64 = tag1_offset + 32 + tag1_padded_len as u64;
        let mut tag2_offset_bytes = [0u8; 32];
        tag2_offset_bytes[24..32].copy_from_slice(&tag2_offset.to_be_bytes());
        calldata.extend_from_slice(&tag2_offset_bytes);

        let mut reviewers_len_bytes = [0u8; 32];
        reviewers_len_bytes[24..32].copy_from_slice(&(reviewers_len as u64).to_be_bytes());
        calldata.extend_from_slice(&reviewers_len_bytes);

        for reviewer in &params.reviewers {
            let reviewer_bytes = self.parse_address(reviewer)?;
            let mut reviewer_padded = [0u8; 32];
            reviewer_padded[12..32].copy_from_slice(&reviewer_bytes);
            calldata.extend_from_slice(&reviewer_padded);
        }

        let mut tag1_len = [0u8; 32];
        tag1_len[24..32].copy_from_slice(&(tag1_bytes.len() as u64).to_be_bytes());
        calldata.extend_from_slice(&tag1_len);

        if tag1_padded_len > 0 {
            let mut tag1_padded = vec![0u8; tag1_padded_len];
            tag1_padded[..tag1_bytes.len()].copy_from_slice(tag1_bytes);
            calldata.extend_from_slice(&tag1_padded);
        }

        let mut tag2_len = [0u8; 32];
        tag2_len[24..32].copy_from_slice(&(tag2_bytes.len() as u64).to_be_bytes());
        calldata.extend_from_slice(&tag2_len);

        if tag2_padded_len > 0 {
            let mut tag2_padded = vec![0u8; tag2_padded_len];
            tag2_padded[..tag2_bytes.len()].copy_from_slice(tag2_bytes);
            calldata.extend_from_slice(&tag2_padded);
        }

        Ok(calldata)
    }

    pub fn encode_get_feedback_calldata(
        &self,
        agent_id: u64,
        feedback_index: u64,
    ) -> Result<Vec<u8>> {
        let function_selector = [0x7a, 0x8a, 0x81, 0x52];

        let mut calldata = Vec::with_capacity(4 + 32 + 32);
        calldata.extend_from_slice(&function_selector);

        let mut agent_id_bytes = [0u8; 32];
        agent_id_bytes[24..32].copy_from_slice(&agent_id.to_be_bytes());
        calldata.extend_from_slice(&agent_id_bytes);

        let mut index_bytes = [0u8; 32];
        index_bytes[24..32].copy_from_slice(&feedback_index.to_be_bytes());
        calldata.extend_from_slice(&index_bytes);

        Ok(calldata)
    }

    pub fn encode_get_feedback_count_calldata(&self, agent_id: u64) -> Result<Vec<u8>> {
        let function_selector = [0x9c, 0x1a, 0x2a, 0x50];

        let mut calldata = Vec::with_capacity(4 + 32);
        calldata.extend_from_slice(&function_selector);

        let mut agent_id_bytes = [0u8; 32];
        agent_id_bytes[24..32].copy_from_slice(&agent_id.to_be_bytes());
        calldata.extend_from_slice(&agent_id_bytes);

        Ok(calldata)
    }

    fn validate_feedback_params(&self, params: &FeedbackParams) -> Result<()> {
        if params.decimals > 18 {
            return Err(Error::InvalidConfig(format!(
                "Decimals must be <= 18, got {}",
                params.decimals
            )));
        }
        Ok(())
    }

    fn parse_address(&self, address: &str) -> Result<[u8; 20]> {
        let address = address.strip_prefix("0x").unwrap_or(address);
        if address.len() != 40 {
            return Err(Error::InvalidConfig(format!(
                "Invalid address length: expected 40 hex chars, got {}",
                address.len()
            )));
        }
        let bytes = hex::decode(address)?;
        let mut result = [0u8; 20];
        result.copy_from_slice(&bytes);
        Ok(result)
    }
}

impl Default for ReputationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct FeedbackBuilder {
    params: FeedbackParams,
}

impl FeedbackBuilder {
    pub fn new(agent_id: u64) -> Self {
        Self {
            params: FeedbackParams::new(agent_id, 0, 2),
        }
    }

    pub fn positive(mut self, value: u128, decimals: u8) -> Self {
        self.params.value = value as i128;
        self.params.decimals = decimals;
        self
    }

    pub fn negative(mut self, value: u128, decimals: u8) -> Self {
        self.params.value = -(value as i128);
        self.params.decimals = decimals;
        self
    }

    pub fn tag1(mut self, tag: impl Into<String>) -> Self {
        self.params.tag1 = tag.into();
        self
    }

    pub fn tag2(mut self, tag: impl Into<String>) -> Self {
        self.params.tag2 = tag.into();
        self
    }

    pub fn proof_of_payment(mut self, proof: [u8; 32]) -> Self {
        self.params.proof_of_payment = proof;
        self
    }

    pub fn build(self) -> FeedbackParams {
        self.params
    }
}

pub fn calculate_reputation_score(
    positive_count: u64,
    negative_count: u64,
    aggregate_value: i128,
    decimals: u8,
) -> f64 {
    let total = positive_count + negative_count;
    if total == 0 {
        return 0.0;
    }

    let normalized = aggregate_value as f64 / 10f64.powi(decimals as i32);
    let ratio = positive_count as f64 / total as f64;

    normalized * ratio
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feedback_signal_properties() {
        let signal = FeedbackSignal {
            agent_id: 1,
            reviewer: "0x1234".to_string(),
            value: 100,
            decimals: 2,
            tag1: "quality".to_string(),
            tag2: "speed".to_string(),
            proof_of_payment: Some([1u8; 32]),
            timestamp: 1000,
            feedback_index: 0,
            revoked: false,
        };

        assert!(signal.is_positive());
        assert!(!signal.is_negative());
        assert_eq!(signal.normalized_value(), 1.0);
        assert!(signal.has_proof_of_payment());
    }

    #[test]
    fn negative_feedback() {
        let signal = FeedbackSignal {
            agent_id: 1,
            reviewer: "0x1234".to_string(),
            value: -50,
            decimals: 2,
            tag1: "".to_string(),
            tag2: "".to_string(),
            proof_of_payment: None,
            timestamp: 1000,
            feedback_index: 0,
            revoked: false,
        };

        assert!(!signal.is_positive());
        assert!(signal.is_negative());
        assert_eq!(signal.normalized_value(), -0.5);
    }

    #[test]
    fn reputation_summary_calculations() {
        let summary = ReputationSummary {
            agent_id: 1,
            feedback_count: 10,
            aggregate_value: 850,
            decimals: 2,
            filters_applied: SummaryFilters::default(),
        };

        assert_eq!(summary.normalized_aggregate(), 8.5);
        assert_eq!(summary.average_score(), Some(0.85));
        assert!(summary.is_positive());
    }

    #[test]
    fn empty_summary_average() {
        let summary = ReputationSummary {
            agent_id: 1,
            feedback_count: 0,
            aggregate_value: 0,
            decimals: 2,
            filters_applied: SummaryFilters::default(),
        };

        assert_eq!(summary.average_score(), None);
    }

    #[test]
    fn feedback_params_builder() {
        let params = FeedbackParams::new(1, 100, 2)
            .with_tag1("quality")
            .with_tag2("speed");

        assert_eq!(params.agent_id, 1);
        assert_eq!(params.value, 100);
        assert_eq!(params.tag1, "quality");
    }

    #[test]
    fn proof_of_payment_hex() {
        let params = FeedbackParams::new(1, 100, 2)
            .with_proof_of_payment_hex(
                "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            )
            .unwrap();

        assert_eq!(params.proof_of_payment[0], 0x12);
        assert_eq!(params.proof_of_payment[31], 0xef);
    }

    #[test]
    fn encode_give_feedback_calldata() {
        let manager = ReputationManager::new();
        let params = FeedbackParams::new(1, 100, 2).with_tags("quality", "");

        let calldata = manager.encode_give_feedback_calldata(&params).unwrap();

        assert_eq!(&calldata[..4], &[0x62, 0x3c, 0x48, 0x71]);
    }

    #[test]
    fn encode_revoke_feedback_calldata() {
        let manager = ReputationManager::new();
        let calldata = manager.encode_revoke_feedback_calldata(1, 5).unwrap();

        assert_eq!(&calldata[..4], &[0x87, 0x23, 0x5a, 0x4b]);
        assert_eq!(calldata.len(), 4 + 32 + 32);
    }

    #[test]
    fn decimals_validation() {
        let manager = ReputationManager::new();
        let params = FeedbackParams::new(1, 100, 19);
        let result = manager.encode_give_feedback_calldata(&params);

        assert!(result.is_err());
    }

    #[test]
    fn feedback_builder() {
        let params = FeedbackBuilder::new(42)
            .positive(500, 2)
            .tag1("reliability")
            .build();

        assert_eq!(params.agent_id, 42);
        assert_eq!(params.value, 500);
        assert_eq!(params.tag1, "reliability");
    }

    #[test]
    fn negative_feedback_builder() {
        let params = FeedbackBuilder::new(1)
            .negative(100, 2)
            .build();

        assert_eq!(params.value, -100);
    }

    #[test]
    fn reputation_score_calculation() {
        let score = calculate_reputation_score(8, 2, 600, 2);
        assert!(score > 0.0);

        let zero_score = calculate_reputation_score(0, 0, 0, 2);
        assert_eq!(zero_score, 0.0);
    }

    #[test]
    fn summary_query_params() {
        let params = SummaryQueryParams::new(1)
            .with_reviewer("0x1234567890123456789012345678901234567890")
            .with_tag1("quality");

        assert_eq!(params.reviewers.len(), 1);
        assert_eq!(params.tag1, "quality");
    }
}
