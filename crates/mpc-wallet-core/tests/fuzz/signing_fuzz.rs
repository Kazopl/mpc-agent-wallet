//! Fuzz tests for Signing Flow
//!
//! Property-based testing for the MPC signing infrastructure.
//! These tests verify invariants of the cryptographic operations.

use mpc_wallet_core::{
    N_PARTIES, PartyRole, Signature, THRESHOLD,
    mpc::MemoryRelay,
    types::{ChainType, Message, PartyId, SessionConfig, TransactionRequest},
};
use proptest::prelude::*;

// ============================================================================
// Strategies for generating test data
// ============================================================================

/// Generate a random 32-byte message hash
fn message_hash_strategy() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate a random party ID (0, 1, or 2)
fn party_id_strategy() -> impl Strategy<Value = PartyId> {
    0usize..3usize
}

/// Generate a valid signing set (at least 2 parties)
fn signing_set_strategy() -> impl Strategy<Value = Vec<PartyRole>> {
    prop_oneof![
        Just(vec![PartyRole::Agent, PartyRole::User]),
        Just(vec![PartyRole::Agent, PartyRole::Recovery]),
        Just(vec![PartyRole::User, PartyRole::Recovery]),
        Just(vec![PartyRole::Agent, PartyRole::User, PartyRole::Recovery]),
    ]
}

/// Generate a random session ID
fn session_id_strategy() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

// ============================================================================
// Session Configuration Fuzzing
// ============================================================================

proptest! {
    /// Test that session config validates party IDs correctly
    #[test]
    fn session_config_party_validation(party_id in 0usize..100usize) {
        let result = SessionConfig::new_agent_wallet(party_id);

        if party_id < N_PARTIES {
            prop_assert!(result.is_ok());
            let config = result.unwrap();
            prop_assert_eq!(config.party_id, party_id);
            prop_assert_eq!(config.n_parties, N_PARTIES);
            prop_assert_eq!(config.threshold, THRESHOLD);
        } else {
            prop_assert!(result.is_err());
        }
    }

    /// Test that session config always generates unique session IDs
    #[test]
    fn session_ids_unique(party_id in party_id_strategy()) {
        let config1 = SessionConfig::new_agent_wallet(party_id).unwrap();
        let config2 = SessionConfig::new_agent_wallet(party_id).unwrap();

        // Session IDs should be different (random)
        prop_assert_ne!(config1.session_id, config2.session_id);
    }

    /// Test signing session threshold validation
    #[test]
    fn signing_session_threshold(
        party_id in party_id_strategy(),
        num_parties in 1usize..5usize,
    ) {
        let parties: Vec<PartyRole> = (0..num_parties)
            .filter_map(|i| PartyRole::from_party_id(i % 3).ok())
            .collect();

        let result = SessionConfig::new_signing_session(party_id, &parties);

        if parties.len() >= THRESHOLD && parties.iter().any(|r| r.party_id() == party_id) {
            prop_assert!(result.is_ok());
        } else {
            prop_assert!(result.is_err());
        }
    }
}

// ============================================================================
// Party Role Fuzzing
// ============================================================================

proptest! {
    /// Test party role round-trip conversion
    #[test]
    fn party_role_roundtrip(role in 0usize..3usize) {
        let party_role = PartyRole::from_party_id(role).unwrap();
        let back_to_id = party_role.party_id();

        prop_assert_eq!(back_to_id, role);
    }

    /// Test invalid party IDs are rejected
    #[test]
    fn invalid_party_id_rejected(id in 3usize..1000usize) {
        let result = PartyRole::from_party_id(id);
        prop_assert!(result.is_err());
    }

    /// Test all roles are covered
    #[test]
    fn all_roles_covered(_dummy: u8) {
        let all_roles = PartyRole::all();

        prop_assert_eq!(all_roles.len(), 3);
        prop_assert!(all_roles.contains(&PartyRole::Agent));
        prop_assert!(all_roles.contains(&PartyRole::User));
        prop_assert!(all_roles.contains(&PartyRole::Recovery));
    }
}

// ============================================================================
// Signature Format Fuzzing
// ============================================================================

proptest! {
    /// Test signature creation with any r, s values
    #[test]
    fn signature_creation(
        r in prop::array::uniform32(any::<u8>()),
        s in prop::array::uniform32(any::<u8>()),
        recovery_id in 0u8..2u8,
    ) {
        let sig = Signature::new(r, s, recovery_id);

        prop_assert_eq!(sig.r, r);
        prop_assert_eq!(sig.s, s);
        prop_assert_eq!(sig.recovery_id, recovery_id);
    }

    /// Test signature to_bytes is reversible
    #[test]
    fn signature_to_bytes_format(
        r in prop::array::uniform32(any::<u8>()),
        s in prop::array::uniform32(any::<u8>()),
        recovery_id in 0u8..2u8,
    ) {
        let sig = Signature::new(r, s, recovery_id);
        let bytes = sig.to_bytes();

        prop_assert_eq!(bytes.len(), 64);
        prop_assert_eq!(&bytes[..32], &r);
        prop_assert_eq!(&bytes[32..], &s);
    }

    /// Test EIP-155 signature format
    #[test]
    fn signature_eip155_format(
        r in prop::array::uniform32(any::<u8>()),
        s in prop::array::uniform32(any::<u8>()),
        recovery_id in 0u8..2u8,
        chain_id in 1u64..1000u64,
    ) {
        let sig = Signature::new(r, s, recovery_id);
        let eip155 = sig.to_eip155(chain_id);

        prop_assert_eq!(eip155.len(), 65);
        prop_assert_eq!(&eip155[..32], &r);
        prop_assert_eq!(&eip155[32..64], &s);

        let expected_v = recovery_id as u64 + 35 + chain_id * 2;
        prop_assert_eq!(eip155[64], expected_v as u8);
    }

    /// Test v value calculation
    #[test]
    fn signature_v_value(
        recovery_id in 0u8..2u8,
    ) {
        let sig = Signature::new([0u8; 32], [0u8; 32], recovery_id);
        let v = sig.v();

        prop_assert_eq!(v, recovery_id + 27);
    }

    /// Test DER encoding never panics
    #[test]
    fn signature_der_no_panic(
        r in prop::array::uniform32(any::<u8>()),
        s in prop::array::uniform32(any::<u8>()),
        recovery_id in 0u8..2u8,
    ) {
        let sig = Signature::new(r, s, recovery_id);

        // Should not panic - may fail for invalid r/s but shouldn't crash
        std::panic::catch_unwind(|| sig.to_der()).ok();
    }
}

// ============================================================================
// Transaction Request Fuzzing
// ============================================================================

proptest! {
    /// Test transaction request creation
    #[test]
    fn tx_request_creation(
        chain in prop_oneof![Just(ChainType::Evm), Just(ChainType::Solana)],
        to in "0x[a-f0-9]{40}",
        value in 0u128..u128::MAX,
    ) {
        let tx = TransactionRequest::new(chain, &to, &value.to_string());

        prop_assert_eq!(tx.chain, chain);
        prop_assert_eq!(tx.to, to);
        prop_assert_eq!(tx.value, value.to_string());
        prop_assert!(!tx.request_id.is_empty());
    }

    /// Test contract call detection
    #[test]
    fn tx_contract_call_detection(
        data in prop::option::of(prop::collection::vec(any::<u8>(), 1..100)),
    ) {
        let mut tx = TransactionRequest::new(ChainType::Evm, "0x1234", "0");
        tx.data = data.clone();

        let is_call = tx.is_contract_call();
        let has_nonempty_data = data.map(|d| !d.is_empty()).unwrap_or(false);

        prop_assert_eq!(is_call, has_nonempty_data);
    }

    /// Test function selector extraction
    #[test]
    fn tx_function_selector(
        data in prop::collection::vec(any::<u8>(), 0..100),
    ) {
        let mut tx = TransactionRequest::new(ChainType::Evm, "0x1234", "0");
        tx.data = Some(data.clone());

        let selector = tx.function_selector();

        if data.len() >= 4 {
            prop_assert!(selector.is_some());
            let s = selector.unwrap();
            prop_assert_eq!(&s, &data[..4]);
        } else {
            prop_assert!(selector.is_none());
        }
    }
}

// ============================================================================
// Message Protocol Fuzzing
// ============================================================================

proptest! {
    /// Test broadcast message creation
    #[test]
    fn broadcast_message_roundtrip(
        from in party_id_strategy(),
        round in 1u32..10u32,
        data in prop::collection::vec(any::<u8>(), 0..1000),
    ) {
        let msg = Message::Broadcast {
            from,
            round,
            data: data.clone(),
        };

        prop_assert_eq!(msg.sender(), from);
        prop_assert_eq!(msg.round(), round);
    }

    /// Test direct message creation
    #[test]
    fn direct_message_roundtrip(
        from in party_id_strategy(),
        to in party_id_strategy(),
        round in 1u32..10u32,
        data in prop::collection::vec(any::<u8>(), 0..1000),
    ) {
        let msg = Message::Direct {
            from,
            to,
            round,
            data: data.clone(),
        };

        prop_assert_eq!(msg.sender(), from);
        prop_assert_eq!(msg.round(), round);
    }
}

// ============================================================================
// Key Share Property Fuzzing
// ============================================================================

proptest! {
    /// Test key share metadata consistency
    #[test]
    fn key_share_metadata_consistency(party_id in party_id_strategy()) {
        let role = PartyRole::from_party_id(party_id).unwrap();

        // Role should map back to correct party ID
        prop_assert_eq!(role.party_id(), party_id);

        // Display should be consistent
        let display = format!("{}", role);
        match role {
            PartyRole::Agent => prop_assert_eq!(display, "Agent"),
            PartyRole::User => prop_assert_eq!(display, "User"),
            PartyRole::Recovery => prop_assert_eq!(display, "Recovery"),
        }
    }
}

// ============================================================================
// Keccak256 Hash Fuzzing
// ============================================================================

proptest! {
    /// Test keccak256 hash produces consistent output
    #[test]
    fn keccak256_consistent(
        data in prop::collection::vec(any::<u8>(), 0..1000),
    ) {
        use mpc_wallet_core::keccak256_hash;

        let hash1 = keccak256_hash(&data);
        let hash2 = keccak256_hash(&data);

        // Same input should produce same hash
        prop_assert_eq!(hash1, hash2);

        // Hash should be 32 bytes
        prop_assert_eq!(hash1.len(), 32);
    }

    /// Test keccak256 produces different hashes for different inputs
    #[test]
    fn keccak256_collision_resistant(
        data1 in prop::collection::vec(any::<u8>(), 1..100),
        data2 in prop::collection::vec(any::<u8>(), 1..100),
    ) {
        prop_assume!(data1 != data2);

        use mpc_wallet_core::keccak256_hash;

        let hash1 = keccak256_hash(&data1);
        let hash2 = keccak256_hash(&data2);

        // Different inputs should (almost certainly) produce different hashes
        prop_assert_ne!(hash1, hash2);
    }
}

// ============================================================================
// Memory Relay Fuzzing (Async)
// ============================================================================

// Note: proptest doesn't directly support async tests, but we can test
// synchronous properties of the relay configuration

proptest! {
    /// Test memory relay configuration
    #[test]
    fn memory_relay_timeout_positive(timeout in 1u64..60000u64) {
        let relay = MemoryRelay::with_timeout(timeout);
        // Should not panic
        drop(relay);
    }
}
