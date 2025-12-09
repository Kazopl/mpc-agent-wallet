"""Main MPC Agent Wallet class."""

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .types import PartyRole, ChainType, TransactionRequest, MpcWalletError, ErrorCode
from .keygen import KeyShare, KeygenConfig, KeygenSession
from .signing import SigningConfig, SigningSession
from .policy import PolicyConfig, PolicyEngine, PolicyDecision


@dataclass
class WalletConfig:
    """Configuration for creating an MPC wallet."""

    role: PartyRole = PartyRole.AGENT
    policy: PolicyConfig | None = None
    key_share: KeyShare | None = None


class MpcAgentWallet:
    """
    MPC Agent Wallet.

    Main class for managing MPC-secured wallets for AI agents.
    Implements 2-of-3 threshold signing where any two parties
    (Agent, User, Recovery) can sign transactions.

    Example:
        >>> # Create a new wallet for the AI agent
        >>> wallet = MpcAgentWallet(WalletConfig(
        ...     role=PartyRole.AGENT,
        ...     policy=PolicyConfig().with_daily_limit(int(1e18)),  # 1 ETH
        ... ))
        >>>
        >>> # Create keygen session
        >>> session = wallet.create_keygen_session(KeygenConfig(
        ...     role=PartyRole.AGENT,
        ...     session_id=generate_session_id(),
        ... ))
        >>>
        >>> # Generate and exchange messages...
        >>> round1_msg = session.generate_round1()
    """

    def __init__(self, config: WalletConfig | None = None) -> None:
        config = config or WalletConfig()
        self._key_share = config.key_share
        self._role = config.role
        self._policy_engine: PolicyEngine | None = None

        if config.policy:
            self._policy_engine = PolicyEngine(config.policy)

    @classmethod
    def from_share(
        cls,
        share: KeyShare,
        policy: PolicyConfig | None = None,
    ) -> "MpcAgentWallet":
        """Create a wallet from an existing key share."""
        return cls(WalletConfig(
            role=PartyRole(share.party_id),
            policy=policy,
            key_share=share,
        ))

    # ============================================================================
    # Key Management
    # ============================================================================

    def create_keygen_session(self, config: KeygenConfig) -> KeygenSession:
        """Create a key generation session."""
        return KeygenSession(config)

    def set_key_share(self, share: KeyShare) -> None:
        """Set the key share after key generation."""
        self._key_share = share
        self._role = PartyRole(share.party_id)

    def get_key_share(self) -> KeyShare | None:
        """Get the current key share (if loaded)."""
        return self._key_share

    def has_key_share(self) -> bool:
        """Check if a key share is loaded."""
        return self._key_share is not None

    @property
    def role(self) -> PartyRole:
        """Get the party role."""
        return self._role

    # ============================================================================
    # Address & Public Key
    # ============================================================================

    def get_address(self) -> str:
        """Get the wallet's Ethereum address."""
        if not self._key_share:
            raise MpcWalletError(ErrorCode.INVALID_CONFIG, "No key share loaded")
        return self._key_share.eth_address

    def get_public_key(self) -> str:
        """Get the wallet's public key (compressed)."""
        if not self._key_share:
            raise MpcWalletError(ErrorCode.INVALID_CONFIG, "No key share loaded")
        return self._key_share.public_key

    def get_chain_address(self, chain: ChainType) -> str:
        """Get address for a specific chain type."""
        if not self._key_share:
            raise MpcWalletError(ErrorCode.INVALID_CONFIG, "No key share loaded")

        if chain == ChainType.EVM:
            return self._key_share.eth_address
        elif chain == ChainType.SOLANA:
            # For Solana, would need to derive ed25519 address
            return self._key_share.public_key
        else:
            raise MpcWalletError(ErrorCode.INVALID_CONFIG, f"Unsupported chain: {chain}")

    # ============================================================================
    # Policy
    # ============================================================================

    def set_policy(self, config: PolicyConfig) -> None:
        """Set the policy configuration."""
        self._policy_engine = PolicyEngine(config)

    def get_policy(self) -> PolicyConfig | None:
        """Get the current policy configuration."""
        return self._policy_engine.config if self._policy_engine else None

    def evaluate_policy(self, tx: TransactionRequest) -> PolicyDecision:
        """Evaluate a transaction against the policy."""
        if not self._policy_engine:
            # No policy = approve all
            return PolicyDecision(approved=True)
        return self._policy_engine.evaluate(tx)

    # ============================================================================
    # Signing
    # ============================================================================

    def create_signing_session(
        self,
        config: SigningConfig,
        message_hash: bytes,
    ) -> SigningSession:
        """Create a signing session."""
        if not self._key_share:
            raise MpcWalletError(ErrorCode.INVALID_CONFIG, "No key share loaded")
        return SigningSession(config, self._key_share, message_hash)

    def hash_message(self, message: bytes) -> bytes:
        """Hash a message for signing (Keccak256)."""
        # Use SHA3-256 as approximation of Keccak256
        from hashlib import sha3_256
        return sha3_256(message).digest()

    def hash_eth_message(self, message: str | bytes) -> bytes:
        """Hash a message with Ethereum prefix."""
        if isinstance(message, str):
            message = message.encode()
        prefix = f"\x19Ethereum Signed Message:\n{len(message)}".encode()
        return self.hash_message(prefix + message)

    def hash_transaction(self, tx: TransactionRequest) -> bytes:
        """Create a transaction hash for signing."""
        import json
        tx_data = json.dumps({
            "to": tx.to,
            "value": tx.value,
            "data": tx.data,
            "chain_id": tx.chain_id,
            "gas_limit": tx.gas_limit,
        })
        return self.hash_message(tx_data.encode())

    # ============================================================================
    # Utilities
    # ============================================================================

    def to_dict(self) -> dict[str, Any]:
        """Export wallet state (without secrets) for debugging."""
        return {
            "role": self._role.name,
            "has_key_share": self.has_key_share(),
            "address": self._key_share.eth_address if self._key_share else None,
            "public_key": self._key_share.public_key if self._key_share else None,
            "has_policy": self._policy_engine is not None,
        }

    def get_info(self) -> dict[str, Any]:
        """Get wallet info summary."""
        return {
            "role": self._role,
            "address": self._key_share.eth_address if self._key_share else None,
            "public_key": self._key_share.public_key if self._key_share else None,
            "has_policy": self._policy_engine is not None,
        }
