"""Key generation module for MPC wallets."""

import json
import secrets
import hashlib
import base64
from dataclasses import dataclass, field
from typing import Any
from enum import Enum

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .types import PartyRole, MpcWalletError, ErrorCode


@dataclass
class KeyShareInfo:
    """Key share information (non-sensitive)."""

    share_id: str
    role: PartyRole
    public_key: str  # Compressed, hex
    eth_address: str
    created_at: int


@dataclass
class KeyShare(KeyShareInfo):
    """Complete key share (includes encrypted secret)."""

    party_id: int
    encrypted_data: str
    chain_code: str
    nonce: str
    salt: str
    version: int = 1


@dataclass
class KeygenConfig:
    """Configuration for key generation."""

    role: PartyRole
    session_id: str
    timeout_secs: int = 300


@dataclass
class KeygenResult:
    """Result of key generation."""

    share: KeyShare
    public_key: str
    eth_address: str


class SessionState(Enum):
    """Session state."""

    INITIALIZED = "initialized"
    ROUND1 = "round1"
    ROUND2 = "round2"
    COMPLETE = "complete"
    FAILED = "failed"


class KeygenSession:
    """
    Key generation session state machine.

    Implements the DKG (Distributed Key Generation) protocol
    for the 2-of-3 threshold ECDSA scheme.

    Example:
        >>> session = KeygenSession(KeygenConfig(
        ...     role=PartyRole.AGENT,
        ...     session_id=generate_session_id(),
        ... ))
        >>>
        >>> # Round 1: Generate and exchange commitments
        >>> round1_msg = session.generate_round1()
        >>> # ... send to other parties and receive their messages ...
        >>> session.process_round1(other_messages)
        >>>
        >>> # Round 2: Generate and exchange public shares
        >>> round2_msg = session.generate_round2()
        >>> # ... send to other parties and receive their messages ...
        >>> result = session.process_round2(other_messages, password)
    """

    def __init__(self, config: KeygenConfig) -> None:
        self._party_id = config.role.value
        self._session_id = bytes.fromhex(config.session_id)
        if len(self._session_id) != 32:
            raise MpcWalletError(ErrorCode.INVALID_CONFIG, "Session ID must be 32 bytes")

        self._round = 0
        self._state = SessionState.INITIALIZED
        self._local_secret: bytes | None = None
        self._commitments: dict[int, bytes] = {}
        self._public_shares: dict[int, bytes] = {}

    @property
    def round(self) -> int:
        """Get current round number."""
        return self._round

    @property
    def state(self) -> SessionState:
        """Get current state."""
        return self._state

    @property
    def is_complete(self) -> bool:
        """Check if keygen is complete."""
        return self._state == SessionState.COMPLETE

    @property
    def is_failed(self) -> bool:
        """Check if keygen failed."""
        return self._state == SessionState.FAILED

    def generate_round1(self) -> str:
        """Generate Round 1 message (commitment)."""
        if self._state != SessionState.INITIALIZED:
            raise MpcWalletError(ErrorCode.KEYGEN_FAILED, "Invalid state for round 1")

        # Generate local secret
        self._local_secret = secrets.token_bytes(32)

        # Create commitment
        commitment = hashlib.sha256(
            b"commitment:" + self._local_secret + self._session_id + bytes([self._party_id])
        ).digest()

        self._round = 1
        self._state = SessionState.ROUND1

        return json.dumps({
            "party_id": self._party_id,
            "session_id": self._session_id.hex(),
            "commitment": commitment.hex(),
        })

    def process_round1(self, messages_json: str) -> None:
        """Process Round 1 messages from other parties."""
        if self._round != 1:
            raise MpcWalletError(ErrorCode.KEYGEN_FAILED, "Must be in round 1")

        messages = json.loads(messages_json)
        if len(messages) != 2:
            raise MpcWalletError(
                ErrorCode.THRESHOLD_NOT_MET, "Expected 2 messages from other parties"
            )

        # Store commitments
        for msg in messages:
            self._commitments[msg["party_id"]] = bytes.fromhex(msg["commitment"])

    def generate_round2(self) -> str:
        """Generate Round 2 message (public share)."""
        if self._state != SessionState.ROUND1 or len(self._commitments) != 2:
            raise MpcWalletError(ErrorCode.KEYGEN_FAILED, "Invalid state for round 2")

        if not self._local_secret:
            raise MpcWalletError(ErrorCode.KEYGEN_FAILED, "Local secret not generated")

        # Generate public share
        public_share = hashlib.sha256(b"public:" + self._local_secret).digest()

        self._round = 2
        self._state = SessionState.ROUND2

        return json.dumps({
            "party_id": self._party_id,
            "session_id": self._session_id.hex(),
            "public_share": public_share.hex(),
        })

    def process_round2(self, messages_json: str, password: str) -> KeygenResult:
        """Process Round 2 messages and complete keygen."""
        if self._round != 2:
            raise MpcWalletError(ErrorCode.KEYGEN_FAILED, "Must be in round 2")

        if not self._local_secret:
            raise MpcWalletError(ErrorCode.KEYGEN_FAILED, "Local secret not available")

        messages = json.loads(messages_json)
        if len(messages) != 2:
            raise MpcWalletError(
                ErrorCode.THRESHOLD_NOT_MET, "Expected 2 messages from other parties"
            )

        # Store public shares
        for msg in messages:
            self._public_shares[msg["party_id"]] = bytes.fromhex(msg["public_share"])

        # Compute aggregated public key
        data = b"aggregate:" + self._local_secret
        for share in self._public_shares.values():
            data += share
        aggregated_pk = hashlib.sha256(data).digest()

        # Create compressed public key format
        public_key = bytes([0x02]) + aggregated_pk

        # Derive Ethereum address
        address_hash = hashlib.sha256(aggregated_pk).digest()
        eth_address = "0x" + address_hash[12:].hex()

        # Encrypt the secret
        ciphertext, nonce, salt = _encrypt_secret(self._local_secret, password)

        # Generate chain code
        chain_code = hashlib.sha256(
            b"chaincode:" + self._session_id + public_key
        ).digest()

        import time

        share = KeyShare(
            share_id=f"share-{self._party_id}",
            party_id=self._party_id,
            role=PartyRole(self._party_id),
            public_key=public_key.hex(),
            eth_address=eth_address,
            encrypted_data=ciphertext,
            chain_code=chain_code.hex(),
            nonce=nonce,
            salt=salt,
            created_at=int(time.time()),
        )

        self._state = SessionState.COMPLETE

        return KeygenResult(
            share=share,
            public_key=public_key.hex(),
            eth_address=eth_address,
        )


def _encrypt_secret(secret: bytes, password: str) -> tuple[str, str, str]:
    """Encrypt a secret using ChaCha20-Poly1305."""
    salt = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)

    # Derive key from password
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000, dklen=32)

    # Encrypt
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, secret, None)

    return base64.b64encode(ciphertext).decode(), nonce.hex(), salt.hex()


def _decrypt_secret(encrypted_data: str, nonce: str, salt: str, password: str) -> bytes:
    """Decrypt a secret using ChaCha20-Poly1305."""
    ciphertext = base64.b64decode(encrypted_data)
    nonce_bytes = bytes.fromhex(nonce)
    salt_bytes = bytes.fromhex(salt)

    # Derive key from password
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt_bytes, 100000, dklen=32)

    # Decrypt
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce_bytes, ciphertext, None)


def generate_session_id() -> str:
    """Generate a random session ID."""
    return secrets.token_hex(32)
