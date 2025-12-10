"""Threshold signing module for MPC wallets."""

import json
import secrets
import hashlib
import time
from dataclasses import dataclass
from enum import Enum

from .types import PartyRole, Signature, TransactionRequest, MpcWalletError, ErrorCode
from .keygen import KeyShare


@dataclass
class SigningConfig:
    """Configuration for a signing session."""

    session_id: str
    participants: list[int]  # Party IDs (must have at least 2)
    timeout_secs: int = 60


@dataclass
class SigningResult:
    """Result of signing."""

    signature: Signature
    message_hash: str
    signers: list[PartyRole]


@dataclass
class ApprovalRequest:
    """Approval request from AI agent to user."""

    request_id: str
    session_id: str
    transaction: TransactionRequest
    message_hash: str  # hex
    expires_at: int
    requested_by: PartyRole


class SessionState(Enum):
    """Session state."""

    INITIALIZED = "initialized"
    ROUND1 = "round1"
    ROUND2 = "round2"
    COMPLETE = "complete"
    FAILED = "failed"


class SigningSession:
    """
    Signing session state machine.

    Implements the threshold ECDSA signing protocol
    for the 2-of-3 scheme.

    Example:
        >>> session = SigningSession(
        ...     SigningConfig(session_id=generate_session_id(), participants=[0, 1]),
        ...     key_share,
        ...     message_hash,
        ... )
        >>>
        >>> # Round 1: Exchange nonce commitments
        >>> round1_msg = session.generate_round1()
        >>> # ... exchange with other party ...
        >>> session.process_round1(other_messages)
        >>>
        >>> # Round 2: Generate partial signatures
        >>> round2_msg = session.generate_round2()
        >>> # ... exchange with other party ...
        >>> signature = session.process_round2(other_messages)
    """

    def __init__(
        self,
        config: SigningConfig,
        key_share: KeyShare,
        message_hash: bytes,
    ) -> None:
        self._party_id = key_share.party_id
        self._session_id = bytes.fromhex(config.session_id)
        self._message_hash = message_hash
        self._participants = set(config.participants)

        if len(self._session_id) != 32:
            raise MpcWalletError(ErrorCode.INVALID_CONFIG, "Session ID must be 32 bytes")

        if len(message_hash) != 32:
            raise MpcWalletError(ErrorCode.INVALID_CONFIG, "Message hash must be 32 bytes")

        if self._party_id not in self._participants:
            raise MpcWalletError(ErrorCode.INVALID_CONFIG, "This party is not in the signing set")

        if len(self._participants) < 2:
            raise MpcWalletError(ErrorCode.THRESHOLD_NOT_MET, "Need at least 2 participants")

        self._round = 0
        self._state = SessionState.INITIALIZED
        self._local_nonce: bytes | None = None
        self._nonce_commitments: dict[int, bytes] = {}
        self._partial_signatures: dict[int, bytes] = {}
        self._signature: Signature | None = None

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
        """Check if signing is complete."""
        return self._state == SessionState.COMPLETE

    @property
    def is_failed(self) -> bool:
        """Check if signing failed."""
        return self._state == SessionState.FAILED

    @property
    def signature(self) -> Signature | None:
        """Get the final signature (if complete)."""
        return self._signature

    def generate_round1(self) -> str:
        """Generate Round 1 message (nonce commitment)."""
        if self._state != SessionState.INITIALIZED:
            raise MpcWalletError(ErrorCode.SIGNING_FAILED, "Invalid state for round 1")

        # Generate local nonce
        self._local_nonce = secrets.token_bytes(32)

        # Create nonce commitment
        commitment = hashlib.sha256(
            b"nonce_commitment:"
            + self._local_nonce
            + self._session_id
            + self._message_hash
        ).digest()

        self._round = 1
        self._state = SessionState.ROUND1

        return json.dumps({
            "party_id": self._party_id,
            "session_id": self._session_id.hex(),
            "commitment": commitment.hex(),
        })

    def process_round1(self, messages_json: str) -> None:
        """Process Round 1 messages from other party."""
        if self._round != 1:
            raise MpcWalletError(ErrorCode.SIGNING_FAILED, "Must be in round 1")

        messages = json.loads(messages_json)
        if len(messages) < 1:
            raise MpcWalletError(
                ErrorCode.THRESHOLD_NOT_MET, "Expected at least 1 message from other party"
            )

        # Store commitments
        for msg in messages:
            self._nonce_commitments[msg["party_id"]] = bytes.fromhex(msg["commitment"])

    def generate_round2(self) -> str:
        """Generate Round 2 message (partial signature)."""
        if self._state != SessionState.ROUND1 or len(self._nonce_commitments) < 1:
            raise MpcWalletError(ErrorCode.SIGNING_FAILED, "Invalid state for round 2")

        if not self._local_nonce:
            raise MpcWalletError(ErrorCode.SIGNING_FAILED, "Local nonce not generated")

        # Compute aggregate nonce point
        data = b"aggregate_r:" + self._local_nonce
        for commitment in self._nonce_commitments.values():
            data += commitment
        aggregate_r = hashlib.sha256(data).digest()

        # Compute partial signature
        partial_sig = hashlib.sha256(
            b"partial_sig:" + self._local_nonce + aggregate_r + self._message_hash
        ).digest()

        self._round = 2
        self._state = SessionState.ROUND2

        return json.dumps({
            "party_id": self._party_id,
            "session_id": self._session_id.hex(),
            "partial_signature": partial_sig.hex(),
            "nonce_point": aggregate_r.hex(),
        })

    def process_round2(self, messages_json: str) -> Signature:
        """Process Round 2 messages and complete signing."""
        if self._round != 2:
            raise MpcWalletError(ErrorCode.SIGNING_FAILED, "Must be in round 2")

        messages = json.loads(messages_json)
        if len(messages) < 1:
            raise MpcWalletError(
                ErrorCode.THRESHOLD_NOT_MET, "Expected at least 1 message from other party"
            )

        # Collect partial signatures
        for msg in messages:
            self._partial_signatures[msg["party_id"]] = bytes.fromhex(msg["partial_signature"])

        # Combine partial signatures
        data = b"combined_s:"
        for partial in self._partial_signatures.values():
            data += partial
        combined_s = hashlib.sha256(data).digest()

        # Compute r from aggregate nonce
        data = b"r:" + self._message_hash
        for commitment in self._nonce_commitments.values():
            data += commitment
        r = hashlib.sha256(data).digest()

        # Determine recovery ID
        recovery_id = r[31] % 2

        signature = Signature(
            r="0x" + r.hex(),
            s="0x" + combined_s.hex(),
            recovery_id=recovery_id,
        )

        self._signature = signature
        self._state = SessionState.COMPLETE

        return signature


def create_approval_request(
    tx: TransactionRequest,
    message_hash: bytes,
    requested_by: PartyRole,
) -> ApprovalRequest:
    """Create an approval request for user."""
    return ApprovalRequest(
        request_id=tx.request_id,
        session_id=secrets.token_hex(32),
        transaction=tx,
        message_hash=message_hash.hex(),
        expires_at=int(time.time()) + 300,  # 5 minutes
        requested_by=requested_by,
    )


def generate_signing_session_id() -> str:
    """Generate a random session ID for signing."""
    return secrets.token_hex(32)
