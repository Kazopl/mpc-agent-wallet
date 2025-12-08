"""Core type definitions for MPC Wallet SDK."""

from enum import IntEnum
from typing import Any
from dataclasses import dataclass, field


class PartyRole(IntEnum):
    """Party roles in the 2-of-3 MPC wallet."""

    AGENT = 0  # AI agent party - can initiate transactions
    USER = 1  # User party - primary approval authority
    RECOVERY = 2  # Recovery guardian - backup approval


class ChainType(IntEnum):
    """Supported blockchain types."""

    EVM = 0  # Ethereum and EVM-compatible chains
    SOLANA = 1  # Solana
    BITCOIN = 2  # Bitcoin


class ErrorCode(IntEnum):
    """Error codes for SDK operations."""

    INVALID_CONFIG = 1
    INVALID_PARTY_ID = 2
    THRESHOLD_NOT_MET = 3
    POLICY_VIOLATION = 4
    SIGNING_FAILED = 5
    KEYGEN_FAILED = 6
    STORAGE_ERROR = 7
    NETWORK_ERROR = 8
    TIMEOUT = 9
    UNKNOWN = 99


class MpcWalletError(Exception):
    """Base exception for MPC Wallet SDK."""

    def __init__(self, code: ErrorCode, message: str, cause: Exception | None = None):
        super().__init__(message)
        self.code = code
        self.cause = cause


@dataclass
class Signature:
    """ECDSA signature components."""

    r: str  # R component (hex string with 0x prefix)
    s: str  # S component (hex string with 0x prefix)
    recovery_id: int  # Recovery ID (0 or 1)

    def to_bytes(self) -> bytes:
        """Convert to bytes (r || s || v)."""
        r_bytes = bytes.fromhex(self.r.removeprefix("0x"))
        s_bytes = bytes.fromhex(self.s.removeprefix("0x"))
        return r_bytes + s_bytes + bytes([self.recovery_id + 27])

    def to_hex(self) -> str:
        """Convert to hex string."""
        return "0x" + self.to_bytes().hex()

    def to_eip155(self, chain_id: int) -> bytes:
        """Convert to EIP-155 format."""
        r_bytes = bytes.fromhex(self.r.removeprefix("0x"))
        s_bytes = bytes.fromhex(self.s.removeprefix("0x"))
        v = self.recovery_id + 35 + chain_id * 2
        return r_bytes + s_bytes + bytes([v])


@dataclass
class TransactionRequest:
    """Transaction request for signing."""

    request_id: str
    chain: ChainType
    to: str
    value: str
    data: str | None = None
    gas_limit: int | None = None
    chain_id: int | None = None
    timestamp: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_contract_call(self) -> bool:
        """Check if this is a contract interaction."""
        return self.data is not None and len(self.data) > 2

    def function_selector(self) -> str | None:
        """Get the function selector (first 4 bytes of data)."""
        if self.data and len(self.data) >= 10:
            return self.data[:10]
        return None


@dataclass
class Balance:
    """Balance information."""

    raw: str  # Raw balance in smallest unit
    formatted: str  # Human-readable balance with decimals
    symbol: str  # Currency/token symbol
    decimals: int  # Number of decimals

    def is_zero(self) -> bool:
        """Check if balance is zero."""
        return self.raw == "0" or not self.raw


@dataclass
class TxHash:
    """Transaction hash result."""

    hash: str  # Transaction hash
    explorer_url: str | None = None  # Explorer URL (if available)


@dataclass
class TxReceipt:
    """Transaction receipt."""

    tx_hash: str
    block_number: int
    status: str  # "success", "failed", or "pending"
    gas_used: int | None = None
    effective_gas_price: int | None = None
