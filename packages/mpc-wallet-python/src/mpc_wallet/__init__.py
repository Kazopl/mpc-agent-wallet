"""
MPC Wallet SDK for AI Agents

A Python SDK for secure, threshold-signed cryptocurrency transactions
using 2-of-3 MPC (Multi-Party Computation).

Example:
    >>> from mpc_wallet import MpcAgentWallet, PolicyConfig, PartyRole
    >>>
    >>> # Create wallet with policy
    >>> wallet = MpcAgentWallet(
    ...     role=PartyRole.AGENT,
    ...     policy=PolicyConfig(daily_limit=int(1e18)),  # 1 ETH
    ... )
    >>>
    >>> # Create keygen session
    >>> session = wallet.create_keygen_session()
    >>> round1_msg = session.generate_round1()
    >>> # ... exchange messages with other parties ...
"""

from .wallet import MpcAgentWallet, WalletConfig
from .keygen import KeyShare, KeyShareInfo, KeygenConfig, KeygenSession, KeygenResult
from .signing import SigningConfig, SigningSession, SigningResult, ApprovalRequest
from .policy import PolicyConfig, PolicyEngine, PolicyDecision, SpendingLimits, TimeBounds
from .types import (
    PartyRole,
    ChainType,
    Signature,
    TransactionRequest,
    Balance,
    TxHash,
    ErrorCode,
    MpcWalletError,
)

__version__ = "0.1.0"
__all__ = [
    # Wallet
    "MpcAgentWallet",
    "WalletConfig",
    # Key generation
    "KeyShare",
    "KeyShareInfo",
    "KeygenConfig",
    "KeygenSession",
    "KeygenResult",
    # Signing
    "SigningConfig",
    "SigningSession",
    "SigningResult",
    "ApprovalRequest",
    # Policy
    "PolicyConfig",
    "PolicyEngine",
    "PolicyDecision",
    "SpendingLimits",
    "TimeBounds",
    # Types
    "PartyRole",
    "ChainType",
    "Signature",
    "TransactionRequest",
    "Balance",
    "TxHash",
    "ErrorCode",
    "MpcWalletError",
]
