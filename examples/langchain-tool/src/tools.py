"""
LangChain Tool implementations for MPC Agent Wallet

Updated for LangChain v1.2.3+ with latest @tool decorator patterns
and Pydantic v2 models.
"""

from typing import Optional
from langchain.tools import tool
from pydantic import BaseModel, Field

from mpc_wallet import (
    MpcAgentWallet,
    TransactionRequest,
    ChainType,
    MpcWalletError,
    ErrorCode,
)


# ============================================================================
# Input Schemas (Pydantic v2)
# ============================================================================

class BalanceInput(BaseModel):
    """Input schema for wallet balance check."""

    chain: str = Field(
        default="ethereum",
        description="Blockchain to check balance on (ethereum, polygon, arbitrum)",
    )


class SendInput(BaseModel):
    """Input schema for sending cryptocurrency."""

    to: str = Field(description="Recipient address (0x...) or ENS name")
    value: str = Field(description="Amount to send in ETH (e.g., '0.5')")
    chain: str = Field(
        default="ethereum",
        description="Blockchain to send on (ethereum, polygon, arbitrum)",
    )


class PolicyCheckInput(BaseModel):
    """Input schema for policy check."""

    to: str = Field(description="Recipient address")
    value: str = Field(description="Amount in ETH")
    chain: str = Field(default="ethereum", description="Blockchain")


# ============================================================================
# Global wallet instance (set via create_wallet_tools)
# ============================================================================

_wallet: Optional[MpcAgentWallet] = None
_relay_url: str = ""
_rpc_urls: dict = {}


def _get_wallet() -> MpcAgentWallet:
    """Get the configured wallet instance."""
    if _wallet is None:
        raise RuntimeError("Wallet not configured. Call create_wallet_tools first.")
    return _wallet


# ============================================================================
# Tools using @tool decorator (LangChain v1.2.3+ pattern)
# ============================================================================

@tool("wallet_address", return_direct=True)
def wallet_address() -> str:
    """Get the wallet's Ethereum address.

    Returns the wallet address that can receive funds.
    """
    try:
        wallet = _get_wallet()
        address = wallet.get_address()
        return f"Wallet address: {address}"
    except MpcWalletError as e:
        return f"Error: {e.message}"


@tool("wallet_balance", args_schema=BalanceInput)
def wallet_balance(chain: str = "ethereum") -> str:
    """Check the wallet balance on a specific blockchain.

    Use this when the user asks about their balance or how much crypto they have.

    Args:
        chain: Blockchain to check (ethereum, polygon, arbitrum)
    """
    try:
        wallet = _get_wallet()
        address = wallet.get_address()

        # In production, query RPC for actual balance
        # For now, return mock data
        return f"""Wallet Balance on {chain.capitalize()}:
- Address: {address}
- Balance: 1.5 ETH (~$3,000 USD)
- Chain: {chain}"""
    except MpcWalletError as e:
        return f"Error checking balance: {e.message}"


@tool("wallet_send", args_schema=SendInput)
def wallet_send(to: str, value: str, chain: str = "ethereum") -> str:
    """Send cryptocurrency from the MPC wallet.

    This requires user approval via their mobile device.
    Use this when the user wants to transfer ETH or tokens to another address.

    Args:
        to: Recipient address (0x...) or ENS name
        value: Amount to send in ETH (e.g., '0.5')
        chain: Blockchain to send on (ethereum, polygon, arbitrum)
    """
    import uuid

    try:
        wallet = _get_wallet()

        # Validate address (basic check)
        if not to.startswith("0x") or len(to) != 42:
            # Could be ENS - in production, resolve it
            if to.endswith(".eth"):
                return f"ENS resolution needed for {to}. Please provide the actual address."
            return f"Invalid address format: {to}"

        # Create transaction request
        chain_ids = {"ethereum": 1, "polygon": 137, "arbitrum": 42161}
        chain_id = chain_ids.get(chain, 1)

        tx = TransactionRequest(
            request_id=str(uuid.uuid4()),
            chain=ChainType.EVM,
            to=to,
            value=str(int(float(value) * 10**18)),  # Convert to wei
            chain_id=chain_id,
        )

        # Check policy first
        decision = wallet.evaluate_policy(tx)

        if not decision.approved:
            return f"""Transaction would be rejected by policy:
- Reason: {decision.reason}
- Amount: {value} ETH
- To: {to}

Please adjust the transaction to comply with spending limits."""

        # In production, submit to relay for approval
        return f"""Transaction submitted for approval:

Transaction Details:
- To: {to}
- Amount: {value} ETH
- Chain: {chain.capitalize()}
- Estimated Gas: ~21,000 (~0.001 ETH)

Waiting for user approval...
Request ID: {tx.request_id}

The user needs to approve this transaction in their mobile app."""

    except MpcWalletError as e:
        return f"Error: {e.message}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"


@tool("wallet_check_policy", args_schema=PolicyCheckInput)
def wallet_check_policy(to: str, value: str, chain: str = "ethereum") -> str:
    """Check if a transaction would be approved by the spending policy.

    Use this to verify limits before attempting to send.

    Args:
        to: Recipient address
        value: Amount in ETH
        chain: Blockchain
    """
    import uuid

    try:
        wallet = _get_wallet()
        chain_ids = {"ethereum": 1, "polygon": 137, "arbitrum": 42161}
        chain_id = chain_ids.get(chain, 1)

        tx = TransactionRequest(
            request_id=str(uuid.uuid4()),
            chain=ChainType.EVM,
            to=to,
            value=str(int(float(value) * 10**18)),
            chain_id=chain_id,
        )

        decision = wallet.evaluate_policy(tx)

        if decision.approved:
            extra = ""
            if decision.requires_additional_approval:
                extra = "\nNote: This high-value transaction requires additional approval."
            return f"""[OK] Transaction would be APPROVED
- Amount: {value} ETH
- To: {to}
- Chain: {chain}{extra}"""
        else:
            return f"""[REJECTED] Transaction would be REJECTED
- Amount: {value} ETH
- To: {to}
- Chain: {chain}
- Reason: {decision.reason}"""

    except MpcWalletError as e:
        return f"Error checking policy: {e.message}"


# ============================================================================
# Factory Function
# ============================================================================

def create_wallet_tools(
    wallet: MpcAgentWallet,
    relay_url: str = "",
    rpc_urls: Optional[dict] = None,
) -> list:
    """
    Create a list of LangChain tools for wallet operations.

    This function configures the global wallet instance and returns
    the tools ready for use with a LangChain agent.

    Args:
        wallet: Initialized MpcAgentWallet instance
        relay_url: URL of the relay service
        rpc_urls: Dict of chain -> RPC URL mappings

    Returns:
        List of LangChain tools
    """
    global _wallet, _relay_url, _rpc_urls

    _wallet = wallet
    _relay_url = relay_url
    _rpc_urls = rpc_urls or {
        "ethereum": "https://eth.llamarpc.com",
        "polygon": "https://polygon-rpc.com",
        "arbitrum": "https://arb1.arbitrum.io/rpc",
    }

    return [
        wallet_address,
        wallet_balance,
        wallet_send,
        wallet_check_policy,
    ]


# ============================================================================
# Alternative: Class-based tools (for more control)
# ============================================================================

class WalletTools:
    """
    Class-based wallet tools for more control over configuration.

    Example:
        tools = WalletTools(wallet, relay_url="wss://...")
        agent = initialize_agent(tools.get_tools(), llm)
    """

    def __init__(
        self,
        wallet: MpcAgentWallet,
        relay_url: str = "",
        rpc_urls: Optional[dict] = None,
    ):
        self.wallet = wallet
        self.relay_url = relay_url
        self.rpc_urls = rpc_urls or {
            "ethereum": "https://eth.llamarpc.com",
            "polygon": "https://polygon-rpc.com",
            "arbitrum": "https://arb1.arbitrum.io/rpc",
        }

    def get_tools(self) -> list:
        """Get configured tools list."""
        return create_wallet_tools(
            self.wallet,
            self.relay_url,
            self.rpc_urls,
        )
