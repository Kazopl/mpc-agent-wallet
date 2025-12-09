"""Solana chain adapter."""

from dataclasses import dataclass
from typing import Any
import asyncio
import httpx

from ..types import Balance, TxHash


@dataclass
class SolanaChainConfig:
    """Solana chain configuration."""

    name: str
    rpc_urls: list[str]
    commitment: str = "confirmed"
    explorer_url: str | None = None


# Pre-configured Solana networks
SolanaNetworks = {
    "MAINNET": SolanaChainConfig(
        name="Solana Mainnet",
        rpc_urls=["https://api.mainnet-beta.solana.com"],
        explorer_url="https://explorer.solana.com",
    ),
    "DEVNET": SolanaChainConfig(
        name="Solana Devnet",
        rpc_urls=["https://api.devnet.solana.com"],
        explorer_url="https://explorer.solana.com?cluster=devnet",
    ),
    "TESTNET": SolanaChainConfig(
        name="Solana Testnet",
        rpc_urls=["https://api.testnet.solana.com"],
        explorer_url="https://explorer.solana.com?cluster=testnet",
    ),
}


@dataclass
class SolanaTxParams:
    """Transaction parameters for Solana."""

    from_address: str  # Base58 pubkey
    to: str  # Base58 pubkey
    amount: int  # In lamports
    recent_blockhash: str | None = None
    priority_fee: int | None = None


@dataclass
class UnsignedSolanaTx:
    """Unsigned Solana transaction."""

    message: bytes
    recent_blockhash: str
    summary: dict[str, str]


class SolanaAdapter:
    """
    Solana chain adapter.

    Example:
        >>> adapter = SolanaAdapter(SolanaNetworks["MAINNET"])
        >>>
        >>> # Get balance
        >>> balance = await adapter.get_balance("...")
        >>>
        >>> # Build transaction
        >>> unsigned_tx = await adapter.build_transaction(SolanaTxParams(
        ...     from_address="...",
        ...     to="...",
        ...     amount=1_000_000_000,  # 1 SOL
        ... ))
    """

    def __init__(self, config: SolanaChainConfig) -> None:
        self._config = config
        self._current_rpc_index = 0

    @property
    def name(self) -> str:
        """Get network name."""
        return self._config.name

    @property
    def symbol(self) -> str:
        """Get native currency symbol."""
        return "SOL"

    @property
    def decimals(self) -> int:
        """Get native currency decimals."""
        return 9

    async def get_balance(self, address: str) -> Balance:
        """Get SOL balance for an address."""
        result = await self._rpc_call(
            "getBalance",
            [address, {"commitment": self._config.commitment}],
        )

        raw_value = result["value"]
        formatted = self._format_lamports(raw_value)

        return Balance(
            raw=str(raw_value),
            formatted=formatted,
            symbol="SOL",
            decimals=9,
        )

    async def get_recent_blockhash(self) -> str:
        """Get recent blockhash."""
        result = await self._rpc_call(
            "getLatestBlockhash",
            [{"commitment": self._config.commitment}],
        )
        return result["value"]["blockhash"]

    async def build_transaction(self, params: SolanaTxParams) -> UnsignedSolanaTx:
        """Build an unsigned transaction."""
        import json

        recent_blockhash = params.recent_blockhash
        if not recent_blockhash:
            recent_blockhash = await self.get_recent_blockhash()

        # Build a simple transfer message (simplified)
        message = json.dumps({
            "from": params.from_address,
            "to": params.to,
            "amount": params.amount,
            "recentBlockhash": recent_blockhash,
            "programId": "11111111111111111111111111111111",
        }).encode()

        # Estimate fee
        base_fee = 5000  # 5000 lamports
        priority_fee = (params.priority_fee or 1000) * 200
        estimated_fee = base_fee + priority_fee

        return UnsignedSolanaTx(
            message=message,
            recent_blockhash=recent_blockhash,
            summary={
                "from": params.from_address,
                "to": params.to,
                "amount": self._format_lamports(params.amount),
                "estimated_fee": self._format_lamports(estimated_fee),
            },
        )

    def finalize_transaction(
        self, unsigned_tx: UnsignedSolanaTx, signature: bytes
    ) -> bytes:
        """Finalize a transaction with signature."""
        # Solana transaction format: [sig_count, signatures..., message]
        tx = bytes([1]) + signature[:64] + unsigned_tx.message
        return tx

    async def broadcast(self, signed_tx: bytes) -> TxHash:
        """Broadcast a signed transaction."""
        import base64

        tx_base64 = base64.b64encode(signed_tx).decode()

        result = await self._rpc_call(
            "sendTransaction",
            [tx_base64, {"encoding": "base64", "preflightCommitment": self._config.commitment}],
        )

        explorer_url = None
        if self._config.explorer_url:
            explorer_url = f"{self._config.explorer_url}/tx/{result}"

        return TxHash(hash=result, explorer_url=explorer_url)

    async def wait_for_confirmation(
        self, signature: str, timeout_secs: int = 60
    ) -> dict[str, Any]:
        """Wait for transaction confirmation."""
        import time

        start_time = time.time()

        while time.time() - start_time < timeout_secs:
            try:
                result = await self._rpc_call("getSignatureStatuses", [[signature]])
                status = result["value"][0]
                if status:
                    confirmation = status.get("confirmationStatus", "")
                    if confirmation in ("confirmed", "finalized"):
                        return {
                            "confirmed": True,
                            "slot": status.get("slot"),
                        }
            except Exception:
                pass

            await asyncio.sleep(2)

        return {"confirmed": False}

    def is_valid_address(self, address: str) -> bool:
        """Check if an address is valid (base58)."""
        import re
        return bool(re.match(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", address))

    def get_explorer_tx_url(self, signature: str) -> str | None:
        """Get explorer URL for a transaction."""
        if not self._config.explorer_url:
            return None
        return f"{self._config.explorer_url}/tx/{signature}"

    def get_explorer_address_url(self, address: str) -> str | None:
        """Get explorer URL for an address."""
        if not self._config.explorer_url:
            return None
        return f"{self._config.explorer_url}/address/{address}"

    async def _rpc_call(self, method: str, params: list[Any]) -> Any:
        """Make an RPC call with failover."""
        errors: list[str] = []

        async with httpx.AsyncClient(timeout=30.0) as client:
            for _ in range(len(self._config.rpc_urls)):
                rpc_url = self._config.rpc_urls[self._current_rpc_index]

                try:
                    response = await client.post(
                        rpc_url,
                        json={
                            "jsonrpc": "2.0",
                            "method": method,
                            "params": params,
                            "id": 1,
                        },
                    )
                    data = response.json()

                    if "error" in data:
                        raise Exception(data["error"].get("message", "RPC error"))

                    return data["result"]

                except Exception as e:
                    errors.append(str(e))
                    self._current_rpc_index = (
                        self._current_rpc_index + 1
                    ) % len(self._config.rpc_urls)

        raise Exception(f"All RPC endpoints failed: {', '.join(errors)}")

    def _format_lamports(self, lamports: int) -> str:
        """Format lamports as SOL."""
        sol = lamports / 1e9
        return f"{sol:.9f}".rstrip("0").rstrip(".") + " SOL"
