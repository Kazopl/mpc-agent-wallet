"""EVM chain adapter."""

from dataclasses import dataclass, field
from typing import Any
import asyncio
import httpx

from ..types import Balance, Signature, TxHash, TxReceipt


@dataclass
class EvmChainConfig:
    """EVM chain configuration."""

    chain_id: int
    name: str
    rpc_urls: list[str]
    symbol: str
    decimals: int = 18
    explorer_url: str | None = None


# Pre-configured chain configs
EVMChains = {
    "ETHEREUM_MAINNET": EvmChainConfig(
        chain_id=1,
        name="Ethereum Mainnet",
        rpc_urls=["https://eth.llamarpc.com", "https://rpc.ankr.com/eth"],
        symbol="ETH",
        explorer_url="https://etherscan.io",
    ),
    "ETHEREUM_SEPOLIA": EvmChainConfig(
        chain_id=11155111,
        name="Ethereum Sepolia",
        rpc_urls=["https://sepolia.drpc.org", "https://rpc.ankr.com/eth_sepolia"],
        symbol="ETH",
        explorer_url="https://sepolia.etherscan.io",
    ),
    "ARBITRUM_ONE": EvmChainConfig(
        chain_id=42161,
        name="Arbitrum One",
        rpc_urls=["https://arb1.arbitrum.io/rpc", "https://rpc.ankr.com/arbitrum"],
        symbol="ETH",
        explorer_url="https://arbiscan.io",
    ),
    "OPTIMISM": EvmChainConfig(
        chain_id=10,
        name="Optimism",
        rpc_urls=["https://mainnet.optimism.io", "https://rpc.ankr.com/optimism"],
        symbol="ETH",
        explorer_url="https://optimistic.etherscan.io",
    ),
    "BASE": EvmChainConfig(
        chain_id=8453,
        name="Base",
        rpc_urls=["https://mainnet.base.org", "https://base.llamarpc.com"],
        symbol="ETH",
        explorer_url="https://basescan.org",
    ),
    "POLYGON": EvmChainConfig(
        chain_id=137,
        name="Polygon",
        rpc_urls=["https://polygon-rpc.com", "https://rpc.ankr.com/polygon"],
        symbol="MATIC",
        explorer_url="https://polygonscan.com",
    ),
}


@dataclass
class EvmTxParams:
    """Transaction parameters for EVM."""

    from_address: str
    to: str
    value: str  # Value in wei as string
    data: str | None = None
    gas_limit: int | None = None
    max_fee_per_gas: int | None = None
    max_priority_fee_per_gas: int | None = None
    nonce: int | None = None


@dataclass
class UnsignedEvmTx:
    """Unsigned EVM transaction."""

    chain_id: int
    serialized: bytes
    signing_hash: bytes
    summary: dict[str, str]


class EvmAdapter:
    """
    EVM chain adapter.

    Example:
        >>> adapter = EvmAdapter(EVMChains["ETHEREUM_MAINNET"])
        >>>
        >>> # Get balance
        >>> balance = await adapter.get_balance("0x...")
        >>>
        >>> # Build transaction
        >>> unsigned_tx = await adapter.build_transaction(EvmTxParams(
        ...     from_address="0x...",
        ...     to="0x...",
        ...     value="1000000000000000000",  # 1 ETH
        ... ))
    """

    def __init__(self, config: EvmChainConfig) -> None:
        self._config = config
        self._current_rpc_index = 0

    @property
    def chain_id(self) -> int:
        """Get chain ID."""
        return self._config.chain_id

    @property
    def symbol(self) -> str:
        """Get native currency symbol."""
        return self._config.symbol

    @property
    def decimals(self) -> int:
        """Get native currency decimals."""
        return self._config.decimals

    async def get_balance(self, address: str) -> Balance:
        """Get balance for an address."""
        result = await self._rpc_call("eth_getBalance", [address, "latest"])
        raw_value = int(result, 16)
        formatted = self._format_value(raw_value)

        return Balance(
            raw=str(raw_value),
            formatted=formatted,
            symbol=self._config.symbol,
            decimals=self._config.decimals,
        )

    async def get_nonce(self, address: str) -> int:
        """Get nonce for an address."""
        result = await self._rpc_call("eth_getTransactionCount", [address, "latest"])
        return int(result, 16)

    async def get_gas_prices(self) -> dict[str, int]:
        """Get current gas prices (EIP-1559)."""
        # Get latest block for base fee
        block = await self._rpc_call("eth_getBlockByNumber", ["latest", False])
        base_fee = int(block.get("baseFeePerGas", "0x0"), 16)

        # Get priority fee suggestion
        try:
            priority_fee = await self._rpc_call("eth_maxPriorityFeePerGas", [])
            max_priority_fee = int(priority_fee, 16)
        except Exception:
            max_priority_fee = 1_000_000_000  # Default to 1 gwei

        max_fee = base_fee * 2 + max_priority_fee

        return {
            "base_fee": base_fee,
            "max_fee_per_gas": max_fee,
            "max_priority_fee_per_gas": max_priority_fee,
        }

    async def estimate_gas(self, params: EvmTxParams) -> int:
        """Estimate gas for a transaction."""
        result = await self._rpc_call(
            "eth_estimateGas",
            [
                {
                    "from": params.from_address,
                    "to": params.to,
                    "value": hex(int(params.value)),
                    "data": params.data or "0x",
                }
            ],
        )
        return int(result, 16)

    async def build_transaction(self, params: EvmTxParams) -> UnsignedEvmTx:
        """Build an unsigned transaction."""
        import json
        import hashlib

        # Get nonce if not provided
        nonce = params.nonce
        if nonce is None:
            nonce = await self.get_nonce(params.from_address)

        # Get gas prices
        gas_prices = await self.get_gas_prices()
        max_fee = params.max_fee_per_gas or gas_prices["max_fee_per_gas"]
        max_priority_fee = params.max_priority_fee_per_gas or gas_prices["max_priority_fee_per_gas"]

        # Estimate gas if not provided
        gas_limit = params.gas_limit
        if gas_limit is None:
            estimated = await self.estimate_gas(params)
            gas_limit = int(estimated * 1.2)  # 20% buffer

        # Build transaction
        tx = {
            "chainId": self._config.chain_id,
            "nonce": nonce,
            "maxFeePerGas": max_fee,
            "maxPriorityFeePerGas": max_priority_fee,
            "gasLimit": gas_limit,
            "to": params.to,
            "value": int(params.value),
            "data": params.data or "",
        }

        # Serialize (simplified)
        serialized = json.dumps(tx).encode()

        # Compute signing hash (simplified)
        signing_hash = hashlib.sha256(serialized).digest()

        # Estimate fee
        estimated_fee = gas_limit * max_fee

        return UnsignedEvmTx(
            chain_id=self._config.chain_id,
            serialized=serialized,
            signing_hash=signing_hash,
            summary={
                "from": params.from_address,
                "to": params.to,
                "value": self._format_value(int(params.value)),
                "estimated_fee": self._format_value(estimated_fee),
            },
        )

    def finalize_transaction(
        self, unsigned_tx: UnsignedEvmTx, signature: Signature
    ) -> bytes:
        """Finalize a transaction with signature."""
        r = bytes.fromhex(signature.r.removeprefix("0x"))
        s = bytes.fromhex(signature.s.removeprefix("0x"))
        v = signature.recovery_id

        signed = unsigned_tx.serialized + r + s + bytes([v])
        return signed

    async def broadcast(self, signed_tx: bytes) -> TxHash:
        """Broadcast a signed transaction."""
        tx_hex = "0x" + signed_tx.hex()
        result = await self._rpc_call("eth_sendRawTransaction", [tx_hex])

        explorer_url = None
        if self._config.explorer_url:
            explorer_url = f"{self._config.explorer_url}/tx/{result}"

        return TxHash(hash=result, explorer_url=explorer_url)

    async def wait_for_confirmation(
        self, tx_hash: str, timeout_secs: int = 60
    ) -> TxReceipt:
        """Wait for transaction confirmation."""
        import time

        start_time = time.time()

        while time.time() - start_time < timeout_secs:
            try:
                receipt = await self._rpc_call("eth_getTransactionReceipt", [tx_hash])
                if receipt:
                    return TxReceipt(
                        tx_hash=tx_hash,
                        block_number=int(receipt["blockNumber"], 16),
                        status="success" if receipt["status"] == "0x1" else "failed",
                        gas_used=int(receipt["gasUsed"], 16),
                        effective_gas_price=int(receipt.get("effectiveGasPrice", "0x0"), 16),
                    )
            except Exception:
                pass

            await asyncio.sleep(2)

        raise TimeoutError(f"Transaction {tx_hash} not confirmed within timeout")

    def is_valid_address(self, address: str) -> bool:
        """Check if an address is valid."""
        import re
        return bool(re.match(r"^0x[0-9a-fA-F]{40}$", address))

    def get_explorer_tx_url(self, tx_hash: str) -> str | None:
        """Get explorer URL for a transaction."""
        if not self._config.explorer_url:
            return None
        return f"{self._config.explorer_url}/tx/{tx_hash}"

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

    def _format_value(self, value: int) -> str:
        """Format a wei value."""
        divisor = 10 ** self._config.decimals
        whole = value // divisor
        fraction = value % divisor

        if fraction == 0:
            return f"{whole} {self._config.symbol}"

        fraction_str = str(fraction).zfill(self._config.decimals)
        trimmed = fraction_str.rstrip("0")
        return f"{whole}.{trimmed} {self._config.symbol}"
