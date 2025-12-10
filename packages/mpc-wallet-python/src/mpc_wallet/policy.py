"""Policy engine for transaction validation."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .types import ChainType, TransactionRequest


@dataclass
class PolicyDecision:
    """Policy decision result."""

    approved: bool
    requires_additional_approval: bool = False
    reason: str | None = None

    def can_proceed(self) -> bool:
        """Check if transaction should proceed."""
        return self.approved or self.requires_additional_approval


@dataclass
class SpendingLimits:
    """Spending limits configuration."""

    per_transaction: int | None = None  # In wei
    daily: int | None = None
    weekly: int | None = None
    currency: str = "ETH"


@dataclass
class TimeBounds:
    """Time window restriction."""

    start_hour: int = 0  # 0-23, UTC
    end_hour: int = 24  # 0-23, UTC
    allowed_days: list[int] = field(default_factory=lambda: [0, 1, 2, 3, 4, 5, 6])

    @classmethod
    def business_hours(cls) -> "TimeBounds":
        """Create business hours restriction (9 AM - 5 PM UTC, weekdays)."""
        return cls(start_hour=9, end_hour=17, allowed_days=[1, 2, 3, 4, 5])

    def is_allowed(self, dt: datetime) -> bool:
        """Check if a datetime falls within the time bounds."""
        hour = dt.hour
        day = dt.weekday()  # 0=Monday in Python, need to convert

        # Convert Python weekday (0=Monday) to JS-style (0=Sunday)
        day = (day + 1) % 7

        if self.start_hour <= self.end_hour:
            hour_ok = self.start_hour <= hour < self.end_hour
        else:
            # Handles wrap-around (e.g., 22:00 - 06:00)
            hour_ok = hour >= self.start_hour or hour < self.end_hour

        return hour_ok and day in self.allowed_days


@dataclass
class ContractRestriction:
    """Contract interaction restriction."""

    allowed_contracts: set[str] = field(default_factory=set)
    allowed_selectors: set[str] = field(default_factory=set)
    blocked_selectors: set[str] = field(default_factory=set)

    def allow_contract(self, address: str) -> "ContractRestriction":
        """Add an allowed contract."""
        self.allowed_contracts.add(address.lower())
        return self

    def allow_selector(self, selector: str) -> "ContractRestriction":
        """Add an allowed function selector."""
        self.allowed_selectors.add(selector.lower())
        return self

    def block_selector(self, selector: str) -> "ContractRestriction":
        """Block a function selector."""
        self.blocked_selectors.add(selector.lower())
        return self


@dataclass
class PolicyConfig:
    """Policy configuration."""

    spending_limits: dict[ChainType, SpendingLimits] = field(default_factory=dict)
    whitelist: set[str] | None = None
    blacklist: set[str] = field(default_factory=set)
    time_bounds: TimeBounds | None = None
    contract_restrictions: ContractRestriction | None = None
    additional_approval_threshold: int | None = None
    max_pending_requests: int = 10
    enabled: bool = True

    @classmethod
    def disabled(cls) -> "PolicyConfig":
        """Create a disabled policy (all transactions allowed)."""
        return cls(enabled=False)

    def with_per_tx_limit(self, amount: int, currency: str = "ETH") -> "PolicyConfig":
        """Set per-transaction spending limit."""
        limits = self.spending_limits.get(ChainType.EVM, SpendingLimits())
        limits.per_transaction = amount
        limits.currency = currency
        self.spending_limits[ChainType.EVM] = limits
        return self

    def with_daily_limit(self, amount: int) -> "PolicyConfig":
        """Set daily spending limit."""
        limits = self.spending_limits.get(ChainType.EVM, SpendingLimits())
        limits.daily = amount
        self.spending_limits[ChainType.EVM] = limits
        return self

    def with_weekly_limit(self, amount: int) -> "PolicyConfig":
        """Set weekly spending limit."""
        limits = self.spending_limits.get(ChainType.EVM, SpendingLimits())
        limits.weekly = amount
        self.spending_limits[ChainType.EVM] = limits
        return self

    def with_whitelist(self, addresses: list[str]) -> "PolicyConfig":
        """Set address whitelist."""
        self.whitelist = {a.lower() for a in addresses}
        return self

    def with_blacklist(self, addresses: list[str]) -> "PolicyConfig":
        """Set address blacklist."""
        self.blacklist = {a.lower() for a in addresses}
        return self

    def with_time_bounds(self, bounds: TimeBounds) -> "PolicyConfig":
        """Set time bounds."""
        self.time_bounds = bounds
        return self

    def with_business_hours(self) -> "PolicyConfig":
        """Set business hours restriction."""
        self.time_bounds = TimeBounds.business_hours()
        return self

    def with_contract_restrictions(self, restrictions: ContractRestriction) -> "PolicyConfig":
        """Set contract restrictions."""
        self.contract_restrictions = restrictions
        return self

    def with_additional_approval_threshold(self, amount: int) -> "PolicyConfig":
        """Set additional approval threshold."""
        self.additional_approval_threshold = amount
        return self


class PolicyEngine:
    """Policy engine for evaluating transactions."""

    def __init__(self, config: PolicyConfig) -> None:
        self._config = config
        self._daily_spending: dict[str, int] = {}
        self._weekly_spending: dict[str, int] = {}

    @property
    def config(self) -> PolicyConfig:
        """Get the policy configuration."""
        return self._config

    def set_config(self, config: PolicyConfig) -> None:
        """Update the policy configuration."""
        self._config = config

    def evaluate(self, tx: TransactionRequest) -> PolicyDecision:
        """Evaluate a transaction against the policy."""
        # Skip evaluation if policy is disabled
        if not self._config.enabled:
            return PolicyDecision(approved=True)

        to_address = tx.to.lower()

        # Check blacklist
        if to_address in self._config.blacklist:
            return PolicyDecision(
                approved=False,
                reason=f"Address {tx.to} is blacklisted",
            )

        # Check whitelist
        if self._config.whitelist and to_address not in self._config.whitelist:
            return PolicyDecision(
                approved=False,
                reason=f"Address {tx.to} is not whitelisted",
            )

        # Check time bounds
        if self._config.time_bounds:
            now = datetime.now(timezone.utc)
            if not self._config.time_bounds.is_allowed(now):
                bounds = self._config.time_bounds
                return PolicyDecision(
                    approved=False,
                    reason=f"Transaction outside allowed time window ({bounds.start_hour}:00-{bounds.end_hour}:00 UTC)",
                )

        # Check contract restrictions
        if tx.is_contract_call() and self._config.contract_restrictions:
            restrictions = self._config.contract_restrictions

            # Check allowed contracts
            if restrictions.allowed_contracts and to_address not in restrictions.allowed_contracts:
                return PolicyDecision(
                    approved=False,
                    reason=f"Contract {tx.to} is not in allowed list",
                )

            # Check function selectors
            selector = tx.function_selector()
            if selector:
                selector = selector.lower()

                if selector in restrictions.blocked_selectors:
                    return PolicyDecision(
                        approved=False,
                        reason=f"Function selector {selector} is blocked",
                    )

                if (
                    restrictions.allowed_selectors
                    and selector not in restrictions.allowed_selectors
                ):
                    return PolicyDecision(
                        approved=False,
                        reason=f"Function selector {selector} is not in allowed list",
                    )

        # Parse transaction value
        value = self._parse_value(tx.value)

        # Check spending limits
        limits = self._config.spending_limits.get(tx.chain)
        if limits:
            # Per-transaction limit
            if limits.per_transaction and value > limits.per_transaction:
                return PolicyDecision(
                    approved=False,
                    reason=f"Transaction value exceeds per-transaction limit of {limits.per_transaction}",
                )

            # Daily limit
            if limits.daily:
                now = datetime.now(timezone.utc)
                date_key = now.strftime("%Y-%m-%d")
                spent = self._daily_spending.get(date_key, 0)
                if spent + value > limits.daily:
                    return PolicyDecision(
                        approved=False,
                        reason=f"Transaction would exceed daily limit of {limits.daily}",
                    )

            # Weekly limit
            if limits.weekly:
                now = datetime.now(timezone.utc)
                week_key = now.strftime("%Y-W%W")
                spent = self._weekly_spending.get(week_key, 0)
                if spent + value > limits.weekly:
                    return PolicyDecision(
                        approved=False,
                        reason=f"Transaction would exceed weekly limit of {limits.weekly}",
                    )

        # Check additional approval threshold
        if self._config.additional_approval_threshold:
            if value > self._config.additional_approval_threshold:
                return PolicyDecision(
                    approved=False,
                    requires_additional_approval=True,
                    reason="Transaction value exceeds additional approval threshold",
                )

        return PolicyDecision(approved=True)

    def record_transaction(self, tx: TransactionRequest) -> None:
        """Record a completed transaction for spending tracking."""
        value = self._parse_value(tx.value)
        now = datetime.now(timezone.utc)

        date_key = now.strftime("%Y-%m-%d")
        week_key = now.strftime("%Y-W%W")

        # Update daily spending
        self._daily_spending[date_key] = self._daily_spending.get(date_key, 0) + value

        # Update weekly spending
        self._weekly_spending[week_key] = self._weekly_spending.get(week_key, 0) + value

    def get_daily_spending(self) -> int:
        """Get current daily spending."""
        now = datetime.now(timezone.utc)
        date_key = now.strftime("%Y-%m-%d")
        return self._daily_spending.get(date_key, 0)

    def get_weekly_spending(self) -> int:
        """Get current weekly spending."""
        now = datetime.now(timezone.utc)
        week_key = now.strftime("%Y-W%W")
        return self._weekly_spending.get(week_key, 0)

    def reset_spending(self) -> None:
        """Reset spending trackers."""
        self._daily_spending.clear()
        self._weekly_spending.clear()

    def _parse_value(self, value: str) -> int:
        """Parse a value string to int."""
        # Handle decimal values (e.g., "1.5" ETH -> wei)
        if "." in value:
            whole, decimal = value.split(".")
            whole_int = int(whole or "0") * (10**18)
            decimal_padded = decimal.ljust(18, "0")[:18]
            decimal_int = int(decimal_padded)
            return whole_int + decimal_int
        return int(value)
