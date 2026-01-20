// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IEntryPoint } from "./IEntryPoint.sol";

/**
 * @title IMpcPaymaster
 * @notice Interface for the MPC Agent Wallet Paymaster
 * @dev ERC-4337 paymaster that sponsors gas for approved MPC smart accounts
 *
 * Features:
 * - Account-based sponsorship management
 * - Per-account sponsorship limits
 * - Global daily sponsorship caps
 * - Owner-controlled whitelist
 *
 * Use Cases:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                     PAYMASTER SPONSORSHIP SCENARIOS                          │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │   AI Agent Onboarding                                                       │
 * │   ├─ Sponsor first N transactions for new users                             │
 * │   ├─ Per-account limit: 0.1 ETH                                             │
 * │   └─ Gradually reduce as user becomes familiar                              │
 * │                                                                             │
 * │   Premium User Accounts                                                     │
 * │   ├─ Unlimited sponsorship for VIP accounts                                 │
 * │   ├─ Higher daily limits                                                    │
 * │   └─ Priority transaction inclusion                                         │
 * │                                                                             │
 * │   DeFi Protocol Integration                                                 │
 * │   ├─ Protocol sponsors gas for their users                                  │
 * │   ├─ Whitelist specific contract interactions                               │
 * │   └─ Cross-subsidize from protocol fees                                     │
 * │                                                                             │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
interface IMpcPaymaster {
    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Sponsorship configuration for an account
     * @param active Whether sponsorship is currently active
     * @param limit Maximum total sponsorship amount (0 = unlimited)
     * @param spent Total amount already sponsored
     * @param dailyLimit Maximum daily sponsorship (0 = unlimited)
     * @param dailySpent Amount sponsored today
     * @param dailyResetTime Timestamp when daily counter resets
     */
    struct SponsorshipConfig {
        bool active;
        uint256 limit;
        uint256 spent;
        uint256 dailyLimit;
        uint256 dailySpent;
        uint256 dailyResetTime;
    }

    /**
     * @notice Post-operation mode from EntryPoint
     */
    enum PostOpMode {
        OpSucceeded,
        OpReverted,
        PostOpReverted
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Emitted when an account is sponsored
     * @param account The sponsored smart account
     * @param limit Maximum sponsorship limit
     * @param dailyLimit Daily sponsorship limit
     */
    event AccountSponsored(address indexed account, uint256 limit, uint256 dailyLimit);

    /**
     * @notice Emitted when sponsorship is revoked
     * @param account The account that lost sponsorship
     */
    event SponsorshipRevoked(address indexed account);

    /**
     * @notice Emitted when sponsorship limits are updated
     * @param account The account with updated limits
     * @param newLimit New total limit
     * @param newDailyLimit New daily limit
     */
    event SponsorshipUpdated(address indexed account, uint256 newLimit, uint256 newDailyLimit);

    /**
     * @notice Emitted when gas is sponsored for an operation
     * @param account The account that was sponsored
     * @param actualGasCost The actual gas cost paid
     * @param totalSpent Total amount sponsored for this account
     */
    event GasSponsored(address indexed account, uint256 actualGasCost, uint256 totalSpent);

    /**
     * @notice Emitted when the paymaster is funded
     * @param sender Who funded the paymaster
     * @param amount Amount deposited to EntryPoint
     */
    event PaymasterFunded(address indexed sender, uint256 amount);

    /**
     * @notice Emitted when funds are withdrawn from the paymaster
     * @param to Withdrawal recipient
     * @param amount Amount withdrawn
     */
    event FundsWithdrawn(address indexed to, uint256 amount);

    /**
     * @notice Emitted when global daily limit is updated
     * @param oldLimit Previous global daily limit
     * @param newLimit New global daily limit
     */
    event GlobalDailyLimitUpdated(uint256 oldLimit, uint256 newLimit);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Account is not sponsored
    error NotSponsored(address account);

    /// @notice Sponsorship limit exceeded
    error SponsorshipLimitExceeded(address account, uint256 requested, uint256 remaining);

    /// @notice Daily sponsorship limit exceeded
    error DailyLimitExceeded(address account, uint256 requested, uint256 remaining);

    /// @notice Global daily limit exceeded
    error GlobalDailyLimitExceeded(uint256 requested, uint256 remaining);

    /// @notice Insufficient deposit in EntryPoint
    error InsufficientDeposit(uint256 required, uint256 available);

    /// @notice Invalid caller (not EntryPoint)
    error OnlyEntryPoint();

    /// @notice Invalid caller (not owner)
    error OnlyOwner();

    /// @notice Invalid address (zero address)
    error ZeroAddress();

    /// @notice Account already sponsored
    error AlreadySponsored(address account);

    /*//////////////////////////////////////////////////////////////
                          SPONSORSHIP MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add an account to the sponsorship list
     * @param account The account to sponsor
     * @param limit Maximum total sponsorship (0 = unlimited)
     * @param dailyLimit Maximum daily sponsorship (0 = unlimited)
     */
    function sponsorAccount(address account, uint256 limit, uint256 dailyLimit) external;

    /**
     * @notice Add multiple accounts to the sponsorship list
     * @param accounts Array of accounts to sponsor
     * @param limits Array of total limits (0 = unlimited)
     * @param dailyLimits Array of daily limits (0 = unlimited)
     */
    function sponsorAccountBatch(
        address[] calldata accounts,
        uint256[] calldata limits,
        uint256[] calldata dailyLimits
    ) external;

    /**
     * @notice Revoke sponsorship for an account
     * @param account The account to remove from sponsorship
     */
    function revokeSponsorshipFor(address account) external;

    /**
     * @notice Update sponsorship limits for an account
     * @param account The account to update
     * @param newLimit New total limit
     * @param newDailyLimit New daily limit
     */
    function updateSponsorshipLimits(address account, uint256 newLimit, uint256 newDailyLimit) external;

    /**
     * @notice Set the global daily sponsorship limit
     * @param newLimit New global daily limit (0 = unlimited)
     */
    function setGlobalDailyLimit(uint256 newLimit) external;

    /*//////////////////////////////////////////////////////////////
                              GETTERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if an account is sponsored
     * @param account The account to check
     * @return True if the account is actively sponsored
     */
    function isSponsored(address account) external view returns (bool);

    /**
     * @notice Get sponsorship configuration for an account
     * @param account The account to query
     * @return config The sponsorship configuration
     */
    function getSponsorshipConfig(address account) external view returns (SponsorshipConfig memory config);

    /**
     * @notice Get remaining sponsorship for an account
     * @param account The account to query
     * @return totalRemaining Remaining total sponsorship
     * @return dailyRemaining Remaining daily sponsorship
     */
    function getRemainingSponsorship(address account)
        external
        view
        returns (uint256 totalRemaining, uint256 dailyRemaining);

    /**
     * @notice Get the global daily sponsorship stats
     * @return limit Global daily limit
     * @return spent Amount spent today
     * @return remaining Amount remaining today
     */
    function getGlobalDailyStats() external view returns (uint256 limit, uint256 spent, uint256 remaining);

    /**
     * @notice Get the EntryPoint contract
     * @return The EntryPoint address
     */
    function entryPoint() external view returns (IEntryPoint);

    /**
     * @notice Get the paymaster's deposit in EntryPoint
     * @return The current deposit balance
     */
    function getDeposit() external view returns (uint256);

    /*//////////////////////////////////////////////////////////////
                          FUNDING FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deposit funds to EntryPoint for gas sponsorship
     */
    function deposit() external payable;

    /**
     * @notice Withdraw funds from EntryPoint
     * @param to Recipient address
     * @param amount Amount to withdraw
     */
    function withdrawTo(address payable to, uint256 amount) external;

    /**
     * @notice Add stake to EntryPoint (required for paymaster operation)
     * @param unstakeDelaySec Delay before stake can be withdrawn
     */
    function addStake(uint32 unstakeDelaySec) external payable;

    /**
     * @notice Unlock stake from EntryPoint
     */
    function unlockStake() external;

    /**
     * @notice Withdraw unlocked stake from EntryPoint
     * @param to Recipient address
     */
    function withdrawStake(address payable to) external;

    /*//////////////////////////////////////////////////////////////
                         ERC-4337 PAYMASTER
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validate a paymaster UserOperation
     * @dev Called by EntryPoint to verify the paymaster is willing to sponsor
     * @param userOp The user operation to validate
     * @param userOpHash Hash of the user operation
     * @param maxCost Maximum cost the paymaster would pay
     * @return context Context for postOp (account address, max cost)
     * @return validationData 0 for success, 1 for failure
     */
    function validatePaymasterUserOp(
        IEntryPoint.PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData);

    /**
     * @notice Post-operation handler
     * @dev Called by EntryPoint after UserOperation execution
     * @param mode PostOp mode (success, revert, postOp revert)
     * @param context Context from validatePaymasterUserOp
     * @param actualGasCost Actual gas cost of the operation
     * @param actualUserOpFeePerGas Actual fee per gas used
     */
    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    ) external;
}
