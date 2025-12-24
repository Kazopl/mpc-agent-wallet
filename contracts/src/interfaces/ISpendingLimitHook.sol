// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ISpendingLimitHook
 * @notice Interface for spending limit enforcement hook
 * @dev Enforces spending policies before and after transaction execution
 *
 * Features:
 * - Per-transaction ETH limits
 * - Daily/weekly spending limits
 * - Per-token ERC-20 limits
 * - Address whitelisting
 * - Automatic limit refresh
 */
interface ISpendingLimitHook {
    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Spending configuration
     * @param txLimit Maximum ETH per transaction (0 = no limit)
     * @param dailyLimit Maximum ETH per day (0 = no limit)
     * @param weeklyLimit Maximum ETH per week (0 = no limit)
     * @param whitelistOnly If true, only whitelisted targets allowed
     * @param enabled Whether limits are active
     */
    struct SpendingConfig {
        uint256 txLimit;
        uint256 dailyLimit;
        uint256 weeklyLimit;
        bool whitelistOnly;
        bool enabled;
    }

    /**
     * @notice Spending tracker state
     * @param dailySpent Amount spent in current day
     * @param weeklySpent Amount spent in current week
     * @param dailyResetTime When daily limit resets
     * @param weeklyResetTime When weekly limit resets
     */
    struct SpendingTracker {
        uint256 dailySpent;
        uint256 weeklySpent;
        uint256 dailyResetTime;
        uint256 weeklyResetTime;
    }

    /**
     * @notice Token-specific spending limit
     * @param dailyLimit Maximum tokens per day
     * @param spent Amount spent in current period
     * @param resetTime When limit resets
     * @param enabled Whether limit is active
     */
    struct TokenLimit {
        uint256 dailyLimit;
        uint256 spent;
        uint256 resetTime;
        bool enabled;
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event SpendingConfigured(
        address indexed account, uint256 txLimit, uint256 dailyLimit, uint256 weeklyLimit, bool whitelistOnly
    );

    event TokenLimitConfigured(address indexed account, address indexed token, uint256 dailyLimit);

    event SpendingRecorded(address indexed account, uint256 amount, uint256 dailyTotal, uint256 weeklyTotal);

    event TokenSpendingRecorded(address indexed account, address indexed token, uint256 amount, uint256 dailyTotal);

    event WhitelistUpdated(address indexed account, address indexed target, bool allowed);

    event LimitsEnabled(address indexed account, bool enabled);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error TransactionLimitExceeded(uint256 amount, uint256 limit);
    error DailyLimitExceeded(uint256 total, uint256 limit);
    error WeeklyLimitExceeded(uint256 total, uint256 limit);
    error TokenDailyLimitExceeded(address token, uint256 total, uint256 limit);
    error TargetNotWhitelisted(address target);
    error InvalidLimit();
    error LimitsDisabled();

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure spending limits
     * @param txLimit Max per transaction
     * @param dailyLimit Max per day
     * @param weeklyLimit Max per week
     * @param whitelistOnly Require whitelisted targets
     */
    function configureSpending(uint256 txLimit, uint256 dailyLimit, uint256 weeklyLimit, bool whitelistOnly) external;

    /**
     * @notice Configure token-specific limit
     * @param token Token address
     * @param dailyLimit Max tokens per day
     */
    function configureTokenLimit(address token, uint256 dailyLimit) external;

    /**
     * @notice Update whitelist
     * @param target Address to update
     * @param allowed Whether to whitelist
     */
    function setWhitelist(address target, bool allowed) external;

    /**
     * @notice Batch whitelist update
     * @param targets Addresses to update
     * @param allowed Whitelist status for each
     */
    function setWhitelistBatch(address[] calldata targets, bool[] calldata allowed) external;

    /**
     * @notice Enable or disable limits
     * @param enabled Whether limits should be active
     */
    function setLimitsEnabled(
        bool enabled
    ) external;

    /*//////////////////////////////////////////////////////////////
                           GETTER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get spending config for an account
     * @param account The account
     * @return The spending configuration
     */
    function getConfig(
        address account
    ) external view returns (SpendingConfig memory);

    /**
     * @notice Get current spending totals
     * @param account The account
     * @return dailySpent Amount spent today
     * @return weeklySpent Amount spent this week
     * @return dailyRemaining Remaining daily allowance
     * @return weeklyRemaining Remaining weekly allowance
     */
    function getSpending(
        address account
    )
        external
        view
        returns (uint256 dailySpent, uint256 weeklySpent, uint256 dailyRemaining, uint256 weeklyRemaining);

    /**
     * @notice Get token spending info
     * @param account The account
     * @param token The token address
     * @return spent Amount spent in current period
     * @return remaining Amount remaining
     * @return resetTime When limit resets
     */
    function getTokenSpending(
        address account,
        address token
    ) external view returns (uint256 spent, uint256 remaining, uint256 resetTime);

    /**
     * @notice Check if target is whitelisted
     * @param account The account
     * @param target The target address
     * @return True if whitelisted
     */
    function isWhitelisted(address account, address target) external view returns (bool);
}
