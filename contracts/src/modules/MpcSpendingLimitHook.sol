// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ISpendingLimitHook } from "../interfaces/ISpendingLimitHook.sol";
import { IERC7579Module } from "../interfaces/IERC7579Module.sol";

/**
 * @title MpcSpendingLimitHook
 * @author MPC Agent Wallet SDK
 * @notice Spending limit enforcement module for MPC smart accounts
 * @dev Implements IERC7579Module (Type 4: Hook) for ERC-7579 compatibility
 *
 * @dev Key features:
 *      - Per-transaction ETH limits
 *      - Daily and weekly spending limits
 *      - Per-token ERC-20 limits
 *      - Address whitelist enforcement
 *      - Automatic period resets
 *
 * Use Cases for AI Agents:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                     AI AGENT SPENDING CONTROLS                               │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │   Autonomous Trading Bot                                                    │
 * │   ├─ Per-trade limit: 0.1 ETH                                               │
 * │   ├─ Daily limit: 1 ETH                                                     │
 * │   └─ Whitelist: DEX routers only                                            │
 * │                                                                             │
 * │   DeFi Yield Optimizer                                                      │
 * │   ├─ Per-tx limit: 10 ETH                                                   │
 * │   ├─ Weekly limit: 50 ETH                                                   │
 * │   ├─ Token limits: 10,000 USDC/day                                          │
 * │   └─ Whitelist: Approved protocols                                          │
 * │                                                                             │
 * │   NFT Bidding Agent                                                         │
 * │   ├─ Per-bid limit: 0.5 ETH                                                 │
 * │   ├─ Daily limit: 2 ETH                                                     │
 * │   └─ Whitelist: NFT marketplaces only                                       │
 * │                                                                             │
 * │   Payment Processing                                                        │
 * │   ├─ Per-payment: 100 USDC                                                  │
 * │   ├─ Daily limit: 1,000 USDC                                                │
 * │   └─ Weekly limit: 5,000 USDC                                               │
 * │                                                                             │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * Integration:
 * This hook is called before and after each transaction execution.
 * It validates spending against configured limits in preHook and
 * records actual spending in postHook.
 */
contract MpcSpendingLimitHook is ISpendingLimitHook, IERC7579Module {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC-7579 Hook module type ID
    uint256 public constant MODULE_TYPE = 4;

    /// @notice Time period for daily limits
    uint256 public constant DAILY_PERIOD = 1 days;

    /// @notice Time period for weekly limits
    uint256 public constant WEEKLY_PERIOD = 7 days;

    /// @notice ERC-20 transfer function selector
    bytes4 public constant TRANSFER_SELECTOR = bytes4(keccak256("transfer(address,uint256)"));

    /// @notice ERC-20 transferFrom function selector
    bytes4 public constant TRANSFER_FROM_SELECTOR = bytes4(keccak256("transferFrom(address,address,uint256)"));

    /// @notice ERC-20 approve function selector
    bytes4 public constant APPROVE_SELECTOR = bytes4(keccak256("approve(address,uint256)"));

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Spending configuration per account
    mapping(address => SpendingConfig) internal _configs;

    /// @notice Spending tracker per account
    mapping(address => SpendingTracker) internal _trackers;

    /// @notice Token limits per account per token
    mapping(address => mapping(address => TokenLimit)) internal _tokenLimits;

    /// @notice Whitelist per account (account => target => allowed)
    mapping(address => mapping(address => bool)) internal _whitelists;

    /// @notice Tracks which accounts have initialized this module (ERC-7579)
    mapping(address => bool) internal _initialized;

    /*//////////////////////////////////////////////////////////////
                       ERC-7579 MODULE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IERC7579Module
     * @dev Initializes spending limits for the calling account
     *      Data format: abi.encode(txLimit, dailyLimit, weeklyLimit, whitelistOnly)
     */
    function onInstall(bytes calldata data) external override {
        address account = msg.sender;

        if (_initialized[account]) {
            revert AlreadyInitialized(account);
        }

        _initialized[account] = true;

        // Decode and apply initial configuration if provided
        if (data.length > 0) {
            (uint256 txLimit, uint256 dailyLimit, uint256 weeklyLimit, bool whitelistOnly) =
                abi.decode(data, (uint256, uint256, uint256, bool));

            // Validate limits
            if (dailyLimit > 0 && weeklyLimit > 0 && weeklyLimit < dailyLimit) {
                revert InvalidLimit();
            }

            _configs[account] = SpendingConfig({
                txLimit: txLimit,
                dailyLimit: dailyLimit,
                weeklyLimit: weeklyLimit,
                whitelistOnly: whitelistOnly,
                enabled: true
            });

            _trackers[account] = SpendingTracker({
                dailySpent: 0,
                weeklySpent: 0,
                dailyResetTime: block.timestamp + DAILY_PERIOD,
                weeklyResetTime: block.timestamp + WEEKLY_PERIOD
            });

            emit SpendingConfigured(account, txLimit, dailyLimit, weeklyLimit, whitelistOnly);
        }

        emit ModuleInstalled(account);
    }

    /**
     * @inheritdoc IERC7579Module
     * @dev Cleans up spending configuration for the calling account
     */
    function onUninstall(bytes calldata /* data */) external override {
        address account = msg.sender;

        if (!_initialized[account]) {
            revert NotInitialized(account);
        }

        // Clean up all state for this account
        delete _configs[account];
        delete _trackers[account];
        _initialized[account] = false;

        emit ModuleUninstalled(account);
    }

    /**
     * @inheritdoc IERC7579Module
     * @dev This is a Hook module (Type 4)
     */
    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE;
    }

    /**
     * @inheritdoc IERC7579Module
     */
    function isInitialized(address account) external view override returns (bool) {
        return _initialized[account];
    }

    /*//////////////////////////////////////////////////////////////
                          CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc ISpendingLimitHook
     */
    function configureSpending(uint256 txLimit, uint256 dailyLimit, uint256 weeklyLimit, bool whitelistOnly) external {
        // Validate limits
        if (dailyLimit > 0 && weeklyLimit > 0 && weeklyLimit < dailyLimit) {
            revert InvalidLimit();
        }

        address account = msg.sender;

        _configs[account] = SpendingConfig({
            txLimit: txLimit,
            dailyLimit: dailyLimit,
            weeklyLimit: weeklyLimit,
            whitelistOnly: whitelistOnly,
            enabled: true
        });

        // Initialize tracker with current periods
        _trackers[account] = SpendingTracker({
            dailySpent: 0,
            weeklySpent: 0,
            dailyResetTime: block.timestamp + DAILY_PERIOD,
            weeklyResetTime: block.timestamp + WEEKLY_PERIOD
        });

        emit SpendingConfigured(account, txLimit, dailyLimit, weeklyLimit, whitelistOnly);
    }

    /**
     * @inheritdoc ISpendingLimitHook
     */
    function configureTokenLimit(address token, uint256 dailyLimit) external {
        address account = msg.sender;

        _tokenLimits[account][token] = TokenLimit({
            dailyLimit: dailyLimit,
            spent: 0,
            resetTime: block.timestamp + DAILY_PERIOD,
            enabled: dailyLimit > 0
        });

        emit TokenLimitConfigured(account, token, dailyLimit);
    }

    /**
     * @inheritdoc ISpendingLimitHook
     */
    function setWhitelist(address target, bool allowed) external {
        address account = msg.sender;
        _whitelists[account][target] = allowed;
        emit WhitelistUpdated(account, target, allowed);
    }

    /**
     * @inheritdoc ISpendingLimitHook
     */
    function setWhitelistBatch(address[] calldata targets, bool[] calldata allowed) external {
        require(targets.length == allowed.length, "Array length mismatch");

        address account = msg.sender;

        for (uint256 i = 0; i < targets.length; i++) {
            _whitelists[account][targets[i]] = allowed[i];
            emit WhitelistUpdated(account, targets[i], allowed[i]);
        }
    }

    /**
     * @inheritdoc ISpendingLimitHook
     */
    function setLimitsEnabled(
        bool enabled
    ) external {
        _configs[msg.sender].enabled = enabled;
        emit LimitsEnabled(msg.sender, enabled);
    }

    /*//////////////////////////////////////////////////////////////
                           HOOK FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Pre-execution hook - validates spending limits
     * @dev Called by MpcSmartAccount before executing a transaction
     * @param target Call target address
     * @param value ETH value being sent
     * @param data Call data
     * @return hookData Encoded data for postHook
     */
    function preHook(address target, uint256 value, bytes calldata data) external returns (bytes memory hookData) {
        address account = msg.sender;
        SpendingConfig storage config = _configs[account];

        if (!config.enabled) {
            return "";
        }

        // Reset periods if needed
        _resetPeriodsIfNeeded(account);

        SpendingTracker storage tracker = _trackers[account];

        // Check whitelist
        if (config.whitelistOnly && !_whitelists[account][target]) {
            revert TargetNotWhitelisted(target);
        }

        // Check ETH spending limits
        if (value > 0) {
            // Per-transaction limit
            if (config.txLimit > 0 && value > config.txLimit) {
                revert TransactionLimitExceeded(value, config.txLimit);
            }

            // Daily limit
            if (config.dailyLimit > 0) {
                uint256 newDailyTotal = tracker.dailySpent + value;
                if (newDailyTotal > config.dailyLimit) {
                    revert DailyLimitExceeded(newDailyTotal, config.dailyLimit);
                }
            }

            // Weekly limit
            if (config.weeklyLimit > 0) {
                uint256 newWeeklyTotal = tracker.weeklySpent + value;
                if (newWeeklyTotal > config.weeklyLimit) {
                    revert WeeklyLimitExceeded(newWeeklyTotal, config.weeklyLimit);
                }
            }
        }

        // Check ERC-20 token limits
        if (data.length >= 4) {
            bytes4 selector = bytes4(data[:4]);

            if (selector == TRANSFER_SELECTOR && data.length >= 68) {
                // transfer(address,uint256)
                uint256 amount = abi.decode(data[36:68], (uint256));
                _checkTokenLimit(account, target, amount);
            } else if (selector == TRANSFER_FROM_SELECTOR && data.length >= 100) {
                // transferFrom(address,address,uint256)
                uint256 amount = abi.decode(data[68:100], (uint256));
                _checkTokenLimit(account, target, amount);
            } else if (selector == APPROVE_SELECTOR && data.length >= 68) {
                // approve(address,uint256) - check approval amounts
                uint256 amount = abi.decode(data[36:68], (uint256));
                _checkTokenLimit(account, target, amount);
            }
        }

        // Encode data for postHook
        return abi.encode(
            value,
            target,
            data.length >= 4 ? bytes4(data[:4]) : bytes4(0),
            data.length >= 68 ? _extractAmount(data) : uint256(0)
        );
    }

    /**
     * @notice Post-execution hook - records spending
     * @dev Called by MpcSmartAccount after executing a transaction
     * @param hookData Data from preHook
     * @param success Whether execution succeeded
     */
    function postHook(bytes calldata hookData, bool success, bytes calldata /* returnData */ ) external {
        if (!success) return;

        address account = msg.sender;
        SpendingConfig storage config = _configs[account];

        if (!config.enabled) return;
        if (hookData.length == 0) return;

        (uint256 value, address target, bytes4 selector, uint256 tokenAmount) =
            abi.decode(hookData, (uint256, address, bytes4, uint256));

        // Record ETH spending
        if (value > 0) {
            SpendingTracker storage tracker = _trackers[account];
            tracker.dailySpent += value;
            tracker.weeklySpent += value;

            emit SpendingRecorded(account, value, tracker.dailySpent, tracker.weeklySpent);
        }

        // Record token spending
        if ((selector == TRANSFER_SELECTOR || selector == TRANSFER_FROM_SELECTOR) && tokenAmount > 0) {
            TokenLimit storage tokenLimit = _tokenLimits[account][target];
            if (tokenLimit.enabled) {
                tokenLimit.spent += tokenAmount;
                emit TokenSpendingRecorded(account, target, tokenAmount, tokenLimit.spent);
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                           GETTER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc ISpendingLimitHook
     */
    function getConfig(
        address account
    ) external view returns (SpendingConfig memory) {
        return _configs[account];
    }

    /**
     * @inheritdoc ISpendingLimitHook
     */
    function getSpending(
        address account
    )
        external
        view
        returns (uint256 dailySpent, uint256 weeklySpent, uint256 dailyRemaining, uint256 weeklyRemaining)
    {
        SpendingConfig storage config = _configs[account];
        SpendingTracker storage tracker = _trackers[account];

        // Check if periods need reset
        if (block.timestamp >= tracker.dailyResetTime) {
            dailySpent = 0;
        } else {
            dailySpent = tracker.dailySpent;
        }

        if (block.timestamp >= tracker.weeklyResetTime) {
            weeklySpent = 0;
        } else {
            weeklySpent = tracker.weeklySpent;
        }

        dailyRemaining = config.dailyLimit > dailySpent ? config.dailyLimit - dailySpent : 0;
        weeklyRemaining = config.weeklyLimit > weeklySpent ? config.weeklyLimit - weeklySpent : 0;

        // If no limit set, return max
        if (config.dailyLimit == 0) dailyRemaining = type(uint256).max;
        if (config.weeklyLimit == 0) weeklyRemaining = type(uint256).max;
    }

    /**
     * @inheritdoc ISpendingLimitHook
     */
    function getTokenSpending(
        address account,
        address token
    ) external view returns (uint256 spent, uint256 remaining, uint256 resetTime) {
        TokenLimit storage limit = _tokenLimits[account][token];

        // Check if period needs reset
        if (block.timestamp >= limit.resetTime) {
            spent = 0;
            resetTime = block.timestamp + DAILY_PERIOD;
        } else {
            spent = limit.spent;
            resetTime = limit.resetTime;
        }

        remaining = limit.dailyLimit > spent ? limit.dailyLimit - spent : 0;

        if (!limit.enabled) {
            remaining = type(uint256).max;
        }
    }

    /**
     * @inheritdoc ISpendingLimitHook
     */
    function isWhitelisted(address account, address target) external view returns (bool) {
        return _whitelists[account][target];
    }

    /**
     * @notice Get tracker state
     * @param account The account
     * @return The spending tracker
     */
    function getTracker(
        address account
    ) external view returns (SpendingTracker memory) {
        return _trackers[account];
    }

    /**
     * @notice Get token limit configuration
     * @param account The account
     * @param token The token address
     * @return The token limit config
     */
    function getTokenLimit(address account, address token) external view returns (TokenLimit memory) {
        return _tokenLimits[account][token];
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Reset spending periods if they have expired
     */
    function _resetPeriodsIfNeeded(
        address account
    ) internal {
        SpendingTracker storage tracker = _trackers[account];

        if (block.timestamp >= tracker.dailyResetTime) {
            tracker.dailySpent = 0;
            tracker.dailyResetTime = block.timestamp + DAILY_PERIOD;
        }

        if (block.timestamp >= tracker.weeklyResetTime) {
            tracker.weeklySpent = 0;
            tracker.weeklyResetTime = block.timestamp + WEEKLY_PERIOD;
        }
    }

    /**
     * @notice Check token limit and revert if exceeded
     */
    function _checkTokenLimit(address account, address token, uint256 amount) internal {
        TokenLimit storage limit = _tokenLimits[account][token];

        if (!limit.enabled) return;

        // Reset if period expired
        if (block.timestamp >= limit.resetTime) {
            limit.spent = 0;
            limit.resetTime = block.timestamp + DAILY_PERIOD;
        }

        uint256 newTotal = limit.spent + amount;
        if (newTotal > limit.dailyLimit) {
            revert TokenDailyLimitExceeded(token, newTotal, limit.dailyLimit);
        }
    }

    /**
     * @notice Extract amount from transfer/approve calldata
     */
    function _extractAmount(
        bytes calldata data
    ) internal pure returns (uint256) {
        bytes4 selector = bytes4(data[:4]);

        if (selector == TRANSFER_SELECTOR && data.length >= 68) {
            return abi.decode(data[36:68], (uint256));
        } else if (selector == TRANSFER_FROM_SELECTOR && data.length >= 100) {
            return abi.decode(data[68:100], (uint256));
        } else if (selector == APPROVE_SELECTOR && data.length >= 68) {
            return abi.decode(data[36:68], (uint256));
        }

        return 0;
    }
}
