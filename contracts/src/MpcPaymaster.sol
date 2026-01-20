// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IMpcPaymaster } from "./interfaces/IMpcPaymaster.sol";
import { IEntryPoint } from "./interfaces/IEntryPoint.sol";

/**
 * @title MpcPaymaster
 * @author MPC Agent Wallet SDK
 * @notice ERC-4337 Paymaster for sponsoring gas costs of MPC smart accounts
 *
 * @dev Enables gasless transactions for AI agent wallets by sponsoring gas costs.
 *      Features include:
 *      - Account-based sponsorship with configurable limits
 *      - Daily spending caps per account and globally
 *      - Owner-managed whitelist of sponsored accounts
 *      - Automatic period reset for daily limits
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                         PAYMASTER ARCHITECTURE                               │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  User Operation Flow:                                                       │
 * │                                                                             │
 * │  ┌─────────┐    ┌────────────┐    ┌──────────────┐    ┌─────────────┐      │
 * │  │  User   │───▶│  Bundler   │───▶│  EntryPoint  │───▶│  Paymaster  │      │
 * │  │ (Agent) │    │            │    │              │    │             │      │
 * │  └─────────┘    └────────────┘    └──────┬───────┘    └──────┬──────┘      │
 * │                                          │                    │             │
 * │                                          │ validatePaymaster  │             │
 * │                                          │◀───────────────────┘             │
 * │                                          │                                  │
 * │                                          │ postOp (record actual gas)       │
 * │                                          │───────────────────▶              │
 * │                                          │                                  │
 * │                                                                             │
 * │  Sponsorship Model:                                                         │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │  Account A: limit=10 ETH, dailyLimit=1 ETH, spent=2.5 ETH          │   │
 * │  │  Account B: limit=0 (unlimited), dailyLimit=0.5 ETH                │   │
 * │  │  Account C: limit=5 ETH, dailyLimit=0 (unlimited)                  │   │
 * │  └─────────────────────────────────────────────────────────────────────┘   │
 * │                                                                             │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * Security Considerations:
 * - Only the owner can add/remove sponsored accounts
 * - Sponsorship limits prevent drain attacks
 * - Daily limits provide additional protection
 * - EntryPoint stake ensures paymaster commitment
 */
contract MpcPaymaster is IMpcPaymaster {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Time period for daily limit reset (24 hours)
    uint256 public constant DAILY_PERIOD = 1 days;

    /// @notice Validation success constant (ERC-4337)
    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;

    /// @notice Validation failure constant (ERC-4337)
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    /*//////////////////////////////////////////////////////////////
                            IMMUTABLE STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice The EntryPoint contract
    IEntryPoint internal immutable _entryPoint;

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Contract owner
    address public owner;

    /// @notice Sponsorship configuration per account
    mapping(address => SponsorshipConfig) internal _sponsorships;

    /// @notice Global daily sponsorship limit (0 = unlimited)
    uint256 public globalDailyLimit;

    /// @notice Global daily amount spent
    uint256 public globalDailySpent;

    /// @notice Global daily reset timestamp
    uint256 public globalDailyResetTime;

    /*//////////////////////////////////////////////////////////////
                              MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Restrict to EntryPoint calls
     */
    modifier onlyEntryPoint() {
        if (msg.sender != address(_entryPoint)) {
            revert OnlyEntryPoint();
        }
        _;
    }

    /**
     * @notice Restrict to owner calls
     */
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert OnlyOwner();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new MpcPaymaster
     * @param anEntryPoint The ERC-4337 EntryPoint contract
     * @param _owner Initial owner address
     * @param _globalDailyLimit Initial global daily limit (0 = unlimited)
     */
    constructor(IEntryPoint anEntryPoint, address _owner, uint256 _globalDailyLimit) {
        if (address(anEntryPoint) == address(0)) {
            revert ZeroAddress();
        }
        if (_owner == address(0)) {
            revert ZeroAddress();
        }

        _entryPoint = anEntryPoint;
        owner = _owner;
        globalDailyLimit = _globalDailyLimit;
        globalDailyResetTime = block.timestamp + DAILY_PERIOD;
    }

    /*//////////////////////////////////////////////////////////////
                      SPONSORSHIP MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IMpcPaymaster
     */
    function sponsorAccount(address account, uint256 limit, uint256 dailyLimit) external onlyOwner {
        if (account == address(0)) {
            revert ZeroAddress();
        }
        if (_sponsorships[account].active) {
            revert AlreadySponsored(account);
        }

        _sponsorships[account] = SponsorshipConfig({
            active: true,
            limit: limit,
            spent: 0,
            dailyLimit: dailyLimit,
            dailySpent: 0,
            dailyResetTime: block.timestamp + DAILY_PERIOD
        });

        emit AccountSponsored(account, limit, dailyLimit);
    }

    /**
     * @inheritdoc IMpcPaymaster
     */
    function sponsorAccountBatch(
        address[] calldata accounts,
        uint256[] calldata limits,
        uint256[] calldata dailyLimits
    ) external onlyOwner {
        require(accounts.length == limits.length && limits.length == dailyLimits.length, "Array length mismatch");

        for (uint256 i = 0; i < accounts.length; i++) {
            address account = accounts[i];

            if (account == address(0)) {
                revert ZeroAddress();
            }
            if (_sponsorships[account].active) {
                revert AlreadySponsored(account);
            }

            _sponsorships[account] = SponsorshipConfig({
                active: true,
                limit: limits[i],
                spent: 0,
                dailyLimit: dailyLimits[i],
                dailySpent: 0,
                dailyResetTime: block.timestamp + DAILY_PERIOD
            });

            emit AccountSponsored(account, limits[i], dailyLimits[i]);
        }
    }

    /**
     * @inheritdoc IMpcPaymaster
     */
    function revokeSponsorshipFor(address account) external onlyOwner {
        if (!_sponsorships[account].active) {
            revert NotSponsored(account);
        }

        _sponsorships[account].active = false;

        emit SponsorshipRevoked(account);
    }

    /**
     * @inheritdoc IMpcPaymaster
     */
    function updateSponsorshipLimits(address account, uint256 newLimit, uint256 newDailyLimit) external onlyOwner {
        if (!_sponsorships[account].active) {
            revert NotSponsored(account);
        }

        _sponsorships[account].limit = newLimit;
        _sponsorships[account].dailyLimit = newDailyLimit;

        emit SponsorshipUpdated(account, newLimit, newDailyLimit);
    }

    /**
     * @inheritdoc IMpcPaymaster
     */
    function setGlobalDailyLimit(uint256 newLimit) external onlyOwner {
        uint256 oldLimit = globalDailyLimit;
        globalDailyLimit = newLimit;

        emit GlobalDailyLimitUpdated(oldLimit, newLimit);
    }

    /**
     * @notice Transfer ownership to a new owner
     * @param newOwner The new owner address
     */
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) {
            revert ZeroAddress();
        }
        owner = newOwner;
    }

    /*//////////////////////////////////////////////////////////////
                              GETTERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IMpcPaymaster
     */
    function isSponsored(address account) external view returns (bool) {
        return _sponsorships[account].active;
    }

    /**
     * @inheritdoc IMpcPaymaster
     */
    function getSponsorshipConfig(address account) external view returns (SponsorshipConfig memory config) {
        return _sponsorships[account];
    }

    /**
     * @inheritdoc IMpcPaymaster
     */
    function getRemainingSponsorship(address account)
        external
        view
        returns (uint256 totalRemaining, uint256 dailyRemaining)
    {
        SponsorshipConfig storage config = _sponsorships[account];

        if (!config.active) {
            return (0, 0);
        }

        // Calculate total remaining
        if (config.limit == 0) {
            totalRemaining = type(uint256).max; // Unlimited
        } else {
            totalRemaining = config.limit > config.spent ? config.limit - config.spent : 0;
        }

        // Calculate daily remaining (accounting for period reset)
        uint256 dailySpent = block.timestamp >= config.dailyResetTime ? 0 : config.dailySpent;

        if (config.dailyLimit == 0) {
            dailyRemaining = type(uint256).max; // Unlimited
        } else {
            dailyRemaining = config.dailyLimit > dailySpent ? config.dailyLimit - dailySpent : 0;
        }
    }

    /**
     * @inheritdoc IMpcPaymaster
     */
    function getGlobalDailyStats() external view returns (uint256 limit, uint256 spent, uint256 remaining) {
        limit = globalDailyLimit;

        // Account for period reset
        if (block.timestamp >= globalDailyResetTime) {
            spent = 0;
        } else {
            spent = globalDailySpent;
        }

        if (limit == 0) {
            remaining = type(uint256).max;
        } else {
            remaining = limit > spent ? limit - spent : 0;
        }
    }

    /**
     * @inheritdoc IMpcPaymaster
     */
    function entryPoint() external view returns (IEntryPoint) {
        return _entryPoint;
    }

    /**
     * @inheritdoc IMpcPaymaster
     */
    function getDeposit() public view returns (uint256) {
        return _entryPoint.balanceOf(address(this));
    }

    /*//////////////////////////////////////////////////////////////
                          FUNDING FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IMpcPaymaster
     */
    function deposit() external payable {
        _entryPoint.depositTo{ value: msg.value }(address(this));
        emit PaymasterFunded(msg.sender, msg.value);
    }

    /**
     * @inheritdoc IMpcPaymaster
     */
    function withdrawTo(address payable to, uint256 amount) external onlyOwner {
        if (to == address(0)) {
            revert ZeroAddress();
        }
        _entryPoint.withdrawTo(to, amount);
        emit FundsWithdrawn(to, amount);
    }

    /**
     * @inheritdoc IMpcPaymaster
     */
    function addStake(uint32 unstakeDelaySec) external payable onlyOwner {
        // Note: This calls a function not in our minimal IEntryPoint interface
        // In production, you'd need to extend the interface or use a low-level call
        (bool success,) = address(_entryPoint).call{ value: msg.value }(
            abi.encodeWithSignature("addStake(uint32)", unstakeDelaySec)
        );
        require(success, "addStake failed");
    }

    /**
     * @inheritdoc IMpcPaymaster
     */
    function unlockStake() external onlyOwner {
        (bool success,) = address(_entryPoint).call(abi.encodeWithSignature("unlockStake()"));
        require(success, "unlockStake failed");
    }

    /**
     * @inheritdoc IMpcPaymaster
     */
    function withdrawStake(address payable to) external onlyOwner {
        if (to == address(0)) {
            revert ZeroAddress();
        }
        (bool success,) = address(_entryPoint).call(abi.encodeWithSignature("withdrawStake(address)", to));
        require(success, "withdrawStake failed");
    }

    /*//////////////////////////////////////////////////////////////
                         ERC-4337 PAYMASTER
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IMpcPaymaster
     * @dev Validates that:
     *      1. Account is in the sponsored list
     *      2. Account hasn't exceeded their total limit
     *      3. Account hasn't exceeded their daily limit
     *      4. Global daily limit isn't exceeded
     *      5. Paymaster has sufficient deposit
     */
    function validatePaymasterUserOp(
        IEntryPoint.PackedUserOperation calldata userOp,
        bytes32, /* userOpHash */
        uint256 maxCost
    ) external onlyEntryPoint returns (bytes memory context, uint256 validationData) {
        address account = userOp.sender;

        // Check if account is sponsored
        SponsorshipConfig storage config = _sponsorships[account];
        if (!config.active) {
            revert NotSponsored(account);
        }

        // Reset daily periods if needed
        _resetDailyIfNeeded(config);
        _resetGlobalDailyIfNeeded();

        // Check total sponsorship limit
        if (config.limit > 0) {
            uint256 totalRemaining = config.limit > config.spent ? config.limit - config.spent : 0;
            if (maxCost > totalRemaining) {
                revert SponsorshipLimitExceeded(account, maxCost, totalRemaining);
            }
        }

        // Check daily sponsorship limit
        if (config.dailyLimit > 0) {
            uint256 dailyRemaining = config.dailyLimit > config.dailySpent ? config.dailyLimit - config.dailySpent : 0;
            if (maxCost > dailyRemaining) {
                revert DailyLimitExceeded(account, maxCost, dailyRemaining);
            }
        }

        // Check global daily limit
        if (globalDailyLimit > 0) {
            uint256 globalRemaining =
                globalDailyLimit > globalDailySpent ? globalDailyLimit - globalDailySpent : 0;
            if (maxCost > globalRemaining) {
                revert GlobalDailyLimitExceeded(maxCost, globalRemaining);
            }
        }

        // Check paymaster deposit
        uint256 currentDeposit = getDeposit();
        if (currentDeposit < maxCost) {
            revert InsufficientDeposit(maxCost, currentDeposit);
        }

        // Return context for postOp
        context = abi.encode(account, maxCost);
        validationData = SIG_VALIDATION_SUCCESS;
    }

    /**
     * @inheritdoc IMpcPaymaster
     * @dev Records the actual gas cost against the account's sponsorship
     */
    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 /* actualUserOpFeePerGas */
    ) external onlyEntryPoint {
        // Only record spending if operation succeeded or reverted (not if postOp itself reverted)
        if (mode == PostOpMode.PostOpReverted) {
            return;
        }

        (address account,) = abi.decode(context, (address, uint256));

        SponsorshipConfig storage config = _sponsorships[account];

        // Reset daily if needed (shouldn't be necessary but safe)
        _resetDailyIfNeeded(config);
        _resetGlobalDailyIfNeeded();

        // Record spending
        config.spent += actualGasCost;
        config.dailySpent += actualGasCost;
        globalDailySpent += actualGasCost;

        emit GasSponsored(account, actualGasCost, config.spent);
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Reset daily spending if period has expired
     * @param config The sponsorship config to check/reset
     */
    function _resetDailyIfNeeded(SponsorshipConfig storage config) internal {
        if (block.timestamp >= config.dailyResetTime) {
            config.dailySpent = 0;
            config.dailyResetTime = block.timestamp + DAILY_PERIOD;
        }
    }

    /**
     * @notice Reset global daily spending if period has expired
     */
    function _resetGlobalDailyIfNeeded() internal {
        if (block.timestamp >= globalDailyResetTime) {
            globalDailySpent = 0;
            globalDailyResetTime = block.timestamp + DAILY_PERIOD;
        }
    }

    /*//////////////////////////////////////////////////////////////
                             FALLBACK
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive ETH and deposit to EntryPoint
     */
    receive() external payable {
        _entryPoint.depositTo{ value: msg.value }(address(this));
        emit PaymasterFunded(msg.sender, msg.value);
    }
}
