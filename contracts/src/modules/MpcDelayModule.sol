// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IDelayModule } from "../interfaces/IDelayModule.sol";
import { IMpcRecoveryModule } from "../interfaces/IMpcRecoveryModule.sol";

/**
 * @title MpcDelayModule
 * @author MPC Agent Wallet SDK
 * @notice Transaction delay enforcement module for MPC smart accounts
 *
 * @dev Key features:
 *      - Configurable value threshold for delayed execution
 *      - Customizable cooldown period (default: 1 hour)
 *      - Guardian-based cancellation during cooldown
 *      - Transaction queuing and execution tracking
 *
 * Security Flow:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                    TRANSACTION DELAY SECURITY FLOW                          │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │   High-Value Transaction Detection                                          │
 * │   ├─ Value > Threshold? ────────────────────────────────────────►           │
 * │   │                                                               │         │
 * │   │  YES                                           NO             │         │
 * │   │   │                                            │              │         │
 * │   │   ▼                                            ▼              │         │
 * │   │  ┌────────────────┐                  ┌────────────────┐       │         │
 * │   │  │ Queue for      │                  │ Execute        │       │         │
 * │   │  │ Delayed Exec   │                  │ Immediately    │       │         │
 * │   │  └───────┬────────┘                  └────────────────┘       │         │
 * │   │          │                                                    │         │
 * │   │          ▼                                                    │         │
 * │   │  ┌────────────────┐                                           │         │
 * │   │  │ Cooldown Period│◄─── Guardian can CANCEL during this time  │         │
 * │   │  │ (e.g. 1 hour)  │                                           │         │
 * │   │  └───────┬────────┘                                           │         │
 * │   │          │                                                    │         │
 * │   │          ▼                                                    │         │
 * │   │  ┌────────────────┐                                           │         │
 * │   │  │ Execute Queued │ ◄─── Anyone can execute after cooldown    │         │
 * │   │  │ Transaction    │                                           │         │
 * │   │  └────────────────┘                                           │         │
 * │   │                                                               │         │
 * └───┴───────────────────────────────────────────────────────────────┴─────────┘
 *
 * Use Cases:
 * - AI agent large transfers require human approval window
 * - Detect and prevent flash loan attack drains
 * - Multi-sig style security without multiple signers
 */
contract MpcDelayModule is IDelayModule {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Default cooldown period (1 hour)
    uint256 public constant DEFAULT_COOLDOWN = 1 hours;

    /// @notice Minimum cooldown period (10 minutes)
    uint256 public constant MIN_COOLDOWN = 10 minutes;

    /// @notice Maximum cooldown period (7 days)
    uint256 public constant MAX_COOLDOWN = 7 days;

    /// @notice Default delay threshold (1 ETH)
    uint256 public constant DEFAULT_THRESHOLD = 1 ether;

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Delay configuration per account
    mapping(address => DelayConfig) internal _configs;

    /// @notice Pending transactions per account (account => txHash => PendingTx)
    mapping(address => mapping(bytes32 => PendingTx)) internal _pendingTxs;

    /// @notice Nonce per account for unique tx hashes
    mapping(address => uint256) internal _nonces;

    /// @notice Recovery module for guardian checks (optional)
    address public recoveryModule;

    /*//////////////////////////////////////////////////////////////
                              MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Restrict to account owner or guardians
     */
    modifier onlyAuthorized(address account) {
        if (msg.sender != account) {
            // Check if caller is a guardian via recovery module
            if (recoveryModule != address(0)) {
                if (!IMpcRecoveryModule(recoveryModule).isGuardian(account, msg.sender)) {
                    revert NotAuthorized();
                }
            } else {
                revert NotAuthorized();
            }
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Constructor sets optional recovery module reference
     * @param _recoveryModule Address of recovery module for guardian checks (can be address(0))
     */
    constructor(address _recoveryModule) {
        recoveryModule = _recoveryModule;
    }

    /*//////////////////////////////////////////////////////////////
                        QUEUE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IDelayModule
     */
    function queueTransaction(
        address target,
        uint256 value,
        bytes calldata data
    ) external returns (bytes32 txHash) {
        if (target == address(0)) {
            revert ZeroAddress();
        }

        address account = msg.sender;
        DelayConfig storage config = _configs[account];

        // Initialize with defaults if not configured
        uint256 cooldown = config.cooldownPeriod;
        if (cooldown == 0) {
            cooldown = DEFAULT_COOLDOWN;
        }

        uint256 executeAfter = block.timestamp + cooldown;

        // Generate unique tx hash using nonce
        txHash = _generateTxHash(account, target, value, data, _nonces[account]);
        _nonces[account]++;

        // Ensure not already queued
        if (_pendingTxs[account][txHash].executeAfter > 0) {
            revert TransactionAlreadyQueued();
        }

        _pendingTxs[account][txHash] = PendingTx({
            target: target,
            value: value,
            data: data,
            executeAfter: executeAfter,
            executed: false,
            cancelled: false,
            queuedBy: account
        });

        emit TransactionQueued(account, txHash, target, value, data, executeAfter);

        return txHash;
    }

    /**
     * @inheritdoc IDelayModule
     */
    function executeQueued(bytes32 txHash) external returns (bytes memory returnData) {
        address account = msg.sender;
        PendingTx storage pendingTx = _pendingTxs[account][txHash];

        if (pendingTx.executeAfter == 0) {
            revert TransactionNotQueued();
        }

        if (pendingTx.executed) {
            revert TransactionAlreadyExecuted();
        }

        if (pendingTx.cancelled) {
            revert TransactionCancelledError();
        }

        if (block.timestamp < pendingTx.executeAfter) {
            revert CooldownNotPassed();
        }

        // Mark as executed before external call (reentrancy protection)
        pendingTx.executed = true;

        // Execute the transaction via the account (caller must be the account)
        bool success;
        (success, returnData) = pendingTx.target.call{value: pendingTx.value}(pendingTx.data);

        // Note: We don't revert on failure - we emit the result
        // The account contract should handle execution

        emit TransactionExecuted(account, txHash, pendingTx.target, pendingTx.value, returnData);

        return returnData;
    }

    /**
     * @inheritdoc IDelayModule
     */
    function cancelQueued(bytes32 txHash) external {
        // Find the account that queued this transaction
        // The caller must be the account owner or a guardian
        address account = msg.sender;
        PendingTx storage pendingTx = _pendingTxs[account][txHash];

        // If not found as direct account, check if caller is guardian
        if (pendingTx.executeAfter == 0) {
            revert TransactionNotQueued();
        }

        // Only account owner or guardians can cancel
        if (msg.sender != account && recoveryModule != address(0)) {
            if (!IMpcRecoveryModule(recoveryModule).isGuardian(account, msg.sender)) {
                revert NotAuthorized();
            }
        }

        if (pendingTx.executed) {
            revert TransactionAlreadyExecuted();
        }

        if (pendingTx.cancelled) {
            revert TransactionCancelledError();
        }

        pendingTx.cancelled = true;

        emit TransactionCancelled(account, txHash, msg.sender);
    }

    /**
     * @notice Cancel a queued transaction (guardian variant)
     * @dev Allows guardians to cancel transactions for any account they guard
     * @param account The account with the pending transaction
     * @param txHash Hash of the queued transaction
     */
    function cancelQueuedFor(address account, bytes32 txHash) external {
        PendingTx storage pendingTx = _pendingTxs[account][txHash];

        if (pendingTx.executeAfter == 0) {
            revert TransactionNotQueued();
        }

        // Must be account owner or guardian
        if (msg.sender != account) {
            if (recoveryModule == address(0)) {
                revert NotAuthorized();
            }
            if (!IMpcRecoveryModule(recoveryModule).isGuardian(account, msg.sender)) {
                revert NotAuthorized();
            }
        }

        if (pendingTx.executed) {
            revert TransactionAlreadyExecuted();
        }

        if (pendingTx.cancelled) {
            revert TransactionCancelledError();
        }

        pendingTx.cancelled = true;

        emit TransactionCancelled(account, txHash, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IDelayModule
     */
    function configureDelay(
        uint256 delayThreshold,
        uint256 cooldownPeriod
    ) external {
        if (cooldownPeriod > 0 && (cooldownPeriod < MIN_COOLDOWN || cooldownPeriod > MAX_COOLDOWN)) {
            revert InvalidCooldownPeriod();
        }

        address account = msg.sender;

        _configs[account] = DelayConfig({
            delayThreshold: delayThreshold,
            cooldownPeriod: cooldownPeriod == 0 ? DEFAULT_COOLDOWN : cooldownPeriod,
            enabled: true
        });

        emit DelayConfigured(account, delayThreshold, cooldownPeriod == 0 ? DEFAULT_COOLDOWN : cooldownPeriod);
    }

    /**
     * @inheritdoc IDelayModule
     */
    function setDelayEnabled(bool enabled) external {
        _configs[msg.sender].enabled = enabled;
        emit DelayEnabled(msg.sender, enabled);
    }

    /*//////////////////////////////////////////////////////////////
                           GETTER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IDelayModule
     */
    function getConfig(address account) external view returns (DelayConfig memory config) {
        config = _configs[account];
        // Return defaults if not configured
        if (config.cooldownPeriod == 0) {
            config.cooldownPeriod = DEFAULT_COOLDOWN;
        }
        if (config.delayThreshold == 0) {
            config.delayThreshold = DEFAULT_THRESHOLD;
        }
        return config;
    }

    /**
     * @inheritdoc IDelayModule
     */
    function threshold(address account) external view returns (uint256) {
        uint256 t = _configs[account].delayThreshold;
        return t == 0 ? DEFAULT_THRESHOLD : t;
    }

    /**
     * @inheritdoc IDelayModule
     */
    function getPendingTx(
        address account,
        bytes32 txHash
    ) external view returns (PendingTx memory) {
        return _pendingTxs[account][txHash];
    }

    /**
     * @inheritdoc IDelayModule
     */
    function requiresDelay(
        address account,
        uint256 value
    ) external view returns (bool) {
        DelayConfig storage config = _configs[account];

        if (!config.enabled) {
            return false;
        }

        uint256 t = config.delayThreshold;
        if (t == 0) {
            t = DEFAULT_THRESHOLD;
        }

        return value > t;
    }

    /**
     * @inheritdoc IDelayModule
     */
    function canExecute(
        address account,
        bytes32 txHash
    ) external view returns (bool) {
        PendingTx storage pendingTx = _pendingTxs[account][txHash];

        return pendingTx.executeAfter > 0
            && !pendingTx.executed
            && !pendingTx.cancelled
            && block.timestamp >= pendingTx.executeAfter;
    }

    /**
     * @inheritdoc IDelayModule
     */
    function getTimeUntilExecution(
        address account,
        bytes32 txHash
    ) external view returns (uint256) {
        PendingTx storage pendingTx = _pendingTxs[account][txHash];

        if (pendingTx.executeAfter == 0 || pendingTx.executed || pendingTx.cancelled) {
            return 0;
        }

        if (block.timestamp >= pendingTx.executeAfter) {
            return 0;
        }

        return pendingTx.executeAfter - block.timestamp;
    }

    /**
     * @notice Get current nonce for an account
     * @param account The account address
     * @return The current nonce value
     */
    function getNonce(address account) external view returns (uint256) {
        return _nonces[account];
    }

    /**
     * @notice Check if delay module is enabled for an account
     * @param account The account address
     * @return True if enabled
     */
    function isEnabled(address account) external view returns (bool) {
        return _configs[account].enabled;
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Generate unique transaction hash
     */
    function _generateTxHash(
        address account,
        address target,
        uint256 value,
        bytes calldata data,
        uint256 nonce
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(account, target, value, data, nonce));
    }
}
