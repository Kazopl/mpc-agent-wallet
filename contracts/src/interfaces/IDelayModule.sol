// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IDelayModule
 * @notice Interface for transaction delay enforcement module
 * @dev Adds a cooldown period before high-value transactions execute,
 *      providing time to detect and cancel malicious operations.
 *
 * Use Cases for AI Agents:
 * - Adds security buffer for high-value autonomous transactions
 * - Allows human oversight for large transfers
 * - Enables cancellation of potentially malicious operations
 *
 * Flow:
 * 1. High-value transaction is queued (value > threshold)
 * 2. Cooldown period begins
 * 3. During cooldown: guardians can cancel
 * 4. After cooldown: anyone can execute
 */
interface IDelayModule {
    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Pending transaction data
     * @param target Call target address
     * @param value ETH value to send
     * @param data Call data
     * @param executeAfter Timestamp when transaction can be executed
     * @param executed Whether transaction has been executed
     * @param cancelled Whether transaction has been cancelled
     * @param queuedBy Address that queued the transaction
     */
    struct PendingTx {
        address target;
        uint256 value;
        bytes data;
        uint256 executeAfter;
        bool executed;
        bool cancelled;
        address queuedBy;
    }

    /**
     * @notice Delay configuration per account
     * @param delayThreshold Value above which delay applies (in wei)
     * @param cooldownPeriod Delay duration in seconds
     * @param enabled Whether delay module is active
     */
    struct DelayConfig {
        uint256 delayThreshold;
        uint256 cooldownPeriod;
        bool enabled;
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event TransactionQueued(
        address indexed account,
        bytes32 indexed txHash,
        address target,
        uint256 value,
        bytes data,
        uint256 executeAfter
    );

    event TransactionExecuted(
        address indexed account,
        bytes32 indexed txHash,
        address target,
        uint256 value,
        bytes returnData
    );

    event TransactionCancelled(
        address indexed account,
        bytes32 indexed txHash,
        address cancelledBy
    );

    event DelayConfigured(
        address indexed account,
        uint256 delayThreshold,
        uint256 cooldownPeriod
    );

    event DelayEnabled(address indexed account, bool enabled);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error TransactionNotQueued();
    error TransactionAlreadyExecuted();
    error TransactionCancelledError();
    error CooldownNotPassed();
    error NotAuthorized();
    error InvalidCooldownPeriod();
    error InvalidThreshold();
    error TransactionAlreadyQueued();
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                        QUEUE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Queue a transaction for delayed execution
     * @param target Call target address
     * @param value ETH value to send
     * @param data Call data
     * @return txHash Hash identifying the queued transaction
     */
    function queueTransaction(
        address target,
        uint256 value,
        bytes calldata data
    ) external returns (bytes32 txHash);

    /**
     * @notice Execute a queued transaction after cooldown
     * @param txHash Hash of the queued transaction
     * @return returnData Return data from the executed call
     */
    function executeQueued(bytes32 txHash) external returns (bytes memory returnData);

    /**
     * @notice Cancel a queued transaction
     * @dev Only callable by account owner or guardians
     * @param txHash Hash of the queued transaction
     */
    function cancelQueued(bytes32 txHash) external;

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure delay parameters
     * @param delayThreshold Value above which delay applies
     * @param cooldownPeriod Delay duration in seconds
     */
    function configureDelay(
        uint256 delayThreshold,
        uint256 cooldownPeriod
    ) external;

    /**
     * @notice Enable or disable the delay module
     * @param enabled Whether delay should be active
     */
    function setDelayEnabled(bool enabled) external;

    /*//////////////////////////////////////////////////////////////
                           GETTER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get delay configuration for an account
     * @param account The account address
     * @return config The delay configuration
     */
    function getConfig(address account) external view returns (DelayConfig memory config);

    /**
     * @notice Get the delay threshold for an account
     * @param account The account address
     * @return The threshold value in wei
     */
    function threshold(address account) external view returns (uint256);

    /**
     * @notice Get pending transaction details
     * @param account The account address
     * @param txHash Hash of the transaction
     * @return tx The pending transaction data
     */
    function getPendingTx(
        address account,
        bytes32 txHash
    ) external view returns (PendingTx memory);

    /**
     * @notice Check if a transaction requires delay
     * @param account The account address
     * @param value The transaction value
     * @return True if delay is required
     */
    function requiresDelay(
        address account,
        uint256 value
    ) external view returns (bool);

    /**
     * @notice Check if a queued transaction can be executed
     * @param account The account address
     * @param txHash Hash of the transaction
     * @return True if ready for execution
     */
    function canExecute(
        address account,
        bytes32 txHash
    ) external view returns (bool);

    /**
     * @notice Get time remaining until transaction can be executed
     * @param account The account address
     * @param txHash Hash of the transaction
     * @return Time in seconds (0 if ready or not queued)
     */
    function getTimeUntilExecution(
        address account,
        bytes32 txHash
    ) external view returns (uint256);
}
