// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IMpcRecoveryModule
 * @notice Interface for MPC key share recovery module
 * @dev Enables secure rotation of MPC public keys with time-delayed execution
 *
 * Recovery Flow:
 * 1. Recovery guardian initiates recovery with new MPC public key
 * 2. Time delay begins (default 2 days)
 * 3. During delay, current key holders can cancel
 * 4. After delay, anyone can execute the recovery
 *
 * This allows recovering from:
 * - Lost key shares
 * - Compromised key shares
 * - Key share refresh/rotation
 */
interface IMpcRecoveryModule {
    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Recovery request data
     * @param newMpcPublicKey The proposed new MPC public key
     * @param executeAfter Timestamp when recovery can be executed
     * @param initiator Address that initiated the recovery
     * @param executed Whether recovery has been executed
     */
    struct RecoveryRequest {
        bytes newMpcPublicKey;
        uint256 executeAfter;
        address initiator;
        bool executed;
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event RecoveryInitiated(
        address indexed account, address indexed initiator, bytes newMpcPublicKey, uint256 executeAfter
    );

    event RecoveryExecuted(address indexed account, bytes oldMpcPublicKey, bytes newMpcPublicKey);

    event RecoveryCancelled(address indexed account, address indexed cancelledBy);

    event RecoveryDelayUpdated(address indexed account, uint256 oldDelay, uint256 newDelay);

    event GuardianAdded(address indexed account, address indexed guardian);

    event GuardianRemoved(address indexed account, address indexed guardian);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error NotGuardian();
    error RecoveryNotInitiated();
    error RecoveryAlreadyPending();
    error RecoveryDelayNotPassed();
    error RecoveryAlreadyExecuted();
    error InvalidMpcPublicKey();
    error RecoveryDelayTooShort();
    error OnlyAccountOrGuardian();
    error GuardianAlreadyExists();
    error GuardianNotFound();
    error CannotRemoveLastGuardian();

    /*//////////////////////////////////////////////////////////////
                          RECOVERY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate MPC key recovery
     * @param account The account to recover
     * @param newMpcPublicKey The new MPC public key
     */
    function initiateRecovery(address account, bytes calldata newMpcPublicKey) external;

    /**
     * @notice Execute pending recovery after delay
     * @param account The account to recover
     */
    function executeRecovery(
        address account
    ) external;

    /**
     * @notice Cancel pending recovery
     * @param account The account with pending recovery
     */
    function cancelRecovery(
        address account
    ) external;

    /*//////////////////////////////////////////////////////////////
                        GUARDIAN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add a recovery guardian for an account
     * @param guardian Address to add as guardian
     */
    function addGuardian(
        address guardian
    ) external;

    /**
     * @notice Remove a recovery guardian
     * @param guardian Address to remove
     */
    function removeGuardian(
        address guardian
    ) external;

    /**
     * @notice Check if an address is a guardian
     * @param account The account to check
     * @param guardian The potential guardian address
     * @return True if guardian
     */
    function isGuardian(address account, address guardian) external view returns (bool);

    /**
     * @notice Get all guardians for an account
     * @param account The account
     * @return Array of guardian addresses
     */
    function getGuardians(
        address account
    ) external view returns (address[] memory);

    /*//////////////////////////////////////////////////////////////
                         CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update recovery delay for an account
     * @param newDelay New delay in seconds
     */
    function setRecoveryDelay(
        uint256 newDelay
    ) external;

    /**
     * @notice Get recovery delay for an account
     * @param account The account
     * @return Delay in seconds
     */
    function getRecoveryDelay(
        address account
    ) external view returns (uint256);

    /**
     * @notice Get pending recovery request
     * @param account The account
     * @return The recovery request
     */
    function getRecoveryRequest(
        address account
    ) external view returns (RecoveryRequest memory);

    /**
     * @notice Check if recovery can be executed
     * @param account The account
     * @return True if recovery is ready
     */
    function canExecuteRecovery(
        address account
    ) external view returns (bool);
}
