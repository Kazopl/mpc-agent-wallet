// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IMpcRecoveryModule } from "../interfaces/IMpcRecoveryModule.sol";
import { IMpcSmartAccount } from "../interfaces/IMpcSmartAccount.sol";
import { IERC7579Module } from "../interfaces/IERC7579Module.sol";

/**
 * @title MpcRecoveryModule
 * @author MPC Agent Wallet SDK
 * @notice Enables secure MPC public key recovery with time-delayed execution
 * @dev Implements IERC7579Module (Type 2: Executor) for ERC-7579 compatibility
 *
 * @dev Key features:
 *      - Guardian-initiated recovery (no single point of failure)
 *      - Configurable time delay (default 2 days)
 *      - Cancellation by current key holders during delay
 *      - Supports key share rotation scenarios
 *
 * Recovery Flow:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                       MPC KEY RECOVERY FLOW                                  │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │   Use Cases:                                                                │
 * │   • Lost key share - User loses device with key share                       │
 * │   • Compromised share - AI agent key leaked                                 │
 * │   • Key rotation - Scheduled security refresh                               │
 * │                                                                             │
 * │   ┌──────────────┐                                                          │
 * │   │   Guardian   │ initiateRecovery(account, newMpcPubKey)                  │
 * │   │              │───────────────────────────────────────────►              │
 * │   └──────────────┘                                              │           │
 * │                                                                 ▼           │
 * │                                                    ┌─────────────────────┐  │
 * │                                                    │   Time Delay        │  │
 * │                                                    │   (Default: 2 days) │  │
 * │   ┌──────────────┐                                 │                     │  │
 * │   │ Current Key  │ cancelRecovery()                │   During delay:     │  │
 * │   │   Holders    │──────────────────►CANCEL        │   - Can be cancelled│  │
 * │   │              │                                 │   - Visible on-chain│  │
 * │   └──────────────┘                                 └──────────┬──────────┘  │
 * │                                                               │             │
 * │                                                               ▼             │
 * │                                                    ┌─────────────────────┐  │
 * │                                                    │  executeRecovery()  │  │
 * │                                                    │                     │  │
 * │                                                    │  Updates MPC pubkey │  │
 * │                                                    │  on MpcSmartAccount │  │
 * │                                                    └─────────────────────┘  │
 * │                                                                             │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * Security Considerations:
 * - Only designated guardians can initiate recovery
 * - Time delay allows detection of malicious recovery attempts
 * - Current key holders (AI agent + user) can cancel during delay
 * - On-chain visibility ensures transparency
 */
contract MpcRecoveryModule is IMpcRecoveryModule, IERC7579Module {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC-7579 Executor module type ID
    uint256 public constant MODULE_TYPE = 2;

    /// @notice Default recovery delay (2 days)
    uint256 public constant DEFAULT_RECOVERY_DELAY = 2 days;

    /// @notice Minimum recovery delay (1 hour)
    uint256 public constant MIN_RECOVERY_DELAY = 1 hours;

    /// @notice Maximum recovery delay (30 days)
    uint256 public constant MAX_RECOVERY_DELAY = 30 days;

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Recovery delay per account
    mapping(address => uint256) internal _recoveryDelays;

    /// @notice Pending recovery requests per account
    mapping(address => RecoveryRequest) internal _recoveryRequests;

    /// @notice Guardians per account (account => guardian => isGuardian)
    mapping(address => mapping(address => bool)) internal _guardians;

    /// @notice Guardian list per account (for enumeration)
    mapping(address => address[]) internal _guardianList;

    /// @notice Whether account has been initialized
    mapping(address => bool) internal _initialized;

    /*//////////////////////////////////////////////////////////////
                              MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Restrict to guardians of the account
     */
    modifier onlyGuardian(
        address account
    ) {
        if (!_guardians[account][msg.sender]) {
            revert NotGuardian();
        }
        _;
    }

    /**
     * @notice Restrict to account or its guardians
     */
    modifier onlyAccountOrGuardian(
        address account
    ) {
        if (msg.sender != account && !_guardians[account][msg.sender]) {
            revert OnlyAccountOrGuardian();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                       ERC-7579 MODULE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IERC7579Module
     * @dev Initializes recovery for the calling account
     *      Data format: abi.encode(guardians[], recoveryDelay)
     */
    function onInstall(bytes calldata data) external override {
        address account = msg.sender;

        if (_initialized[account]) {
            revert AlreadyInitialized(account);
        }

        // Decode initialization data
        (address[] memory guardians, uint256 recoveryDelay) = abi.decode(data, (address[], uint256));

        if (recoveryDelay < MIN_RECOVERY_DELAY || recoveryDelay > MAX_RECOVERY_DELAY) {
            revert RecoveryDelayTooShort();
        }

        _recoveryDelays[account] = recoveryDelay;
        _initialized[account] = true;

        // Add guardians
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] != address(0) && !_guardians[account][guardians[i]]) {
                _guardians[account][guardians[i]] = true;
                _guardianList[account].push(guardians[i]);
                emit GuardianAdded(account, guardians[i]);
            }
        }

        emit ModuleInstalled(account);
    }

    /**
     * @inheritdoc IERC7579Module
     * @dev Cleans up recovery configuration for the calling account
     */
    function onUninstall(bytes calldata /* data */) external override {
        address account = msg.sender;

        if (!_initialized[account]) {
            revert NotInitialized(account);
        }

        // Cancel any pending recovery
        if (_recoveryRequests[account].executeAfter > 0 && !_recoveryRequests[account].executed) {
            delete _recoveryRequests[account];
        }

        // Remove all guardians
        address[] storage guardians = _guardianList[account];
        for (uint256 i = 0; i < guardians.length; i++) {
            _guardians[account][guardians[i]] = false;
        }
        delete _guardianList[account];

        // Clean up other state
        delete _recoveryDelays[account];
        _initialized[account] = false;

        emit ModuleUninstalled(account);
    }

    /**
     * @inheritdoc IERC7579Module
     * @dev This is an Executor module (Type 2)
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
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize recovery for an account
     * @param guardians Initial guardian addresses
     * @param recoveryDelay Recovery delay in seconds
     */
    function initialize(address[] calldata guardians, uint256 recoveryDelay) external {
        address account = msg.sender;

        if (_initialized[account]) {
            // Already initialized, skip
            return;
        }

        if (recoveryDelay < MIN_RECOVERY_DELAY || recoveryDelay > MAX_RECOVERY_DELAY) {
            revert RecoveryDelayTooShort();
        }

        _recoveryDelays[account] = recoveryDelay;
        _initialized[account] = true;

        // Add guardians
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] != address(0) && !_guardians[account][guardians[i]]) {
                _guardians[account][guardians[i]] = true;
                _guardianList[account].push(guardians[i]);
                emit GuardianAdded(account, guardians[i]);
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                          RECOVERY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IMpcRecoveryModule
     */
    function initiateRecovery(address account, bytes calldata newMpcPublicKey) external onlyGuardian(account) {
        if (newMpcPublicKey.length != 33) {
            revert InvalidMpcPublicKey();
        }

        RecoveryRequest storage request = _recoveryRequests[account];

        // Check if there's already a pending recovery
        if (request.executeAfter > 0 && !request.executed) {
            revert RecoveryAlreadyPending();
        }

        uint256 delay = _recoveryDelays[account];
        if (delay == 0) {
            delay = DEFAULT_RECOVERY_DELAY;
        }

        uint256 executeAfter = block.timestamp + delay;

        _recoveryRequests[account] = RecoveryRequest({
            newMpcPublicKey: newMpcPublicKey,
            executeAfter: executeAfter,
            initiator: msg.sender,
            executed: false
        });

        emit RecoveryInitiated(account, msg.sender, newMpcPublicKey, executeAfter);
    }

    /**
     * @inheritdoc IMpcRecoveryModule
     */
    function executeRecovery(
        address account
    ) external {
        RecoveryRequest storage request = _recoveryRequests[account];

        if (request.executeAfter == 0) {
            revert RecoveryNotInitiated();
        }

        if (request.executed) {
            revert RecoveryAlreadyExecuted();
        }

        if (block.timestamp < request.executeAfter) {
            revert RecoveryDelayNotPassed();
        }

        // Mark as executed before external call
        request.executed = true;

        // Get old key for event
        bytes memory oldKey = IMpcSmartAccount(account).mpcPublicKey();

        // Update MPC public key on the account
        IMpcSmartAccount(account).updateMpcPublicKey(request.newMpcPublicKey);

        emit RecoveryExecuted(account, oldKey, request.newMpcPublicKey);
    }

    /**
     * @inheritdoc IMpcRecoveryModule
     */
    function cancelRecovery(
        address account
    ) external onlyAccountOrGuardian(account) {
        RecoveryRequest storage request = _recoveryRequests[account];

        if (request.executeAfter == 0 || request.executed) {
            revert RecoveryNotInitiated();
        }

        delete _recoveryRequests[account];

        emit RecoveryCancelled(account, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        GUARDIAN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IMpcRecoveryModule
     */
    function addGuardian(
        address guardian
    ) external {
        address account = msg.sender;

        if (guardian == address(0)) {
            revert InvalidMpcPublicKey(); // Reusing error for zero address
        }

        if (_guardians[account][guardian]) {
            revert GuardianAlreadyExists();
        }

        _guardians[account][guardian] = true;
        _guardianList[account].push(guardian);

        emit GuardianAdded(account, guardian);
    }

    /**
     * @inheritdoc IMpcRecoveryModule
     */
    function removeGuardian(
        address guardian
    ) external {
        address account = msg.sender;

        if (!_guardians[account][guardian]) {
            revert GuardianNotFound();
        }

        // Ensure at least one guardian remains
        if (_guardianList[account].length <= 1) {
            revert CannotRemoveLastGuardian();
        }

        _guardians[account][guardian] = false;

        // Remove from list (swap and pop)
        address[] storage guardians = _guardianList[account];
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] == guardian) {
                guardians[i] = guardians[guardians.length - 1];
                guardians.pop();
                break;
            }
        }

        // Cancel any pending recovery if guardian set changes
        RecoveryRequest storage request = _recoveryRequests[account];
        if (request.executeAfter > 0 && !request.executed) {
            delete _recoveryRequests[account];
            emit RecoveryCancelled(account, msg.sender);
        }

        emit GuardianRemoved(account, guardian);
    }

    /**
     * @inheritdoc IMpcRecoveryModule
     */
    function isGuardian(address account, address guardian) external view returns (bool) {
        return _guardians[account][guardian];
    }

    /**
     * @inheritdoc IMpcRecoveryModule
     */
    function getGuardians(
        address account
    ) external view returns (address[] memory) {
        return _guardianList[account];
    }

    /*//////////////////////////////////////////////////////////////
                         CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IMpcRecoveryModule
     */
    function setRecoveryDelay(
        uint256 newDelay
    ) external {
        if (newDelay < MIN_RECOVERY_DELAY || newDelay > MAX_RECOVERY_DELAY) {
            revert RecoveryDelayTooShort();
        }

        address account = msg.sender;
        uint256 oldDelay = _recoveryDelays[account];
        _recoveryDelays[account] = newDelay;

        emit RecoveryDelayUpdated(account, oldDelay, newDelay);
    }

    /**
     * @inheritdoc IMpcRecoveryModule
     */
    function getRecoveryDelay(
        address account
    ) external view returns (uint256) {
        uint256 delay = _recoveryDelays[account];
        return delay == 0 ? DEFAULT_RECOVERY_DELAY : delay;
    }

    /**
     * @inheritdoc IMpcRecoveryModule
     */
    function getRecoveryRequest(
        address account
    ) external view returns (RecoveryRequest memory) {
        return _recoveryRequests[account];
    }

    /**
     * @inheritdoc IMpcRecoveryModule
     */
    function canExecuteRecovery(
        address account
    ) external view returns (bool) {
        RecoveryRequest storage request = _recoveryRequests[account];

        return request.executeAfter > 0 && !request.executed && block.timestamp >= request.executeAfter;
    }

    /**
     * @notice Get time remaining until recovery can be executed
     * @param account The account
     * @return Time in seconds (0 if ready or no pending recovery)
     */
    function getTimeUntilExecution(
        address account
    ) external view returns (uint256) {
        RecoveryRequest storage request = _recoveryRequests[account];

        if (request.executeAfter == 0 || request.executed) {
            return 0;
        }

        if (block.timestamp >= request.executeAfter) {
            return 0;
        }

        return request.executeAfter - block.timestamp;
    }
}
