// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IMpcSmartAccount } from "./interfaces/IMpcSmartAccount.sol";
import { IEntryPoint } from "./interfaces/IEntryPoint.sol";
import { ISessionKeyModule } from "./interfaces/ISessionKeyModule.sol";
import { IDelayModule } from "./interfaces/IDelayModule.sol";
import {
    IERC7579Module,
    IERC7579AccountConfig,
    IERC7579ModuleConfig,
    ERC7579ModuleTypes
} from "./interfaces/IERC7579Module.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title MpcSmartAccount
 * @author MPC Agent Wallet SDK
 * @notice ERC-4337 smart account secured by MPC threshold signatures with ERC-7579 modular support
 *
 * @dev Key features:
 *      - 2-of-3 threshold MPC signature validation
 *      - Built-in spending limits and whitelisting
 *      - Time-based transaction restrictions
 *      - Upgradeable via UUPS pattern
 *      - EIP-1271 signature validation
 *      - ERC-7579 modular account architecture for extensibility
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                      MPC SMART ACCOUNT ARCHITECTURE                          │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  Key Share Distribution (2-of-3):                                           │
 * │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                         │
 * │  │  AI Agent   │  │    User     │  │  Recovery   │                         │
 * │  │   Share     │  │   Share     │  │  Guardian   │                         │
 * │  │             │  │             │  │   Share     │                         │
 * │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                         │
 * │         │                │                │                                 │
 * │         └────────────────┼────────────────┘                                 │
 * │                          │                                                  │
 * │                          ▼                                                  │
 * │              ┌───────────────────────┐                                      │
 * │              │   Aggregated ECDSA    │                                      │
 * │              │      Signature        │                                      │
 * │              └───────────┬───────────┘                                      │
 * │                          │                                                  │
 * │                          ▼                                                  │
 * │              ┌───────────────────────┐                                      │
 * │              │   MpcSmartAccount     │                                      │
 * │              │   validateUserOp()    │                                      │
 * │              │                       │                                      │
 * │              │   - Verify MPC sig    │                                      │
 * │              │   - Check policies    │                                      │
 * │              │   - Execute tx        │                                      │
 * │              └───────────────────────┘                                      │
 * │                                                                             │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * Security Model:
 * - MPC signature ensures no single party can sign alone
 * - On-chain policies provide additional protection
 * - Recovery module enables key rotation without fund loss
 */
contract MpcSmartAccount is
    IMpcSmartAccount,
    IERC1271,
    IERC7579AccountConfig,
    IERC7579ModuleConfig,
    Initializable,
    UUPSUpgradeable
{
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice EIP-1271 magic value for valid signature
    bytes4 internal constant EIP1271_SUCCESS = 0x1626ba7e;

    /// @notice EIP-1271 magic value for invalid signature
    bytes4 internal constant EIP1271_FAILED = 0xffffffff;

    /// @notice ERC-4337 signature validation success
    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;

    /// @notice ERC-4337 signature validation failure
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    /// @notice Time period for daily limit reset
    uint256 public constant DAILY_PERIOD = 1 days;

    /// @notice Account implementation identifier
    string public constant ACCOUNT_ID = "mpc-agent-wallet.smart-account.v1";

    /*//////////////////////////////////////////////////////////////
                       ERC-7579 EXECUTION MODES
    //////////////////////////////////////////////////////////////*/

    /// @notice Default single execution mode
    bytes32 public constant EXEC_MODE_DEFAULT = bytes32(0);

    /// @notice Batch execution mode
    bytes32 public constant EXEC_MODE_BATCH = bytes32(uint256(1));

    /// @notice Try (failure-tolerant) execution mode
    bytes32 public constant EXEC_MODE_TRY = bytes32(uint256(2));

    /// @notice Delegatecall execution mode (not supported for security)
    bytes32 public constant EXEC_MODE_DELEGATECALL = bytes32(uint256(0xff));

    /*//////////////////////////////////////////////////////////////
                          ERC-7579 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when module type is not supported
    error UnsupportedModuleType(uint256 moduleTypeId);

    /// @notice Thrown when module is already installed
    error ModuleAlreadyInstalled(uint256 moduleTypeId, address module);

    /// @notice Thrown when module is not installed
    error ModuleNotInstalled(uint256 moduleTypeId, address module);

    /// @notice Thrown when execution mode is not supported
    error UnsupportedExecutionMode(bytes32 mode);

    /// @notice Thrown when module address is invalid
    error InvalidModuleAddress();

    /*//////////////////////////////////////////////////////////////
                            IMMUTABLE STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice The EntryPoint contract
    IEntryPoint internal immutable _entryPoint;

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice MPC aggregated public key (compressed secp256k1, 33 bytes)
    bytes internal _mpcPublicKey;

    /// @notice Recovery module address (can update MPC key)
    address public recoveryModule;

    /// @notice Daily spending limit in wei (0 = no limit)
    uint256 internal _dailyLimit;

    /// @notice Amount spent in current day
    uint256 internal _spentToday;

    /// @notice Timestamp when daily limit resets
    uint256 internal _dailyResetTime;

    /// @notice Session key module address
    address public sessionKeyModule;

    /// @notice Delay module address for high-value transaction delays
    address public delayModule;

    /// @notice Current session key signer (set during validation, used in execution)
    address internal _currentSessionKeySigner;

    /// @notice Address whitelist (target => allowed)
    mapping(address => bool) internal _whitelist;

    /// @notice Whether whitelist is enforced
    bool public whitelistEnabled;

    /// @notice Time restriction start hour (0-23, UTC)
    uint8 internal _timeRestrictionStart;

    /// @notice Time restriction end hour (0-23, UTC)
    uint8 internal _timeRestrictionEnd;

    /// @notice Whether time restrictions are enabled
    bool internal _timeRestrictionsEnabled;

    /*//////////////////////////////////////////////////////////////
                       ERC-7579 MODULE STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Installed validators (moduleTypeId 1)
    /// @dev Maps module address => installed status
    mapping(address => bool) internal _installedValidators;

    /// @notice Installed executors (moduleTypeId 2)
    /// @dev Maps module address => installed status
    mapping(address => bool) internal _installedExecutors;

    /// @notice Installed fallback handlers (moduleTypeId 3)
    /// @dev Maps selector => module address
    mapping(bytes4 => address) internal _fallbackHandlers;

    /// @notice Installed hooks (moduleTypeId 4)
    /// @dev Maps module address => installed status
    mapping(address => bool) internal _installedHooks;

    /// @notice Array of installed validators for enumeration
    address[] internal _validatorList;

    /// @notice Array of installed executors for enumeration
    address[] internal _executorList;

    /// @notice Array of installed hooks for enumeration
    address[] internal _hookList;

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
     * @notice Restrict to self or recovery module
     */
    modifier onlySelfOrRecovery() {
        if (msg.sender != address(this) && msg.sender != recoveryModule) {
            revert OnlySelfOrRecovery();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Constructor sets the EntryPoint
     * @param anEntryPoint The EntryPoint contract address
     */
    constructor(
        IEntryPoint anEntryPoint
    ) {
        _entryPoint = anEntryPoint;
        _disableInitializers();
    }

    /**
     * @notice Initialize the account with MPC public key
     * @param mpcPubKey The aggregated MPC public key (33 bytes compressed)
     * @param _recoveryModule Address of the recovery module
     * @param initialDailyLimit Initial daily spending limit (0 = no limit)
     */
    function initialize(
        bytes calldata mpcPubKey,
        address _recoveryModule,
        uint256 initialDailyLimit
    ) external initializer {
        if (mpcPubKey.length != 33) {
            revert InvalidMpcPublicKey();
        }
        if (_recoveryModule == address(0)) {
            revert ZeroAddress();
        }

        _mpcPublicKey = mpcPubKey;
        recoveryModule = _recoveryModule;
        _dailyLimit = initialDailyLimit;
        _dailyResetTime = block.timestamp + DAILY_PERIOD;
    }

    /**
     * @notice Set the session key module address
     * @param _sessionKeyModule Address of the session key module
     */
    function setSessionKeyModule(
        address _sessionKeyModule
    ) external onlySelfOrRecovery {
        sessionKeyModule = _sessionKeyModule;
    }

    /**
     * @notice Set the delay module address
     * @param _delayModule Address of the delay module
     */
    function setDelayModule(
        address _delayModule
    ) external onlySelfOrRecovery {
        delayModule = _delayModule;
    }

    /*//////////////////////////////////////////////////////////////
                         ERC-4337 VALIDATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validate a UserOperation signature
     * @dev Verifies the MPC threshold signature or session key signature
     *
     * Signature format detection:
     * - Session key signature: 85 bytes (20 bytes signer address + 65 bytes ECDSA sig)
     * - MPC signature: 65 bytes (standard ECDSA signature)
     *
     * @param userOp The UserOperation to validate
     * @param userOpHash Hash of the UserOperation
     * @param missingAccountFunds Funds to deposit for gas
     * @return validationData 0 for success, 1 for failure (or packed time bounds for session keys)
     */
    function validateUserOp(
        IEntryPoint.PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        // Check if this is a session key signature
        if (_isSessionKeySignature(userOp.signature)) {
            validationData = _validateSessionKey(userOpHash, userOp.signature);
        } else {
            // Fall back to MPC signature validation
            validationData = _validateMpcSignature(userOpHash, userOp.signature);
            // Clear any previous session key signer
            _currentSessionKeySigner = address(0);
        }

        // Pay prefund to EntryPoint
        if (missingAccountFunds > 0) {
            (bool success,) = payable(address(_entryPoint)).call{ value: missingAccountFunds }("");
            (success); // Ignore failure - EntryPoint will check deposit
        }

        return validationData;
    }

    /**
     * @notice Check if a signature is a session key signature
     * @dev Session key signatures are 85 bytes (20 address + 65 ECDSA)
     *      MPC signatures are 65 bytes (standard ECDSA)
     * @param signature The signature to check
     * @return True if this appears to be a session key signature
     */
    function _isSessionKeySignature(
        bytes calldata signature
    ) internal view returns (bool) {
        // Session key signatures are 85 bytes and session key module must be set
        return signature.length == 85 && sessionKeyModule != address(0);
    }

    /**
     * @notice Validate a session key signature
     * @param userOpHash Hash of the UserOperation
     * @param signature The session key signature (20 bytes signer + 65 bytes ECDSA)
     * @return validationData Packed validation data with time bounds
     */
    function _validateSessionKey(
        bytes32 userOpHash,
        bytes calldata signature
    ) internal returns (uint256 validationData) {
        // Delegate validation to session key module
        validationData = ISessionKeyModule(sessionKeyModule).validateSessionKey(address(this), userOpHash, signature);

        // Extract and store the session key signer for use in execution
        // If validation succeeded (not returning SIG_VALIDATION_FAILED)
        if (validationData != SIG_VALIDATION_FAILED) {
            _currentSessionKeySigner = address(bytes20(signature[:20]));
        } else {
            _currentSessionKeySigner = address(0);
        }

        return validationData;
    }

    /**
     * @notice Validate MPC signature
     * @dev Recovers signer from signature and compares to stored MPC public key
     * @param hash The hash that was signed
     * @param signature The ECDSA signature
     * @return validationData 0 for success, 1 for failure
     */
    function _validateMpcSignature(
        bytes32 hash,
        bytes calldata signature
    ) internal view returns (uint256 validationData) {
        bytes32 ethSignedHash = hash.toEthSignedMessageHash();

        // Recover the address from signature
        (address recovered, ECDSA.RecoverError error,) = ethSignedHash.tryRecover(signature);

        if (error != ECDSA.RecoverError.NoError) {
            return SIG_VALIDATION_FAILED;
        }

        // Derive address from stored MPC public key and compare
        address mpcAddress = _publicKeyToAddress(_mpcPublicKey);

        if (recovered != mpcAddress) {
            return SIG_VALIDATION_FAILED;
        }

        return SIG_VALIDATION_SUCCESS;
    }

    /**
     * @notice Convert compressed public key to Ethereum address
     * @param pubKey 33-byte compressed public key
     * @return The derived address
     */
    function _publicKeyToAddress(
        bytes memory pubKey
    ) internal pure returns (address) {
        // For compressed public keys, we need to decompress first
        // However, since MPC signing produces a signature, we can also
        // store the address derived from the aggregated public key
        // For simplicity, we hash the compressed key (this is a placeholder)
        // In production, proper decompression would be needed
        return address(uint160(uint256(keccak256(pubKey))));
    }

    /*//////////////////////////////////////////////////////////////
                           EIP-1271 SUPPORT
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IERC1271
     */
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        uint256 result = _validateMpcSignature(hash, signature);

        if (result == SIG_VALIDATION_SUCCESS) {
            return EIP1271_SUCCESS;
        }

        return EIP1271_FAILED;
    }

    /*//////////////////////////////////////////////////////////////
                              EXECUTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IMpcSmartAccount
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external payable onlyEntryPoint returns (bytes memory returnData) {
        // If using a session key, validate against session key restrictions
        if (_currentSessionKeySigner != address(0) && sessionKeyModule != address(0)) {
            ISessionKeyModule(sessionKeyModule).validateAndRecordSpending(
                address(this), _currentSessionKeySigner, target, value, data
            );
            // Clear session key signer after use
            _currentSessionKeySigner = address(0);
        } else {
            // Check policies for MPC-signed transactions
            _checkPolicies(target, value);
            // Record spending
            _recordSpending(value);
        }

        // Check if delay is required for high-value transactions
        if (_requiresDelay(value)) {
            // Queue transaction for delayed execution
            bytes32 txHash = IDelayModule(delayModule).queueTransaction(target, value, data);
            // Return the tx hash encoded as return data
            return abi.encode(txHash);
        }

        // Execute call immediately
        bool success;
        (success, returnData) = target.call{ value: value }(data);

        if (!success) {
            revert ExecutionFailed(target, returnData);
        }

        emit TransactionExecuted(target, value, data, returnData);
    }

    /**
     * @notice Execute a previously queued delayed transaction
     * @param txHash Hash of the queued transaction
     * @return returnData Return data from the executed call
     */
    function executeDelayed(bytes32 txHash) external onlyEntryPoint returns (bytes memory returnData) {
        if (delayModule == address(0)) {
            revert ExecutionFailed(address(0), "Delay module not set");
        }

        // Get the pending transaction details
        IDelayModule.PendingTx memory pendingTx = IDelayModule(delayModule).getPendingTx(address(this), txHash);

        // Execute through the delay module (which verifies cooldown has passed)
        returnData = IDelayModule(delayModule).executeQueued(txHash);

        emit TransactionExecuted(pendingTx.target, pendingTx.value, pendingTx.data, returnData);

        return returnData;
    }

    /**
     * @notice Cancel a queued delayed transaction
     * @param txHash Hash of the queued transaction
     */
    function cancelDelayed(bytes32 txHash) external onlySelfOrRecovery {
        if (delayModule == address(0)) {
            revert ExecutionFailed(address(0), "Delay module not set");
        }

        IDelayModule(delayModule).cancelQueued(txHash);
    }

    /**
     * @notice Check if a transaction value requires delay
     * @param value The transaction value
     * @return True if delay is required
     */
    function _requiresDelay(uint256 value) internal view returns (bool) {
        if (delayModule == address(0)) {
            return false;
        }
        return IDelayModule(delayModule).requiresDelay(address(this), value);
    }

    /**
     * @inheritdoc IMpcSmartAccount
     */
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external payable onlyEntryPoint returns (bytes[] memory returnDatas) {
        uint256 length = targets.length;
        if (length != values.length || length != datas.length) {
            revert InvalidArrayLength();
        }

        // Check total value for spending limit
        uint256 totalValue = 0;
        for (uint256 i = 0; i < length; i++) {
            totalValue += values[i];
        }

        // If using a session key, validate against session key restrictions
        if (_currentSessionKeySigner != address(0) && sessionKeyModule != address(0)) {
            for (uint256 i = 0; i < length; i++) {
                ISessionKeyModule(sessionKeyModule).validateAndRecordSpending(
                    address(this), _currentSessionKeySigner, targets[i], values[i], datas[i]
                );
            }
            // Clear session key signer after use
            _currentSessionKeySigner = address(0);
        } else {
            // Check policies for MPC-signed batch
            for (uint256 i = 0; i < length; i++) {
                _checkPolicies(targets[i], values[i]);
            }
            // Record total spending
            _recordSpending(totalValue);
        }

        returnDatas = new bytes[](length);

        for (uint256 i = 0; i < length; i++) {
            bool success;
            (success, returnDatas[i]) = targets[i].call{ value: values[i] }(datas[i]);

            if (!success) {
                revert ExecutionFailed(targets[i], returnDatas[i]);
            }
        }

        emit TransactionBatchExecuted(targets, values, datas);
    }

    /*//////////////////////////////////////////////////////////////
                          MPC KEY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IMpcSmartAccount
     */
    function mpcPublicKey() external view returns (bytes memory) {
        return _mpcPublicKey;
    }

    /**
     * @inheritdoc IMpcSmartAccount
     * @dev Only callable by recovery module
     */
    function updateMpcPublicKey(
        bytes calldata newPublicKey
    ) external onlySelfOrRecovery {
        if (newPublicKey.length != 33) {
            revert InvalidMpcPublicKey();
        }

        bytes memory oldKey = _mpcPublicKey;
        _mpcPublicKey = newPublicKey;

        emit MpcPublicKeyUpdated(oldKey, newPublicKey);
    }

    /*//////////////////////////////////////////////////////////////
                          POLICY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IMpcSmartAccount
     */
    function isWhitelisted(
        address target
    ) external view returns (bool) {
        return _whitelist[target];
    }

    /**
     * @inheritdoc IMpcSmartAccount
     */
    function setWhitelist(address target, bool allowed) external onlySelfOrRecovery {
        _whitelist[target] = allowed;
        emit WhitelistUpdated(target, allowed);
    }

    /**
     * @inheritdoc IMpcSmartAccount
     */
    function setWhitelistBatch(address[] calldata targets, bool[] calldata allowed) external onlySelfOrRecovery {
        if (targets.length != allowed.length) {
            revert InvalidArrayLength();
        }

        for (uint256 i = 0; i < targets.length; i++) {
            _whitelist[targets[i]] = allowed[i];
            emit WhitelistUpdated(targets[i], allowed[i]);
        }
    }

    /**
     * @notice Enable or disable whitelist enforcement
     * @param enabled Whether whitelist should be enforced
     */
    function setWhitelistEnabled(
        bool enabled
    ) external onlySelfOrRecovery {
        whitelistEnabled = enabled;
    }

    /**
     * @inheritdoc IMpcSmartAccount
     */
    function dailyLimit() external view returns (uint256) {
        return _dailyLimit;
    }

    /**
     * @inheritdoc IMpcSmartAccount
     */
    function spentToday() external view returns (uint256) {
        if (block.timestamp >= _dailyResetTime) {
            return 0; // Period has reset
        }
        return _spentToday;
    }

    /**
     * @inheritdoc IMpcSmartAccount
     */
    function remainingDailyAllowance() external view returns (uint256) {
        if (_dailyLimit == 0) {
            return type(uint256).max; // No limit
        }

        uint256 spent = block.timestamp >= _dailyResetTime ? 0 : _spentToday;

        if (spent >= _dailyLimit) {
            return 0;
        }

        return _dailyLimit - spent;
    }

    /**
     * @inheritdoc IMpcSmartAccount
     */
    function setDailyLimit(
        uint256 newLimit
    ) external onlySelfOrRecovery {
        uint256 oldLimit = _dailyLimit;
        _dailyLimit = newLimit;
        emit DailyLimitUpdated(oldLimit, newLimit);
    }

    /**
     * @notice Configure time restrictions
     * @param startHour Start hour (0-23, UTC)
     * @param endHour End hour (0-23, UTC)
     * @param enabled Whether restrictions are active
     */
    function setTimeRestrictions(uint8 startHour, uint8 endHour, bool enabled) external onlySelfOrRecovery {
        require(startHour < 24 && endHour < 24, "Invalid hour");
        _timeRestrictionStart = startHour;
        _timeRestrictionEnd = endHour;
        _timeRestrictionsEnabled = enabled;
    }

    /**
     * @inheritdoc IMpcSmartAccount
     */
    function getTimeRestrictions() external view returns (uint8 startHour, uint8 endHour, bool enabled) {
        return (_timeRestrictionStart, _timeRestrictionEnd, _timeRestrictionsEnabled);
    }

    /*//////////////////////////////////////////////////////////////
                               GETTERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IMpcSmartAccount
     */
    function entryPoint() external view returns (address) {
        return address(_entryPoint);
    }

    /**
     * @inheritdoc IMpcSmartAccount
     */
    function getNonce(
        uint192 key
    ) external view returns (uint256) {
        return _entryPoint.getNonce(address(this), key);
    }

    /**
     * @notice Get the MPC address derived from public key
     * @return The address that can sign for this account
     */
    function getMpcAddress() external view returns (address) {
        return _publicKeyToAddress(_mpcPublicKey);
    }

    /**
     * @notice Get the current session key signer (set during validation)
     * @dev This is only valid between validateUserOp and execute calls
     * @return The session key signer address, or zero if not using session key
     */
    function getCurrentSessionKeySigner() external view returns (address) {
        return _currentSessionKeySigner;
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check all policies before execution
     */
    function _checkPolicies(address target, uint256 value) internal view {
        // Check whitelist
        if (whitelistEnabled && !_whitelist[target]) {
            revert NotWhitelisted(target);
        }

        // Check spending limit
        if (_dailyLimit > 0 && value > 0) {
            uint256 spent = block.timestamp >= _dailyResetTime ? 0 : _spentToday;
            uint256 remaining = _dailyLimit > spent ? _dailyLimit - spent : 0;

            if (value > remaining) {
                revert DailyLimitExceeded(value, remaining);
            }
        }

        // Check time restrictions
        if (_timeRestrictionsEnabled) {
            uint8 currentHour = uint8((block.timestamp / 1 hours) % 24);

            bool inAllowedWindow;
            if (_timeRestrictionStart <= _timeRestrictionEnd) {
                // Normal window (e.g., 9-17)
                inAllowedWindow = currentHour >= _timeRestrictionStart && currentHour < _timeRestrictionEnd;
            } else {
                // Overnight window (e.g., 22-6)
                inAllowedWindow = currentHour >= _timeRestrictionStart || currentHour < _timeRestrictionEnd;
            }

            if (!inAllowedWindow) {
                revert TimeRestrictionViolated();
            }
        }
    }

    /**
     * @notice Record spending and reset period if needed
     */
    function _recordSpending(
        uint256 value
    ) internal {
        if (value == 0) return;

        // Reset period if needed
        if (block.timestamp >= _dailyResetTime) {
            _spentToday = 0;
            _dailyResetTime = block.timestamp + DAILY_PERIOD;
        }

        _spentToday += value;
    }

    /*//////////////////////////////////////////////////////////////
                              UPGRADES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Authorize upgrade (UUPS)
     * @dev Only callable by self (via EntryPoint) or recovery module
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlySelfOrRecovery {
        // Additional checks can be added here
        (newImplementation); // Silence unused variable warning
    }

    /*//////////////////////////////////////////////////////////////
                    ERC-7579 ACCOUNT CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IERC7579AccountConfig
     * @dev Returns the unique identifier for this account implementation
     */
    function accountId() external pure override returns (string memory) {
        return ACCOUNT_ID;
    }

    /**
     * @inheritdoc IERC7579AccountConfig
     * @dev Supports default (single call) and batch execution modes
     *      Delegatecall is explicitly not supported for security
     */
    function supportsExecutionMode(bytes32 mode) external pure override returns (bool) {
        return mode == EXEC_MODE_DEFAULT || mode == EXEC_MODE_BATCH || mode == EXEC_MODE_TRY;
    }

    /**
     * @inheritdoc IERC7579AccountConfig
     * @dev Supports all four ERC-7579 module types:
     *      1 = Validator, 2 = Executor, 3 = Fallback, 4 = Hook
     */
    function supportsModule(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId >= ERC7579ModuleTypes.MODULE_TYPE_VALIDATOR
            && moduleTypeId <= ERC7579ModuleTypes.MODULE_TYPE_HOOK;
    }

    /*//////////////////////////////////////////////////////////////
                    ERC-7579 MODULE CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IERC7579ModuleConfig
     * @dev Installs a module on this account
     *      - Type 1 (Validator): Added to validator set
     *      - Type 2 (Executor): Added to executor set
     *      - Type 3 (Fallback): Registered for specific selectors (decoded from initData)
     *      - Type 4 (Hook): Added to hook set
     */
    function installModule(
        uint256 moduleTypeId,
        address module,
        bytes calldata initData
    ) external override onlySelfOrRecovery {
        if (module == address(0)) {
            revert InvalidModuleAddress();
        }

        // Verify module supports the claimed type
        if (!IERC7579Module(module).isModuleType(moduleTypeId)) {
            revert UnsupportedModuleType(moduleTypeId);
        }

        if (moduleTypeId == ERC7579ModuleTypes.MODULE_TYPE_VALIDATOR) {
            _installValidator(module, initData);
        } else if (moduleTypeId == ERC7579ModuleTypes.MODULE_TYPE_EXECUTOR) {
            _installExecutor(module, initData);
        } else if (moduleTypeId == ERC7579ModuleTypes.MODULE_TYPE_FALLBACK) {
            _installFallbackHandler(module, initData);
        } else if (moduleTypeId == ERC7579ModuleTypes.MODULE_TYPE_HOOK) {
            _installHook(module, initData);
        } else {
            revert UnsupportedModuleType(moduleTypeId);
        }

        emit ModuleInstalled(moduleTypeId, module);
    }

    /**
     * @inheritdoc IERC7579ModuleConfig
     * @dev Uninstalls a module from this account
     */
    function uninstallModule(
        uint256 moduleTypeId,
        address module,
        bytes calldata deInitData
    ) external override onlySelfOrRecovery {
        if (module == address(0)) {
            revert InvalidModuleAddress();
        }

        if (moduleTypeId == ERC7579ModuleTypes.MODULE_TYPE_VALIDATOR) {
            _uninstallValidator(module, deInitData);
        } else if (moduleTypeId == ERC7579ModuleTypes.MODULE_TYPE_EXECUTOR) {
            _uninstallExecutor(module, deInitData);
        } else if (moduleTypeId == ERC7579ModuleTypes.MODULE_TYPE_FALLBACK) {
            _uninstallFallbackHandler(module, deInitData);
        } else if (moduleTypeId == ERC7579ModuleTypes.MODULE_TYPE_HOOK) {
            _uninstallHook(module, deInitData);
        } else {
            revert UnsupportedModuleType(moduleTypeId);
        }

        emit ModuleUninstalled(moduleTypeId, module);
    }

    /**
     * @inheritdoc IERC7579ModuleConfig
     * @dev For fallback handlers, additionalContext should contain the selector (bytes4)
     */
    function isModuleInstalled(
        uint256 moduleTypeId,
        address module,
        bytes calldata additionalContext
    ) external view override returns (bool) {
        if (moduleTypeId == ERC7579ModuleTypes.MODULE_TYPE_VALIDATOR) {
            return _installedValidators[module];
        } else if (moduleTypeId == ERC7579ModuleTypes.MODULE_TYPE_EXECUTOR) {
            return _installedExecutors[module];
        } else if (moduleTypeId == ERC7579ModuleTypes.MODULE_TYPE_FALLBACK) {
            if (additionalContext.length >= 4) {
                bytes4 selector = bytes4(additionalContext[:4]);
                return _fallbackHandlers[selector] == module;
            }
            return false;
        } else if (moduleTypeId == ERC7579ModuleTypes.MODULE_TYPE_HOOK) {
            return _installedHooks[module];
        }
        return false;
    }

    /*//////////////////////////////////////////////////////////////
                    MODULE INSTALLATION INTERNALS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Install a validator module
     * @param module The validator module address
     * @param initData Initialization data for the module
     */
    function _installValidator(address module, bytes calldata initData) internal {
        if (_installedValidators[module]) {
            revert ModuleAlreadyInstalled(ERC7579ModuleTypes.MODULE_TYPE_VALIDATOR, module);
        }

        _installedValidators[module] = true;
        _validatorList.push(module);

        // Call module's onInstall
        IERC7579Module(module).onInstall(initData);
    }

    /**
     * @notice Uninstall a validator module
     * @param module The validator module address
     * @param deInitData Cleanup data for the module
     */
    function _uninstallValidator(address module, bytes calldata deInitData) internal {
        if (!_installedValidators[module]) {
            revert ModuleNotInstalled(ERC7579ModuleTypes.MODULE_TYPE_VALIDATOR, module);
        }

        _installedValidators[module] = false;
        _removeFromArray(_validatorList, module);

        // Call module's onUninstall
        IERC7579Module(module).onUninstall(deInitData);
    }

    /**
     * @notice Install an executor module
     * @param module The executor module address
     * @param initData Initialization data for the module
     */
    function _installExecutor(address module, bytes calldata initData) internal {
        if (_installedExecutors[module]) {
            revert ModuleAlreadyInstalled(ERC7579ModuleTypes.MODULE_TYPE_EXECUTOR, module);
        }

        _installedExecutors[module] = true;
        _executorList.push(module);

        // Call module's onInstall
        IERC7579Module(module).onInstall(initData);
    }

    /**
     * @notice Uninstall an executor module
     * @param module The executor module address
     * @param deInitData Cleanup data for the module
     */
    function _uninstallExecutor(address module, bytes calldata deInitData) internal {
        if (!_installedExecutors[module]) {
            revert ModuleNotInstalled(ERC7579ModuleTypes.MODULE_TYPE_EXECUTOR, module);
        }

        _installedExecutors[module] = false;
        _removeFromArray(_executorList, module);

        // Call module's onUninstall
        IERC7579Module(module).onUninstall(deInitData);
    }

    /**
     * @notice Install a fallback handler module
     * @dev initData format: abi.encode(bytes4[] selectors)
     * @param module The fallback handler module address
     * @param initData Initialization data containing selectors to register
     */
    function _installFallbackHandler(address module, bytes calldata initData) internal {
        // Decode selectors from initData
        bytes4[] memory selectors = abi.decode(initData, (bytes4[]));

        for (uint256 i = 0; i < selectors.length; i++) {
            bytes4 selector = selectors[i];
            if (_fallbackHandlers[selector] != address(0)) {
                revert ModuleAlreadyInstalled(ERC7579ModuleTypes.MODULE_TYPE_FALLBACK, module);
            }
            _fallbackHandlers[selector] = module;
        }

        // Call module's onInstall with the original initData
        IERC7579Module(module).onInstall(initData);
    }

    /**
     * @notice Uninstall a fallback handler module
     * @dev deInitData format: abi.encode(bytes4[] selectors)
     * @param module The fallback handler module address
     * @param deInitData Cleanup data containing selectors to unregister
     */
    function _uninstallFallbackHandler(address module, bytes calldata deInitData) internal {
        // Decode selectors from deInitData
        bytes4[] memory selectors = abi.decode(deInitData, (bytes4[]));

        for (uint256 i = 0; i < selectors.length; i++) {
            bytes4 selector = selectors[i];
            if (_fallbackHandlers[selector] != module) {
                revert ModuleNotInstalled(ERC7579ModuleTypes.MODULE_TYPE_FALLBACK, module);
            }
            _fallbackHandlers[selector] = address(0);
        }

        // Call module's onUninstall
        IERC7579Module(module).onUninstall(deInitData);
    }

    /**
     * @notice Install a hook module
     * @param module The hook module address
     * @param initData Initialization data for the module
     */
    function _installHook(address module, bytes calldata initData) internal {
        if (_installedHooks[module]) {
            revert ModuleAlreadyInstalled(ERC7579ModuleTypes.MODULE_TYPE_HOOK, module);
        }

        _installedHooks[module] = true;
        _hookList.push(module);

        // Call module's onInstall
        IERC7579Module(module).onInstall(initData);
    }

    /**
     * @notice Uninstall a hook module
     * @param module The hook module address
     * @param deInitData Cleanup data for the module
     */
    function _uninstallHook(address module, bytes calldata deInitData) internal {
        if (!_installedHooks[module]) {
            revert ModuleNotInstalled(ERC7579ModuleTypes.MODULE_TYPE_HOOK, module);
        }

        _installedHooks[module] = false;
        _removeFromArray(_hookList, module);

        // Call module's onUninstall
        IERC7579Module(module).onUninstall(deInitData);
    }

    /**
     * @notice Remove an address from an array (swap and pop)
     * @param array The array to modify
     * @param element The element to remove
     */
    function _removeFromArray(address[] storage array, address element) internal {
        uint256 length = array.length;
        for (uint256 i = 0; i < length; i++) {
            if (array[i] == element) {
                array[i] = array[length - 1];
                array.pop();
                return;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                       MODULE ENUMERATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get all installed validator modules
     * @return Array of validator module addresses
     */
    function getInstalledValidators() external view returns (address[] memory) {
        return _validatorList;
    }

    /**
     * @notice Get all installed executor modules
     * @return Array of executor module addresses
     */
    function getInstalledExecutors() external view returns (address[] memory) {
        return _executorList;
    }

    /**
     * @notice Get all installed hook modules
     * @return Array of hook module addresses
     */
    function getInstalledHooks() external view returns (address[] memory) {
        return _hookList;
    }

    /**
     * @notice Get the fallback handler for a specific selector
     * @param selector The function selector
     * @return The handler module address (or zero if none)
     */
    function getFallbackHandler(bytes4 selector) external view returns (address) {
        return _fallbackHandlers[selector];
    }

    /*//////////////////////////////////////////////////////////////
                             FALLBACK
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive ETH
     */
    receive() external payable { }

    /**
     * @notice Fallback for unknown function calls
     * @dev Routes to installed fallback handler modules if one exists for the selector
     */
    fallback() external payable {
        bytes4 selector = msg.sig;
        address handler = _fallbackHandlers[selector];

        if (handler != address(0)) {
            // Delegate to fallback handler
            assembly {
                // Copy calldata to memory
                calldatacopy(0, 0, calldatasize())

                // Call the handler with the calldata
                let result := call(gas(), handler, callvalue(), 0, calldatasize(), 0, 0)

                // Copy return data
                returndatacopy(0, 0, returndatasize())

                switch result
                case 0 { revert(0, returndatasize()) }
                default { return(0, returndatasize()) }
            }
        }
        // If no handler, just accept the call (no-op)
    }
}
