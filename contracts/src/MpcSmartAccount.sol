// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IMpcSmartAccount } from "./interfaces/IMpcSmartAccount.sol";
import { IEntryPoint } from "./interfaces/IEntryPoint.sol";
import { ISessionKeyModule } from "./interfaces/ISessionKeyModule.sol";
import { IDelayModule } from "./interfaces/IDelayModule.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title MpcSmartAccount
 * @author MPC Agent Wallet SDK
 * @notice ERC-4337 smart account secured by MPC threshold signatures
 *
 * @dev Key features:
 *      - 2-of-3 threshold MPC signature validation
 *      - Built-in spending limits and whitelisting
 *      - Time-based transaction restrictions
 *      - Upgradeable via UUPS pattern
 *      - EIP-1271 signature validation
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
contract MpcSmartAccount is IMpcSmartAccount, IERC1271, Initializable, UUPSUpgradeable {
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
                             FALLBACK
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive ETH
     */
    receive() external payable { }

    /**
     * @notice Fallback for unknown function calls
     */
    fallback() external payable { }
}
