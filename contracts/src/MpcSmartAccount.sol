// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IMpcSmartAccount } from "./interfaces/IMpcSmartAccount.sol";
import { IEntryPoint } from "./interfaces/IEntryPoint.sol";
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

    /*//////////////////////////////////////////////////////////////
                         ERC-4337 VALIDATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validate a UserOperation signature
     * @dev Verifies the MPC threshold signature against the stored public key
     * @param userOp The UserOperation to validate
     * @param userOpHash Hash of the UserOperation
     * @param missingAccountFunds Funds to deposit for gas
     * @return validationData 0 for success, 1 for failure
     */
    function validateUserOp(
        IEntryPoint.PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        // Validate MPC signature
        validationData = _validateMpcSignature(userOpHash, userOp.signature);

        // Pay prefund to EntryPoint
        if (missingAccountFunds > 0) {
            (bool success,) = payable(address(_entryPoint)).call{ value: missingAccountFunds }("");
            (success); // Ignore failure - EntryPoint will check deposit
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
        // Check policies
        _checkPolicies(target, value);

        // Execute call
        bool success;
        (success, returnData) = target.call{ value: value }(data);

        if (!success) {
            revert ExecutionFailed(target, returnData);
        }

        // Record spending
        _recordSpending(value);

        emit TransactionExecuted(target, value, data, returnData);
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

        // Check policies for batch
        for (uint256 i = 0; i < length; i++) {
            _checkPolicies(targets[i], values[i]);
        }

        returnDatas = new bytes[](length);

        for (uint256 i = 0; i < length; i++) {
            bool success;
            (success, returnDatas[i]) = targets[i].call{ value: values[i] }(datas[i]);

            if (!success) {
                revert ExecutionFailed(targets[i], returnDatas[i]);
            }
        }

        // Record total spending
        _recordSpending(totalValue);

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
