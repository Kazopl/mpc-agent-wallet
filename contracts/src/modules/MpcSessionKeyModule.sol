// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ISessionKeyModule } from "../interfaces/ISessionKeyModule.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title MpcSessionKeyModule
 * @author MPC Agent Wallet SDK
 * @notice Session key management module for MPC smart accounts
 *
 * @dev Key features:
 *      - Time-bound session keys with start and expiry timestamps
 *      - Per-session spending limits
 *      - Target address whitelisting
 *      - Function selector restrictions
 *      - Revocation support
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                      SESSION KEY ARCHITECTURE                                │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │   Session Key Creation:                                                     │
 * │   ┌──────────────────┐                                                      │
 * │   │   MPC Signature  │  (from 2-of-3 threshold)                             │
 * │   │   via UserOp     │───────────────────────────────────────►              │
 * │   └──────────────────┘                                        │             │
 * │                                                               ▼             │
 * │                                                  ┌─────────────────────────┐│
 * │                                                  │  createSessionKey()     ││
 * │                                                  │                         ││
 * │                                                  │  - Store session key    ││
 * │                                                  │  - Set time bounds      ││
 * │                                                  │  - Set spending limit   ││
 * │                                                  │  - Set whitelist        ││
 * │                                                  └─────────────────────────┘│
 * │                                                                             │
 * │   Session Key Usage:                                                        │
 * │   ┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐ │
 * │   │   AI Agent       │      │  Session Key     │      │   Smart Account  │ │
 * │   │   signs UserOp   │─────►│  Module checks:  │─────►│   executes tx    │ │
 * │   │   with session   │      │  - Time valid    │      │                  │ │
 * │   │   key EOA        │      │  - Spend limit   │      │                  │ │
 * │   └──────────────────┘      │  - Whitelist     │      └──────────────────┘ │
 * │                             │  - Selectors     │                            │
 * │                             └──────────────────┘                            │
 * │                                                                             │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * Security Model:
 * - Session keys provide scoped delegation without exposing MPC key shares
 * - Time bounds ensure automatic expiration
 * - Spending limits prevent excessive fund usage
 * - Whitelist restricts interaction targets
 * - Selector restrictions limit callable functions
 * - Revocation allows immediate key invalidation
 */
contract MpcSessionKeyModule is ISessionKeyModule {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC-4337 signature validation success
    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;

    /// @notice ERC-4337 signature validation failure
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    /// @notice Maximum session key duration (30 days)
    uint256 public constant MAX_SESSION_DURATION = 30 days;

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Session keys per account (account => signer => SessionKey)
    mapping(address => mapping(address => SessionKey)) internal _sessionKeys;

    /// @notice List of session key signers per account (for enumeration)
    mapping(address => address[]) internal _sessionKeyList;

    /// @notice Index of signer in the list (account => signer => index + 1, 0 means not in list)
    mapping(address => mapping(address => uint256)) internal _sessionKeyIndex;

    /*//////////////////////////////////////////////////////////////
                          SESSION KEY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc ISessionKeyModule
     */
    function createSessionKey(
        SessionKeyParams calldata params
    ) external {
        address account = msg.sender;

        // Validate params
        if (params.signer == address(0)) {
            revert InvalidSessionKeyParams();
        }
        if (params.validUntil <= params.validAfter) {
            revert InvalidSessionKeyParams();
        }
        if (params.validUntil <= block.timestamp) {
            revert InvalidSessionKeyParams();
        }
        if (params.validUntil > block.timestamp + MAX_SESSION_DURATION) {
            revert InvalidSessionKeyParams();
        }

        // Check if session key already exists and is not revoked
        SessionKey storage existing = _sessionKeys[account][params.signer];
        if (existing.signer != address(0) && !existing.revoked && existing.validUntil > block.timestamp) {
            revert SessionKeyAlreadyExists();
        }

        // Create session key
        _sessionKeys[account][params.signer] = SessionKey({
            signer: params.signer,
            validAfter: params.validAfter,
            validUntil: params.validUntil,
            spendingLimit: params.spendingLimit,
            spent: 0,
            whitelist: params.whitelist,
            selectors: params.selectors,
            revoked: false
        });

        // Add to list if not already present
        if (_sessionKeyIndex[account][params.signer] == 0) {
            _sessionKeyList[account].push(params.signer);
            _sessionKeyIndex[account][params.signer] = _sessionKeyList[account].length;
        }

        emit SessionKeyCreated(
            account, params.signer, params.validAfter, params.validUntil, params.spendingLimit
        );
    }

    /**
     * @inheritdoc ISessionKeyModule
     */
    function revokeSessionKey(
        address signer
    ) external {
        address account = msg.sender;

        SessionKey storage sessionKey = _sessionKeys[account][signer];
        if (sessionKey.signer == address(0)) {
            revert SessionKeyNotFound();
        }

        sessionKey.revoked = true;

        emit SessionKeyRevoked(account, signer);
    }

    /**
     * @inheritdoc ISessionKeyModule
     */
    function updateWhitelist(address signer, address[] calldata whitelist) external {
        address account = msg.sender;

        SessionKey storage sessionKey = _sessionKeys[account][signer];
        if (sessionKey.signer == address(0)) {
            revert SessionKeyNotFound();
        }
        if (sessionKey.revoked) {
            revert SessionKeyIsRevoked();
        }

        sessionKey.whitelist = whitelist;

        emit SessionKeyWhitelistUpdated(account, signer, whitelist);
    }

    /**
     * @inheritdoc ISessionKeyModule
     */
    function updateSelectors(address signer, bytes4[] calldata selectors) external {
        address account = msg.sender;

        SessionKey storage sessionKey = _sessionKeys[account][signer];
        if (sessionKey.signer == address(0)) {
            revert SessionKeyNotFound();
        }
        if (sessionKey.revoked) {
            revert SessionKeyIsRevoked();
        }

        sessionKey.selectors = selectors;

        emit SessionKeySelectorsUpdated(account, signer, selectors);
    }

    /*//////////////////////////////////////////////////////////////
                             VALIDATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc ISessionKeyModule
     * @dev Returns packed validation data per ERC-4337:
     *      - Bits 0-159: aggregator address (0 for none)
     *      - Bits 160-207: validUntil (6 bytes)
     *      - Bits 208-255: validAfter (6 bytes)
     *      If signature is invalid, return SIG_VALIDATION_FAILED
     */
    function validateSessionKey(
        address account,
        bytes32 userOpHash,
        bytes calldata signature
    ) external view returns (uint256 validationData) {
        // Extract signer from signature (first 20 bytes indicate the session key signer)
        // Signature format: [signer address (20 bytes)][ECDSA signature (65 bytes)]
        if (signature.length < 85) {
            return SIG_VALIDATION_FAILED;
        }

        address signer = address(bytes20(signature[:20]));
        bytes memory ecdsaSig = signature[20:85];

        // Get session key
        SessionKey storage sessionKey = _sessionKeys[account][signer];

        // Check if session key exists
        if (sessionKey.signer == address(0)) {
            return SIG_VALIDATION_FAILED;
        }

        // Check if revoked
        if (sessionKey.revoked) {
            return SIG_VALIDATION_FAILED;
        }

        // Verify ECDSA signature
        bytes32 ethSignedHash = userOpHash.toEthSignedMessageHash();
        (address recovered, ECDSA.RecoverError error,) = ethSignedHash.tryRecover(ecdsaSig);

        if (error != ECDSA.RecoverError.NoError || recovered != signer) {
            return SIG_VALIDATION_FAILED;
        }

        // Pack validation data with time bounds
        // validationData = (validAfter << 208) | (validUntil << 160) | sigFailed
        uint256 validAfter = uint256(sessionKey.validAfter);
        uint256 validUntil = uint256(sessionKey.validUntil);

        return (validAfter << 208) | (validUntil << 160);
    }

    /**
     * @inheritdoc ISessionKeyModule
     * @dev Called by the smart account during execution to validate and record spending
     */
    function validateAndRecordSpending(
        address account,
        address signer,
        address target,
        uint256 value,
        bytes calldata data
    ) external {
        // Only callable by the account itself
        if (msg.sender != account) {
            revert OnlyAccountOwner();
        }

        SessionKey storage sessionKey = _sessionKeys[account][signer];

        // Check session key exists
        if (sessionKey.signer == address(0)) {
            revert SessionKeyNotFound();
        }

        // Check not revoked
        if (sessionKey.revoked) {
            revert SessionKeyIsRevoked();
        }

        // Check time bounds
        if (block.timestamp < sessionKey.validAfter) {
            revert SessionKeyNotYetValid();
        }
        if (block.timestamp > sessionKey.validUntil) {
            revert SessionKeyExpired();
        }

        // Check whitelist (if set)
        if (sessionKey.whitelist.length > 0) {
            bool allowed = false;
            for (uint256 i = 0; i < sessionKey.whitelist.length; i++) {
                if (sessionKey.whitelist[i] == target) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                revert SessionKeyTargetNotWhitelisted(target);
            }
        }

        // Check selectors (if set and data is present)
        if (sessionKey.selectors.length > 0 && data.length >= 4) {
            bytes4 selector = bytes4(data[:4]);
            bool allowed = false;
            for (uint256 i = 0; i < sessionKey.selectors.length; i++) {
                if (sessionKey.selectors[i] == selector) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                revert SessionKeySelectorNotAllowed(selector);
            }
        }

        // Check and record spending
        if (value > 0 && sessionKey.spendingLimit > 0) {
            uint256 remaining = sessionKey.spendingLimit - sessionKey.spent;
            if (value > remaining) {
                revert SessionKeySpendingLimitExceeded(value, remaining);
            }
            sessionKey.spent += value;

            emit SessionKeySpent(account, signer, value, sessionKey.spent);
        }
    }

    /*//////////////////////////////////////////////////////////////
                               GETTERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc ISessionKeyModule
     */
    function getSessionKey(address account, address signer) external view returns (SessionKey memory) {
        return _sessionKeys[account][signer];
    }

    /**
     * @inheritdoc ISessionKeyModule
     */
    function isSessionKeyValid(address account, address signer) external view returns (bool) {
        SessionKey storage sessionKey = _sessionKeys[account][signer];

        if (sessionKey.signer == address(0)) return false;
        if (sessionKey.revoked) return false;
        if (block.timestamp < sessionKey.validAfter) return false;
        if (block.timestamp > sessionKey.validUntil) return false;

        return true;
    }

    /**
     * @inheritdoc ISessionKeyModule
     */
    function getRemainingSpending(address account, address signer) external view returns (uint256) {
        SessionKey storage sessionKey = _sessionKeys[account][signer];

        if (sessionKey.signer == address(0)) return 0;
        if (sessionKey.revoked) return 0;
        if (sessionKey.spendingLimit == 0) return type(uint256).max;

        if (sessionKey.spent >= sessionKey.spendingLimit) return 0;
        return sessionKey.spendingLimit - sessionKey.spent;
    }

    /**
     * @inheritdoc ISessionKeyModule
     */
    function getActiveSessionKeys(
        address account
    ) external view returns (address[] memory) {
        address[] storage allKeys = _sessionKeyList[account];
        uint256 activeCount = 0;

        // Count active keys
        for (uint256 i = 0; i < allKeys.length; i++) {
            SessionKey storage sk = _sessionKeys[account][allKeys[i]];
            if (!sk.revoked && block.timestamp >= sk.validAfter && block.timestamp <= sk.validUntil) {
                activeCount++;
            }
        }

        // Collect active keys
        address[] memory activeKeys = new address[](activeCount);
        uint256 index = 0;
        for (uint256 i = 0; i < allKeys.length; i++) {
            SessionKey storage sk = _sessionKeys[account][allKeys[i]];
            if (!sk.revoked && block.timestamp >= sk.validAfter && block.timestamp <= sk.validUntil) {
                activeKeys[index] = allKeys[i];
                index++;
            }
        }

        return activeKeys;
    }

    /**
     * @inheritdoc ISessionKeyModule
     */
    function isTargetAllowed(address account, address signer, address target) external view returns (bool) {
        SessionKey storage sessionKey = _sessionKeys[account][signer];

        if (sessionKey.signer == address(0)) return false;

        // Empty whitelist means all targets allowed
        if (sessionKey.whitelist.length == 0) return true;

        for (uint256 i = 0; i < sessionKey.whitelist.length; i++) {
            if (sessionKey.whitelist[i] == target) {
                return true;
            }
        }

        return false;
    }

    /**
     * @inheritdoc ISessionKeyModule
     */
    function isSelectorAllowed(address account, address signer, bytes4 selector) external view returns (bool) {
        SessionKey storage sessionKey = _sessionKeys[account][signer];

        if (sessionKey.signer == address(0)) return false;

        // Empty selectors list means all selectors allowed
        if (sessionKey.selectors.length == 0) return true;

        for (uint256 i = 0; i < sessionKey.selectors.length; i++) {
            if (sessionKey.selectors[i] == selector) {
                return true;
            }
        }

        return false;
    }

    /**
     * @notice Extract session key signer from signature
     * @param signature The signature bytes
     * @return The session key signer address
     */
    function extractSigner(
        bytes calldata signature
    ) external pure returns (address) {
        if (signature.length < 20) return address(0);
        return address(bytes20(signature[:20]));
    }
}
