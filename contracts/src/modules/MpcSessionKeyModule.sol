// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ISessionKeyModule } from "../interfaces/ISessionKeyModule.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";

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

    /// @notice EIP-712 domain separator typehash for ERC-7715
    bytes32 public constant ERC7715_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /// @notice Permission context typehash for ERC-7715
    bytes32 public constant PERMISSION_CONTEXT_TYPEHASH = keccak256(
        "PermissionContext(bytes32 permissionId,address signer,address account,uint256 chainId,uint48 expiry,uint256 nativeAllowance,bytes32 whitelistHash,bytes32 selectorsHash)"
    );

    /// @notice EIP-1271 magic value for valid signature
    bytes4 internal constant EIP1271_SUCCESS = 0x1626ba7e;

    /*//////////////////////////////////////////////////////////////
                       ERC-7715 PERMISSION STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice ERC-7715 permission context structure
     * @param permissionId Unique identifier for the permission
     * @param signer Authorized signer address (AI agent EOA)
     * @param account Smart account address
     * @param chainId Chain ID this permission is valid on
     * @param expiry Timestamp when permission expires
     * @param nativeAllowance Native token spending allowance
     * @param whitelist Allowed target addresses
     * @param selectors Allowed function selectors
     * @param signature Account's signature over the permission
     */
    struct ERC7715PermissionContext {
        bytes32 permissionId;
        address signer;
        address account;
        uint256 chainId;
        uint48 expiry;
        uint256 nativeAllowance;
        address[] whitelist;
        bytes4[] selectors;
        bytes signature;
    }

    /*//////////////////////////////////////////////////////////////
                        ERC-7715 SPECIFIC EVENTS
    //////////////////////////////////////////////////////////////*/

    event ERC7715PermissionValidated(
        address indexed account,
        bytes32 indexed permissionId,
        address indexed signer
    );

    event SessionKeyFromPermission(
        address indexed account,
        address indexed signer,
        bytes32 indexed permissionId
    );

    /*//////////////////////////////////////////////////////////////
                        ERC-7715 SPECIFIC ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidPermissionContext();
    error PermissionChainMismatch();
    error PermissionExpired();
    error InvalidPermissionSignature();

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Session keys per account (account => signer => SessionKey)
    mapping(address => mapping(address => SessionKey)) internal _sessionKeys;

    /// @notice List of session key signers per account (for enumeration)
    mapping(address => address[]) internal _sessionKeyList;

    /// @notice Index of signer in the list (account => signer => index + 1, 0 means not in list)
    mapping(address => mapping(address => uint256)) internal _sessionKeyIndex;

    /// @notice ERC-7715 permission IDs mapped to session keys (account => permissionId => signer)
    mapping(address => mapping(bytes32 => address)) internal _permissionToSigner;

    /// @notice Cached domain separator
    bytes32 internal _cachedDomainSeparator;

    /// @notice Cached chain ID
    uint256 internal _cachedChainId;

    /// @notice Whether domain separator is initialized
    bool internal _domainInitialized;

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

    /*//////////////////////////////////////////////////////////////
                    ERC-7715 PERMISSION CONTEXT FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a session key from an ERC-7715 permission context
     * @dev This function validates the permission context and creates
     *      a corresponding session key for the authorized signer.
     *
     * The permission context is decoded and validated:
     * - Chain ID must match current chain
     * - Permission must not be expired
     * - Signature must be valid (from account or via EIP-1271)
     *
     * @param permissionContext Encoded ERC-7715 permission context
     */
    function createSessionKeyFromPermission(
        bytes calldata permissionContext
    ) external {
        ERC7715PermissionContext memory ctx = _decodePermissionContext(permissionContext);

        // Validate the permission context
        _validatePermissionContext(ctx);

        // Check if session key already exists for this permission
        if (_permissionToSigner[ctx.account][ctx.permissionId] != address(0)) {
            revert SessionKeyAlreadyExists();
        }

        // Create session key params from permission context
        SessionKeyParams memory params = SessionKeyParams({
            signer: ctx.signer,
            validAfter: uint48(block.timestamp),
            validUntil: ctx.expiry,
            spendingLimit: ctx.nativeAllowance,
            whitelist: ctx.whitelist,
            selectors: ctx.selectors
        });

        // Store session key
        _sessionKeys[ctx.account][ctx.signer] = SessionKey({
            signer: ctx.signer,
            validAfter: params.validAfter,
            validUntil: params.validUntil,
            spendingLimit: params.spendingLimit,
            spent: 0,
            whitelist: params.whitelist,
            selectors: params.selectors,
            revoked: false
        });

        // Link permission ID to signer
        _permissionToSigner[ctx.account][ctx.permissionId] = ctx.signer;

        // Add to list if not already present
        if (_sessionKeyIndex[ctx.account][ctx.signer] == 0) {
            _sessionKeyList[ctx.account].push(ctx.signer);
            _sessionKeyIndex[ctx.account][ctx.signer] = _sessionKeyList[ctx.account].length;
        }

        emit SessionKeyCreated(
            ctx.account,
            ctx.signer,
            params.validAfter,
            params.validUntil,
            params.spendingLimit
        );

        emit SessionKeyFromPermission(ctx.account, ctx.signer, ctx.permissionId);
    }

    /**
     * @notice Validate an ERC-7715 permission context
     * @dev Verifies the context is properly signed and not expired
     * @param permissionContext Encoded ERC-7715 permission context
     * @return ctx The decoded and validated permission context
     */
    function validatePermissionContext(
        bytes calldata permissionContext
    ) external view returns (ERC7715PermissionContext memory ctx) {
        ctx = _decodePermissionContext(permissionContext);
        _validatePermissionContextView(ctx);
        return ctx;
    }

    /**
     * @notice Get the session key signer associated with a permission ID
     * @param account The smart account address
     * @param permissionId The ERC-7715 permission ID
     * @return The signer address (or zero if not found)
     */
    function getSignerForPermission(
        address account,
        bytes32 permissionId
    ) external view returns (address) {
        return _permissionToSigner[account][permissionId];
    }

    /**
     * @notice Revoke a session key by permission ID
     * @param permissionId The ERC-7715 permission ID
     */
    function revokeSessionKeyByPermission(
        bytes32 permissionId
    ) external {
        address account = msg.sender;
        address signer = _permissionToSigner[account][permissionId];

        if (signer == address(0)) {
            revert SessionKeyNotFound();
        }

        SessionKey storage sessionKey = _sessionKeys[account][signer];
        sessionKey.revoked = true;

        emit SessionKeyRevoked(account, signer);
    }

    /**
     * @notice Encode a permission context for off-chain use
     * @dev Helper function to encode permission context in the expected format
     * @param ctx The permission context to encode
     * @return The encoded permission context bytes
     */
    function encodePermissionContext(
        ERC7715PermissionContext calldata ctx
    ) external pure returns (bytes memory) {
        return abi.encode(
            ctx.permissionId,
            ctx.signer,
            ctx.account,
            ctx.chainId,
            ctx.expiry,
            ctx.nativeAllowance,
            ctx.whitelist,
            ctx.selectors,
            ctx.signature
        );
    }

    /**
     * @notice Get the hash that needs to be signed for a permission context
     * @dev Used by the wallet to sign permission contexts
     * @param ctx The permission context (without signature)
     * @return The EIP-712 digest to sign
     */
    function getPermissionContextHash(
        ERC7715PermissionContext calldata ctx
    ) external view returns (bytes32) {
        return _computePermissionDigest(ctx);
    }

    /*//////////////////////////////////////////////////////////////
                    ERC-7715 INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Decode permission context from bytes
     * @param permissionContext Encoded permission context
     * @return ctx Decoded permission context
     */
    function _decodePermissionContext(
        bytes calldata permissionContext
    ) internal pure returns (ERC7715PermissionContext memory ctx) {
        (
            ctx.permissionId,
            ctx.signer,
            ctx.account,
            ctx.chainId,
            ctx.expiry,
            ctx.nativeAllowance,
            ctx.whitelist,
            ctx.selectors,
            ctx.signature
        ) = abi.decode(
            permissionContext,
            (bytes32, address, address, uint256, uint48, uint256, address[], bytes4[], bytes)
        );

        return ctx;
    }

    /**
     * @notice Validate permission context (state-changing version)
     * @param ctx The permission context to validate
     */
    function _validatePermissionContext(
        ERC7715PermissionContext memory ctx
    ) internal {
        // Initialize domain separator if needed
        if (!_domainInitialized) {
            _cachedChainId = block.chainid;
            _cachedDomainSeparator = _computeDomainSeparator();
            _domainInitialized = true;
        }

        // Verify chain ID
        if (ctx.chainId != block.chainid) {
            revert PermissionChainMismatch();
        }

        // Check not expired
        if (block.timestamp > ctx.expiry) {
            revert PermissionExpired();
        }

        // Check expiry is within max duration
        if (ctx.expiry > block.timestamp + MAX_SESSION_DURATION) {
            revert InvalidSessionKeyParams();
        }

        // Verify signature
        _verifyPermissionSignature(ctx);

        emit ERC7715PermissionValidated(ctx.account, ctx.permissionId, ctx.signer);
    }

    /**
     * @notice Validate permission context (view version)
     * @param ctx The permission context to validate
     */
    function _validatePermissionContextView(
        ERC7715PermissionContext memory ctx
    ) internal view {
        // Verify chain ID
        if (ctx.chainId != block.chainid) {
            revert PermissionChainMismatch();
        }

        // Check not expired
        if (block.timestamp > ctx.expiry) {
            revert PermissionExpired();
        }

        // Verify signature (view version)
        _verifyPermissionSignatureView(ctx);
    }

    /**
     * @notice Verify the signature over the permission context
     * @param ctx The permission context with signature
     */
    function _verifyPermissionSignature(
        ERC7715PermissionContext memory ctx
    ) internal view {
        bytes32 digest = _computePermissionDigest(ctx);

        // Try ECDSA recovery first
        (address recovered, ECDSA.RecoverError error,) = ECDSA.tryRecover(digest, ctx.signature);

        if (error == ECDSA.RecoverError.NoError && recovered == ctx.account) {
            return; // Valid ECDSA signature
        }

        // Try EIP-1271 validation for smart accounts
        try IERC1271(ctx.account).isValidSignature(digest, ctx.signature) returns (bytes4 magicValue) {
            if (magicValue == EIP1271_SUCCESS) {
                return; // Valid EIP-1271 signature
            }
        } catch {
            // EIP-1271 call failed
        }

        revert InvalidPermissionSignature();
    }

    /**
     * @notice Verify signature (view version without try-catch side effects)
     * @param ctx The permission context with signature
     */
    function _verifyPermissionSignatureView(
        ERC7715PermissionContext memory ctx
    ) internal view {
        bytes32 digest = _computePermissionDigest(ctx);

        // Try ECDSA recovery first
        (address recovered, ECDSA.RecoverError error,) = ECDSA.tryRecover(digest, ctx.signature);

        if (error == ECDSA.RecoverError.NoError && recovered == ctx.account) {
            return;
        }

        // Try EIP-1271 validation
        (bool success, bytes memory result) = ctx.account.staticcall(
            abi.encodeWithSelector(IERC1271.isValidSignature.selector, digest, ctx.signature)
        );

        if (success && result.length >= 32) {
            bytes4 magicValue = abi.decode(result, (bytes4));
            if (magicValue == EIP1271_SUCCESS) {
                return;
            }
        }

        revert InvalidPermissionSignature();
    }

    /**
     * @notice Compute the EIP-712 digest for a permission context
     * @param ctx The permission context
     * @return The digest to sign
     */
    function _computePermissionDigest(
        ERC7715PermissionContext memory ctx
    ) internal view returns (bytes32) {
        bytes32 whitelistHash = keccak256(abi.encodePacked(ctx.whitelist));
        bytes32 selectorsHash = keccak256(abi.encodePacked(ctx.selectors));

        bytes32 structHash = keccak256(
            abi.encode(
                PERMISSION_CONTEXT_TYPEHASH,
                ctx.permissionId,
                ctx.signer,
                ctx.account,
                ctx.chainId,
                ctx.expiry,
                ctx.nativeAllowance,
                whitelistHash,
                selectorsHash
            )
        );

        return keccak256(
            abi.encodePacked("\x19\x01", _domainSeparator(), structHash)
        );
    }

    /**
     * @notice Compute the EIP-712 domain separator
     * @return The domain separator
     */
    function _computeDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                ERC7715_DOMAIN_TYPEHASH,
                keccak256(bytes("MpcSessionKeyModule")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    /**
     * @notice Get the domain separator (handles chain ID changes)
     * @return The domain separator
     */
    function _domainSeparator() internal view returns (bytes32) {
        if (_domainInitialized && block.chainid == _cachedChainId) {
            return _cachedDomainSeparator;
        }
        return _computeDomainSeparator();
    }

    /**
     * @notice Get the current domain separator
     * @return The EIP-712 domain separator
     */
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }
}
