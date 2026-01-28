// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IERC7710 } from "./interfaces/IERC7710.sol";
import { ISessionKeyModule } from "./interfaces/ISessionKeyModule.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title ERC7710DelegationManager
 * @author MPC Agent Wallet SDK
 * @notice Delegation manager for ERC-7710 permission redemption
 *
 * @dev This contract bridges ERC-7715 permission grants with on-chain execution.
 *      It validates permission contexts and executes actions on behalf of
 *      smart accounts that have granted permissions.
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                    ERC-7710 DELEGATION MANAGER                              │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │   Permission Context Structure:                                             │
 * │   ┌─────────────────────────────────────────────────────────────────────┐  │
 * │   │  bytes32 permissionId    - Unique ID for this permission           │  │
 * │   │  address signer          - Authorized signer (AI agent EOA)        │  │
 * │   │  address account         - Smart account granting permission       │  │
 * │   │  uint256 chainId         - Chain this permission is valid on       │  │
 * │   │  uint48 expiry           - When permission expires                 │  │
 * │   │  uint256 nativeAllowance - ETH spending limit                      │  │
 * │   │  address[] whitelist     - Allowed targets (empty = all)           │  │
 * │   │  bytes4[] selectors      - Allowed selectors (empty = all)         │  │
 * │   │  bytes signature         - Account's signature over permission     │  │
 * │   └─────────────────────────────────────────────────────────────────────┘  │
 * │                                                                             │
 * │   Validation Flow:                                                          │
 * │   1. Decode permission context                                              │
 * │   2. Verify chain ID matches                                                │
 * │   3. Check permission not expired                                           │
 * │   4. Check permission not revoked                                           │
 * │   5. Verify caller is the authorized signer                                 │
 * │   6. Verify account signature over permission                               │
 * │   7. For each action:                                                       │
 * │      a. Check target is whitelisted                                         │
 * │      b. Check selector is allowed                                           │
 * │      c. Check spending limit                                                │
 * │   8. Execute actions via account                                            │
 * │                                                                             │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * Security Considerations:
 * - Permission context must be signed by the smart account
 * - Only the authorized signer can redeem delegations
 * - Spending limits are enforced per-permission
 * - Permissions can be revoked by the account at any time
 */
contract ERC7710DelegationManager is IERC7710 {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice EIP-712 domain separator typehash
    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /// @notice Permission context typehash for EIP-712 signing
    bytes32 public constant PERMISSION_TYPEHASH = keccak256(
        "Permission(bytes32 permissionId,address signer,address account,uint256 chainId,uint48 expiry,uint256 nativeAllowance,bytes32 whitelistHash,bytes32 selectorsHash)"
    );

    /// @notice Domain separator name
    string public constant NAME = "ERC7710DelegationManager";

    /// @notice Domain separator version
    string public constant VERSION = "1";

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Registered delegations (account => permissionId => DelegationState)
    mapping(address => mapping(bytes32 => DelegationState)) internal _delegations;

    /// @notice Session key module for additional validation
    address public sessionKeyModule;

    /// @notice Cached domain separator
    bytes32 internal immutable _cachedDomainSeparator;

    /// @notice Cached chain ID
    uint256 internal immutable _cachedChainId;

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Internal state for a registered delegation
     * @param signer Authorized signer address
     * @param expiry Expiry timestamp
     * @param nativeAllowance Original native token allowance
     * @param spent Amount of native token spent
     * @param registered Whether delegation is registered
     * @param revoked Whether delegation is revoked
     */
    struct DelegationState {
        address signer;
        uint48 expiry;
        uint256 nativeAllowance;
        uint256 spent;
        bool registered;
        bool revoked;
    }

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _sessionKeyModule) {
        sessionKeyModule = _sessionKeyModule;
        _cachedChainId = block.chainid;
        _cachedDomainSeparator = _computeDomainSeparator();
    }

    /*//////////////////////////////////////////////////////////////
                          DELEGATION MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IERC7710
     * @dev Only callable by the smart account itself
     */
    function registerDelegation(bytes calldata permissionContext) external {
        PermissionContext memory ctx = _decodePermissionContext(permissionContext);

        // Verify caller is the account
        if (msg.sender != ctx.account) {
            revert AccountMismatch();
        }

        // Verify chain ID
        if (ctx.chainId != block.chainid) {
            revert ChainMismatch();
        }

        // Check not already registered
        if (_delegations[ctx.account][ctx.permissionId].registered) {
            revert PermissionAlreadyRegistered();
        }

        // Verify signature over permission context
        _verifyPermissionSignature(ctx);

        // Register delegation
        _delegations[ctx.account][ctx.permissionId] = DelegationState({
            signer: ctx.signer,
            expiry: ctx.expiry,
            nativeAllowance: ctx.nativeAllowance,
            spent: 0,
            registered: true,
            revoked: false
        });

        emit DelegationRegistered(
            ctx.permissionId,
            ctx.account,
            ctx.signer,
            ctx.expiry
        );
    }

    /**
     * @inheritdoc IERC7710
     * @dev Only callable by the smart account or authorized signer
     */
    function revokeDelegation(bytes32 permissionId) external {
        // Find which account this permission belongs to
        // In practice, we'd need to know the account - using msg.sender as account
        address account = msg.sender;

        DelegationState storage delegation = _delegations[account][permissionId];

        if (!delegation.registered) {
            revert InvalidPermissionContext();
        }

        // Only account or signer can revoke
        if (msg.sender != account && msg.sender != delegation.signer) {
            revert OnlyAccountOrSigner();
        }

        delegation.revoked = true;

        emit DelegationRevoked(permissionId, account);
    }

    /**
     * @inheritdoc IERC7710
     */
    function redeemDelegation(
        bytes calldata permissionContext,
        Action[] calldata actions
    ) external returns (bytes[] memory results) {
        PermissionContext memory ctx = _decodePermissionContext(permissionContext);

        // Validate permission context
        _validatePermissionContext(ctx);

        // Get delegation state
        DelegationState storage delegation = _delegations[ctx.account][ctx.permissionId];

        // Calculate total value
        uint256 totalValue = 0;
        for (uint256 i = 0; i < actions.length; i++) {
            totalValue += actions[i].value;
        }

        // Check spending limit
        if (ctx.nativeAllowance > 0) {
            uint256 remaining = ctx.nativeAllowance - delegation.spent;
            if (totalValue > remaining) {
                revert SpendingLimitExceeded(totalValue, remaining);
            }
            delegation.spent += totalValue;
        }

        // Validate each action
        for (uint256 i = 0; i < actions.length; i++) {
            _validateAction(ctx, actions[i]);
        }

        // Execute actions
        results = new bytes[](actions.length);
        for (uint256 i = 0; i < actions.length; i++) {
            results[i] = _executeAction(ctx.account, actions[i], i);
        }

        emit DelegationRedeemed(
            ctx.permissionId,
            ctx.account,
            ctx.signer,
            actions.length
        );

        return results;
    }

    /*//////////////////////////////////////////////////////////////
                               GETTERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IERC7710
     */
    function isDelegationValid(
        bytes32 permissionId,
        address account
    ) external view returns (bool) {
        DelegationState storage delegation = _delegations[account][permissionId];

        if (!delegation.registered) return false;
        if (delegation.revoked) return false;
        if (block.timestamp > delegation.expiry) return false;

        return true;
    }

    /**
     * @inheritdoc IERC7710
     */
    function getRemainingAllowance(
        bytes32 permissionId,
        address account
    ) external view returns (uint256) {
        DelegationState storage delegation = _delegations[account][permissionId];

        if (!delegation.registered || delegation.revoked) return 0;
        if (delegation.nativeAllowance == 0) return type(uint256).max;
        if (delegation.spent >= delegation.nativeAllowance) return 0;

        return delegation.nativeAllowance - delegation.spent;
    }

    /**
     * @inheritdoc IERC7710
     */
    function getDelegationInfo(
        bytes32 permissionId,
        address account
    ) external view returns (
        address signer,
        uint48 expiry,
        uint256 spent,
        bool revoked
    ) {
        DelegationState storage delegation = _delegations[account][permissionId];
        return (
            delegation.signer,
            delegation.expiry,
            delegation.spent,
            delegation.revoked
        );
    }

    /**
     * @notice Get the domain separator
     * @return The EIP-712 domain separator
     */
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Decode permission context from bytes
     * @param permissionContext Encoded permission context
     * @return ctx Decoded PermissionContext struct
     */
    function _decodePermissionContext(
        bytes calldata permissionContext
    ) internal pure returns (PermissionContext memory ctx) {
        // Decode using abi.decode
        // Format: (permissionId, signer, account, chainId, expiry, nativeAllowance, whitelist, selectors, signature)
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
     * @notice Validate permission context
     * @param ctx The permission context to validate
     */
    function _validatePermissionContext(PermissionContext memory ctx) internal view {
        // Verify chain ID
        if (ctx.chainId != block.chainid) {
            revert ChainMismatch();
        }

        // Verify caller is the authorized signer
        if (msg.sender != ctx.signer) {
            revert InvalidSigner();
        }

        // Check delegation is registered
        DelegationState storage delegation = _delegations[ctx.account][ctx.permissionId];
        if (!delegation.registered) {
            // If not pre-registered, verify signature and register on-the-fly
            _verifyPermissionSignature(ctx);

            // For on-the-fly registration, we don't persist state here
            // as it would require storage writes in a view-like check
            // Instead, we just validate the signature is valid
        } else {
            // If registered, check revocation status
            if (delegation.revoked) {
                revert PermissionRevoked();
            }
        }

        // Check not expired
        if (block.timestamp > ctx.expiry) {
            revert PermissionExpired();
        }
    }

    /**
     * @notice Validate an individual action against permission context
     * @param ctx The permission context
     * @param action The action to validate
     */
    function _validateAction(
        PermissionContext memory ctx,
        Action calldata action
    ) internal pure {
        // Check whitelist (if set)
        if (ctx.whitelist.length > 0) {
            bool allowed = false;
            for (uint256 i = 0; i < ctx.whitelist.length; i++) {
                if (ctx.whitelist[i] == action.to) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                revert TargetNotAllowed(action.to);
            }
        }

        // Check selectors (if set and data is present)
        if (ctx.selectors.length > 0 && action.data.length >= 4) {
            bytes4 selector = bytes4(action.data[:4]);
            bool allowed = false;
            for (uint256 i = 0; i < ctx.selectors.length; i++) {
                if (ctx.selectors[i] == selector) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                revert SelectorNotAllowed(selector);
            }
        }
    }

    /**
     * @notice Execute an action on behalf of the smart account
     * @param account The smart account address
     * @param action The action to execute
     * @param index The action index (for error reporting)
     * @return returnData The return data from the call
     */
    function _executeAction(
        address account,
        Action calldata action,
        uint256 index
    ) internal returns (bytes memory returnData) {
        // Call the smart account's execute function
        // The account should verify that this delegation manager is authorized
        (bool success, bytes memory result) = account.call(
            abi.encodeWithSignature(
                "executeFromDelegation(address,uint256,bytes)",
                action.to,
                action.value,
                action.data
            )
        );

        if (!success) {
            revert ActionExecutionFailed(index, result);
        }

        // Decode the return data
        if (result.length > 0) {
            returnData = abi.decode(result, (bytes));
        }

        return returnData;
    }

    /**
     * @notice Verify the account's signature over the permission context
     * @param ctx The permission context containing the signature
     */
    function _verifyPermissionSignature(PermissionContext memory ctx) internal view {
        // Compute hash of whitelist and selectors
        bytes32 whitelistHash = keccak256(abi.encodePacked(ctx.whitelist));
        bytes32 selectorsHash = keccak256(abi.encodePacked(ctx.selectors));

        // Compute struct hash
        bytes32 structHash = keccak256(
            abi.encode(
                PERMISSION_TYPEHASH,
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

        // Compute digest
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _domainSeparator(), structHash)
        );

        // Recover signer
        address recovered = digest.recover(ctx.signature);

        // For smart accounts, we need to verify via EIP-1271
        // For now, check if recovered matches the account or call isValidSignature
        if (recovered != ctx.account) {
            // Try EIP-1271 validation
            (bool success, bytes memory result) = ctx.account.staticcall(
                abi.encodeWithSignature(
                    "isValidSignature(bytes32,bytes)",
                    digest,
                    ctx.signature
                )
            );

            if (!success || result.length < 4) {
                revert InvalidSignature();
            }

            bytes4 magicValue = abi.decode(result, (bytes4));
            if (magicValue != bytes4(0x1626ba7e)) {
                revert InvalidSignature();
            }
        }
    }

    /**
     * @notice Compute the EIP-712 domain separator
     * @return The domain separator
     */
    function _computeDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    /**
     * @notice Get the current domain separator (handles chain ID changes)
     * @return The domain separator
     */
    function _domainSeparator() internal view returns (bytes32) {
        if (block.chainid == _cachedChainId) {
            return _cachedDomainSeparator;
        }
        return _computeDomainSeparator();
    }
}
