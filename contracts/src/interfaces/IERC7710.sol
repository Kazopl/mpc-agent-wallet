// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IERC7710
 * @notice Interface for ERC-7710 delegation redemption
 * @dev ERC-7710 defines a standard for redeeming delegated permissions
 *      in smart accounts. This enables dapps and AI agents to execute
 *      transactions using permissions granted via ERC-7715.
 *
 * Flow:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                      ERC-7710 DELEGATION FLOW                               │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │   1. Permission Grant (ERC-7715):                                           │
 * │   ┌──────────────────┐                                                      │
 * │   │  wallet_request  │                                                      │
 * │   │  Execution       │──────────────────────────────────────►               │
 * │   │  Permissions     │                                        │             │
 * │   └──────────────────┘                                        │             │
 * │                                                               ▼             │
 * │                                                  ┌─────────────────────────┐│
 * │                                                  │  PermissionsContext     ││
 * │                                                  │  (signed permission ID  ││
 * │                                                  │   + encoded params)     ││
 * │                                                  └─────────────────────────┘│
 * │                                                                             │
 * │   2. Permission Redemption (ERC-7710):                                      │
 * │   ┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐ │
 * │   │   AI Agent       │      │  Delegation      │      │   Smart Account  │ │
 * │   │   calls          │─────►│  Manager:        │─────►│   executes       │ │
 * │   │   redeemDelegation      │  - Verify ctx    │      │   actions        │ │
 * │   │                  │      │  - Check perms   │      │                  │ │
 * │   └──────────────────┘      │  - Validate sig  │      └──────────────────┘ │
 * │                             └──────────────────┘                            │
 * │                                                                             │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
interface IERC7710 {
    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Action to be executed via delegated permission
     * @param to Target contract address
     * @param value ETH value to send
     * @param data Calldata for the target contract
     */
    struct Action {
        address to;
        uint256 value;
        bytes data;
    }

    /**
     * @notice Decoded permission context containing delegation details
     * @param permissionId Unique identifier for the granted permission
     * @param signer Address authorized to use this permission
     * @param account Smart account address this permission applies to
     * @param chainId Chain ID this permission is valid on
     * @param expiry Timestamp when permission expires
     * @param nativeAllowance Native token spending allowance
     * @param whitelist Allowed target addresses (empty = all allowed)
     * @param selectors Allowed function selectors (empty = all allowed)
     * @param signature Wallet's signature over the permission
     */
    struct PermissionContext {
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
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event DelegationRedeemed(
        bytes32 indexed permissionId,
        address indexed account,
        address indexed signer,
        uint256 actionsCount
    );

    event DelegationRegistered(
        bytes32 indexed permissionId,
        address indexed account,
        address indexed signer,
        uint48 expiry
    );

    event DelegationRevoked(
        bytes32 indexed permissionId,
        address indexed account
    );

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidPermissionContext();
    error PermissionExpired();
    error PermissionRevoked();
    error InvalidSignature();
    error InvalidSigner();
    error ChainMismatch();
    error AccountMismatch();
    error TargetNotAllowed(address target);
    error SelectorNotAllowed(bytes4 selector);
    error SpendingLimitExceeded(uint256 requested, uint256 remaining);
    error ActionExecutionFailed(uint256 index, bytes returnData);
    error OnlyAccountOrSigner();
    error PermissionAlreadyRegistered();

    /*//////////////////////////////////////////////////////////////
                          DELEGATION MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a new delegation (called by smart account)
     * @param permissionContext Encoded permission context
     */
    function registerDelegation(bytes calldata permissionContext) external;

    /**
     * @notice Revoke an existing delegation
     * @param permissionId The permission ID to revoke
     */
    function revokeDelegation(bytes32 permissionId) external;

    /**
     * @notice Redeem a delegation to execute actions
     * @dev This is the main entry point for ERC-7710 delegation redemption.
     *      The caller must be the authorized signer from the permission context.
     * @param permissionContext Encoded permission context containing:
     *        - Permission ID
     *        - Signer address
     *        - Account address
     *        - Chain ID
     *        - Expiry timestamp
     *        - Native token allowance
     *        - Whitelist addresses
     *        - Allowed selectors
     *        - Wallet signature
     * @param actions Array of actions to execute
     * @return results Array of return data from each action
     */
    function redeemDelegation(
        bytes calldata permissionContext,
        Action[] calldata actions
    ) external returns (bytes[] memory results);

    /*//////////////////////////////////////////////////////////////
                               GETTERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if a delegation is valid
     * @param permissionId The permission ID to check
     * @param account The smart account address
     * @return True if the delegation is valid (registered, not revoked, not expired)
     */
    function isDelegationValid(
        bytes32 permissionId,
        address account
    ) external view returns (bool);

    /**
     * @notice Get remaining spending allowance for a delegation
     * @param permissionId The permission ID
     * @param account The smart account address
     * @return The remaining native token allowance
     */
    function getRemainingAllowance(
        bytes32 permissionId,
        address account
    ) external view returns (uint256);

    /**
     * @notice Get delegation info
     * @param permissionId The permission ID
     * @param account The smart account address
     * @return signer The authorized signer
     * @return expiry The expiry timestamp
     * @return spent Amount already spent
     * @return revoked Whether the delegation is revoked
     */
    function getDelegationInfo(
        bytes32 permissionId,
        address account
    ) external view returns (
        address signer,
        uint48 expiry,
        uint256 spent,
        bool revoked
    );
}
