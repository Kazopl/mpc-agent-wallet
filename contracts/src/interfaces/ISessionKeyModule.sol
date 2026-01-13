// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ISessionKeyModule
 * @notice Interface for session key management in MPC smart accounts
 * @dev Session keys enable AI agents to operate with scoped, time-limited permissions
 *      without exposing the master MPC key
 *
 * Use Cases:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                       SESSION KEY USE CASES                                  │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │   AI Trading Bot                                                            │
 * │   ├─ Session key valid for 24 hours                                         │
 * │   ├─ Spending limit: 1 ETH per session                                      │
 * │   └─ Whitelist: Uniswap Router only                                         │
 * │                                                                             │
 * │   Payment Processor                                                         │
 * │   ├─ Session key valid for 7 days                                           │
 * │   ├─ Spending limit: 0.1 ETH per transaction                                │
 * │   └─ Selectors: transfer(), approve() only                                  │
 * │                                                                             │
 * │   NFT Minting Agent                                                         │
 * │   ├─ Session key valid for 1 hour                                           │
 * │   ├─ Spending limit: 0.5 ETH total                                          │
 * │   └─ Whitelist: Specific NFT contract only                                  │
 * │                                                                             │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
interface ISessionKeyModule {
    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Session key data structure
     * @param signer Session key address (EOA that can sign on behalf of account)
     * @param validAfter Timestamp when session key becomes valid
     * @param validUntil Timestamp when session key expires
     * @param spendingLimit Maximum ETH that can be spent with this session key
     * @param spent Amount already spent with this session key
     * @param whitelist Array of allowed target addresses (empty = all allowed)
     * @param selectors Array of allowed function selectors (empty = all allowed)
     * @param revoked Whether the session key has been revoked
     */
    struct SessionKey {
        address signer;
        uint48 validAfter;
        uint48 validUntil;
        uint256 spendingLimit;
        uint256 spent;
        address[] whitelist;
        bytes4[] selectors;
        bool revoked;
    }

    /**
     * @notice Parameters for creating a session key
     */
    struct SessionKeyParams {
        address signer;
        uint48 validAfter;
        uint48 validUntil;
        uint256 spendingLimit;
        address[] whitelist;
        bytes4[] selectors;
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event SessionKeyCreated(
        address indexed account,
        address indexed signer,
        uint48 validAfter,
        uint48 validUntil,
        uint256 spendingLimit
    );

    event SessionKeyRevoked(address indexed account, address indexed signer);

    event SessionKeySpent(address indexed account, address indexed signer, uint256 amount, uint256 totalSpent);

    event SessionKeyWhitelistUpdated(address indexed account, address indexed signer, address[] whitelist);

    event SessionKeySelectorsUpdated(address indexed account, address indexed signer, bytes4[] selectors);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error SessionKeyNotFound();
    error SessionKeyExpired();
    error SessionKeyNotYetValid();
    error SessionKeyIsRevoked();
    error SessionKeySpendingLimitExceeded(uint256 requested, uint256 remaining);
    error SessionKeyTargetNotWhitelisted(address target);
    error SessionKeySelectorNotAllowed(bytes4 selector);
    error SessionKeyAlreadyExists();
    error InvalidSessionKeyParams();
    error InvalidSignature();
    error OnlyAccountOwner();

    /*//////////////////////////////////////////////////////////////
                          SESSION KEY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new session key for an account
     * @param params Session key parameters
     */
    function createSessionKey(
        SessionKeyParams calldata params
    ) external;

    /**
     * @notice Revoke an existing session key
     * @param signer The session key signer address to revoke
     */
    function revokeSessionKey(
        address signer
    ) external;

    /**
     * @notice Update whitelist for an existing session key
     * @param signer The session key signer address
     * @param whitelist New whitelist addresses
     */
    function updateWhitelist(address signer, address[] calldata whitelist) external;

    /**
     * @notice Update allowed selectors for an existing session key
     * @param signer The session key signer address
     * @param selectors New allowed selectors
     */
    function updateSelectors(address signer, bytes4[] calldata selectors) external;

    /*//////////////////////////////////////////////////////////////
                             VALIDATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validate a session key signature for a user operation
     * @param account The smart account address
     * @param userOpHash The hash of the user operation
     * @param signature The signature from the session key
     * @return validationData Packed validation data (sigFailed, validAfter, validUntil)
     */
    function validateSessionKey(
        address account,
        bytes32 userOpHash,
        bytes calldata signature
    ) external view returns (uint256 validationData);

    /**
     * @notice Validate and record spending for a session key
     * @param account The smart account address
     * @param signer The session key signer
     * @param target The call target
     * @param value The ETH value being sent
     * @param data The call data
     */
    function validateAndRecordSpending(
        address account,
        address signer,
        address target,
        uint256 value,
        bytes calldata data
    ) external;

    /*//////////////////////////////////////////////////////////////
                               GETTERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get session key data
     * @param account The smart account address
     * @param signer The session key signer address
     * @return The session key data
     */
    function getSessionKey(address account, address signer) external view returns (SessionKey memory);

    /**
     * @notice Check if a session key is valid
     * @param account The smart account address
     * @param signer The session key signer address
     * @return True if the session key is valid (not expired, not revoked, within time bounds)
     */
    function isSessionKeyValid(address account, address signer) external view returns (bool);

    /**
     * @notice Get remaining spending allowance for a session key
     * @param account The smart account address
     * @param signer The session key signer address
     * @return The remaining amount that can be spent
     */
    function getRemainingSpending(address account, address signer) external view returns (uint256);

    /**
     * @notice Get all active session keys for an account
     * @param account The smart account address
     * @return Array of session key signer addresses
     */
    function getActiveSessionKeys(
        address account
    ) external view returns (address[] memory);

    /**
     * @notice Check if a target is whitelisted for a session key
     * @param account The smart account address
     * @param signer The session key signer address
     * @param target The target address to check
     * @return True if whitelisted or whitelist is empty (all allowed)
     */
    function isTargetAllowed(address account, address signer, address target) external view returns (bool);

    /**
     * @notice Check if a selector is allowed for a session key
     * @param account The smart account address
     * @param signer The session key signer address
     * @param selector The function selector to check
     * @return True if allowed or selectors list is empty (all allowed)
     */
    function isSelectorAllowed(address account, address signer, bytes4 selector) external view returns (bool);
}
