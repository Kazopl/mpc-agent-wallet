// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IEntryPoint } from "./IEntryPoint.sol";

/**
 * @title IMpcSmartAccount
 * @notice Interface for MPC-secured smart accounts
 * @dev Extends ERC-4337 with MPC-specific functionality for AI agent wallets
 *
 * Key Features:
 * - MPC threshold signature validation (aggregated from 2-of-3 shares)
 * - Policy engine for spending limits, whitelists, and time restrictions
 * - Upgradeable via UUPS pattern
 */
interface IMpcSmartAccount {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event MpcPublicKeyUpdated(bytes oldKey, bytes newKey);
    event WhitelistUpdated(address indexed target, bool allowed);
    event DailyLimitUpdated(uint256 oldLimit, uint256 newLimit);
    event TransactionExecuted(address indexed target, uint256 value, bytes data, bytes returnData);
    event TransactionBatchExecuted(address[] targets, uint256[] values, bytes[] datas);
    event PolicyViolation(address indexed target, uint256 value, string reason);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidMpcSignature();
    error InvalidMpcPublicKey();
    error OnlyEntryPoint();
    error OnlySelfOrRecovery();
    error ExecutionFailed(address target, bytes returnData);
    error InvalidArrayLength();
    error DailyLimitExceeded(uint256 requested, uint256 remaining);
    error NotWhitelisted(address target);
    error TimeRestrictionViolated();
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                          MPC KEY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get the MPC aggregated public key
     * @return The compressed public key bytes (33 bytes for secp256k1)
     */
    function mpcPublicKey() external view returns (bytes memory);

    /**
     * @notice Update the MPC public key (only via recovery)
     * @param newPublicKey The new aggregated MPC public key
     */
    function updateMpcPublicKey(
        bytes calldata newPublicKey
    ) external;

    /*//////////////////////////////////////////////////////////////
                          POLICY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if an address is whitelisted
     * @param target The address to check
     * @return True if whitelisted
     */
    function isWhitelisted(
        address target
    ) external view returns (bool);

    /**
     * @notice Add or remove an address from whitelist
     * @param target Address to update
     * @param allowed True to whitelist, false to remove
     */
    function setWhitelist(address target, bool allowed) external;

    /**
     * @notice Batch update whitelist
     * @param targets Addresses to update
     * @param allowed Whitelist status for each address
     */
    function setWhitelistBatch(address[] calldata targets, bool[] calldata allowed) external;

    /**
     * @notice Get the daily spending limit
     * @return The daily limit in wei
     */
    function dailyLimit() external view returns (uint256);

    /**
     * @notice Get amount spent today
     * @return The amount spent in the current period
     */
    function spentToday() external view returns (uint256);

    /**
     * @notice Get remaining daily allowance
     * @return The remaining amount that can be spent today
     */
    function remainingDailyAllowance() external view returns (uint256);

    /**
     * @notice Update daily spending limit
     * @param newLimit New daily limit in wei
     */
    function setDailyLimit(
        uint256 newLimit
    ) external;

    /*//////////////////////////////////////////////////////////////
                              EXECUTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Execute a single call
     * @param target Address to call
     * @param value ETH value to send
     * @param data Call data
     * @return returnData Return data from the call
     */
    function execute(address target, uint256 value, bytes calldata data) external payable returns (bytes memory);

    /**
     * @notice Execute multiple calls in sequence
     * @param targets Addresses to call
     * @param values ETH values to send
     * @param datas Call data array
     * @return returnDatas Return data from each call
     */
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external payable returns (bytes[] memory returnDatas);

    /*//////////////////////////////////////////////////////////////
                               GETTERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get the EntryPoint address
     */
    function entryPoint() external view returns (address);

    /**
     * @notice Get the account nonce from EntryPoint
     */
    function getNonce(
        uint192 key
    ) external view returns (uint256);

    /**
     * @notice Get time restriction bounds
     * @return startHour Start hour (0-23)
     * @return endHour End hour (0-23)
     * @return enabled Whether time restrictions are active
     */
    function getTimeRestrictions() external view returns (uint8 startHour, uint8 endHour, bool enabled);
}
