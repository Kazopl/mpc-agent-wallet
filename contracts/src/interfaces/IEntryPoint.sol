// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IEntryPoint
 * @notice ERC-4337 EntryPoint interface - the singleton contract that validates and executes UserOperations
 * @dev This is a simplified interface focusing on the core functionality needed for MPC wallet
 */
interface IEntryPoint {
    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice UserOperation struct - the core data structure for account abstraction
     * @dev Packed version (ERC-4337 v0.7) with combined gas fields
     */
    struct PackedUserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        bytes32 accountGasLimits;
        uint256 preVerificationGas;
        bytes32 gasFees;
        bytes paymasterAndData;
        bytes signature;
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );

    event Deposited(address indexed account, uint256 totalDeposit);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error FailedOp(uint256 opIndex, string reason);

    /*//////////////////////////////////////////////////////////////
                            CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) external;

    function simulateValidation(
        PackedUserOperation calldata userOp
    ) external;

    /*//////////////////////////////////////////////////////////////
                           DEPOSIT FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function balanceOf(
        address account
    ) external view returns (uint256);

    function depositTo(
        address account
    ) external payable;

    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external;

    /*//////////////////////////////////////////////////////////////
                           UTILITY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getUserOpHash(
        PackedUserOperation calldata userOp
    ) external view returns (bytes32);

    function getNonce(address sender, uint192 key) external view returns (uint256);
}
