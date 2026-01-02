// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Test, console2 } from "forge-std/Test.sol";
import { MpcSmartAccount } from "../src/MpcSmartAccount.sol";
import { MpcSmartAccountFactory } from "../src/MpcSmartAccountFactory.sol";
import { MpcRecoveryModule } from "../src/modules/MpcRecoveryModule.sol";
import { MpcSpendingLimitHook } from "../src/modules/MpcSpendingLimitHook.sol";
import { IEntryPoint } from "../src/interfaces/IEntryPoint.sol";

/**
 * @title Base Test Contract
 * @notice Common setup and utilities for all MPC wallet tests
 */
abstract contract BaseTest is Test {
    /*//////////////////////////////////////////////////////////////
                               CONTRACTS
    //////////////////////////////////////////////////////////////*/

    MpcSmartAccountFactory public factory;
    MpcRecoveryModule public recoveryModule;
    MpcSpendingLimitHook public spendingLimitHook;

    // Mock EntryPoint for testing
    MockEntryPoint public entryPoint;

    /*//////////////////////////////////////////////////////////////
                                ACTORS
    //////////////////////////////////////////////////////////////*/

    // MPC key simulation (in reality, these would be threshold signatures)
    address public mpcSigner;
    uint256 public mpcSignerKey;

    address public guardian1;
    address public guardian2;
    address public guardian3;

    address public bundler;
    address public beneficiary;
    address public attacker;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 public constant INITIAL_BALANCE = 100 ether;
    uint256 public constant DEFAULT_DAILY_LIMIT = 10 ether;

    // Sample compressed MPC public key (33 bytes)
    // In production, this would be the actual aggregated public key from DKG
    bytes public constant SAMPLE_MPC_PUBKEY = hex"02" // Prefix for even y-coordinate
        hex"0000000000000000000000000000000000000000000000000000000000000001"; // x-coordinate placeholder

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        // Generate keys
        (mpcSigner, mpcSignerKey) = makeAddrAndKey("mpcSigner");
        (guardian1,) = makeAddrAndKey("guardian1");
        (guardian2,) = makeAddrAndKey("guardian2");
        (guardian3,) = makeAddrAndKey("guardian3");
        (bundler,) = makeAddrAndKey("bundler");
        (beneficiary,) = makeAddrAndKey("beneficiary");
        (attacker,) = makeAddrAndKey("attacker");

        // Deploy mock EntryPoint
        entryPoint = new MockEntryPoint();

        // Deploy contracts
        factory = new MpcSmartAccountFactory(IEntryPoint(address(entryPoint)));
        recoveryModule = new MpcRecoveryModule();
        spendingLimitHook = new MpcSpendingLimitHook();

        // Fund actors
        vm.deal(mpcSigner, INITIAL_BALANCE);
        vm.deal(guardian1, INITIAL_BALANCE);
        vm.deal(bundler, INITIAL_BALANCE);
    }

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create an MPC smart account
     */
    function createAccount(
        bytes memory mpcPubKey,
        uint256 dailyLimit,
        uint256 salt
    ) internal returns (MpcSmartAccount) {
        return factory.createAccount(mpcPubKey, address(recoveryModule), dailyLimit, salt);
    }

    /**
     * @notice Create an MPC smart account with default parameters
     */
    function createDefaultAccount(
        uint256 salt
    ) internal returns (MpcSmartAccount) {
        return createAccount(generateMpcPubKey(mpcSigner), DEFAULT_DAILY_LIMIT, salt);
    }

    /**
     * @notice Generate a mock MPC public key from an address
     * @dev In production, this would be the actual aggregated public key
     */
    function generateMpcPubKey(
        address signer
    ) internal pure returns (bytes memory) {
        // Create a 33-byte compressed public key
        // Format: 0x02 or 0x03 prefix + 32-byte x-coordinate
        // We use the address hash as a placeholder for testing
        bytes32 xCoord = keccak256(abi.encodePacked(signer));
        return abi.encodePacked(bytes1(0x02), xCoord);
    }

    /**
     * @notice Get the counterfactual address for an account
     */
    function getAccountAddress(
        bytes memory mpcPubKey,
        uint256 dailyLimit,
        uint256 salt
    ) internal view returns (address) {
        return factory.getAddress(mpcPubKey, address(recoveryModule), dailyLimit, salt);
    }

    /**
     * @notice Sign a hash with the MPC signer key
     */
    function signWithMpc(
        bytes32 hash
    ) internal view returns (bytes memory) {
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mpcSignerKey, ethSignedHash);
        return abi.encodePacked(r, s, v);
    }

    /**
     * @notice Create a basic UserOperation
     */
    function createUserOp(
        address sender,
        uint256 nonce,
        bytes memory callData
    ) internal view returns (IEntryPoint.PackedUserOperation memory) {
        return IEntryPoint.PackedUserOperation({
            sender: sender,
            nonce: nonce,
            initCode: "",
            callData: callData,
            accountGasLimits: packGasLimits(100_000, 100_000),
            preVerificationGas: 21_000,
            gasFees: packGasFees(1 gwei, 10 gwei),
            paymasterAndData: "",
            signature: ""
        });
    }

    /**
     * @notice Pack gas limits
     */
    function packGasLimits(uint128 verificationGasLimit, uint128 callGasLimit) internal pure returns (bytes32) {
        return bytes32(uint256(verificationGasLimit) << 128 | uint256(callGasLimit));
    }

    /**
     * @notice Pack gas fees
     */
    function packGasFees(uint128 maxPriorityFeePerGas, uint128 maxFeePerGas) internal pure returns (bytes32) {
        return bytes32(uint256(maxPriorityFeePerGas) << 128 | uint256(maxFeePerGas));
    }

    /**
     * @notice Encode execute call
     */
    function encodeExecute(address target, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("execute(address,uint256,bytes)", target, value, data);
    }
}

/**
 * @title Mock EntryPoint
 * @notice Simplified EntryPoint for testing
 */
contract MockEntryPoint is IEntryPoint {
    mapping(address => uint256) internal _deposits;
    mapping(address => mapping(uint192 => uint256)) internal _nonces;

    function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) external {
        for (uint256 i = 0; i < ops.length; i++) {
            PackedUserOperation calldata op = ops[i];

            // Increment nonce
            uint192 key = uint192(op.nonce >> 64);
            _nonces[op.sender][key]++;

            // Call validateUserOp
            bytes32 userOpHash = getUserOpHash(op);
            (bool success,) = op.sender.call(
                abi.encodeWithSignature(
                    "validateUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes),bytes32,uint256)",
                    op,
                    userOpHash,
                    0
                )
            );
            require(success, "Validation failed");

            // Execute callData
            if (op.callData.length > 0) {
                (success,) = op.sender.call(op.callData);
                require(success, "Execution failed");
            }
        }

        // Pay beneficiary (simplified)
        (beneficiary);
    }

    function simulateValidation(
        PackedUserOperation calldata
    ) external pure {
        revert("Not implemented");
    }

    function balanceOf(
        address account
    ) external view returns (uint256) {
        return _deposits[account];
    }

    function depositTo(
        address account
    ) external payable {
        _deposits[account] += msg.value;
        emit Deposited(account, _deposits[account]);
    }

    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external {
        require(_deposits[msg.sender] >= withdrawAmount, "Insufficient deposit");
        _deposits[msg.sender] -= withdrawAmount;
        withdrawAddress.transfer(withdrawAmount);
    }

    function getUserOpHash(
        PackedUserOperation calldata userOp
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                userOp.sender,
                userOp.nonce,
                keccak256(userOp.initCode),
                keccak256(userOp.callData),
                userOp.accountGasLimits,
                userOp.preVerificationGas,
                userOp.gasFees,
                keccak256(userOp.paymasterAndData),
                block.chainid,
                address(this)
            )
        );
    }

    function getNonce(address sender, uint192 key) external view returns (uint256) {
        return _nonces[sender][key];
    }

    receive() external payable {
        _deposits[msg.sender] += msg.value;
    }
}
