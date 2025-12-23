// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { MpcSmartAccount } from "./MpcSmartAccount.sol";
import { IEntryPoint } from "./interfaces/IEntryPoint.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { Create2 } from "@openzeppelin/contracts/utils/Create2.sol";

/**
 * @title MpcSmartAccountFactory
 * @author MPC Agent Wallet SDK
 * @notice Factory for deploying MPC smart account proxies
 *
 * @dev Features:
 *      - Counterfactual address computation
 *      - CREATE2 deterministic deployment
 *      - Single implementation, multiple proxies
 *      - Gas-efficient proxy pattern
 *
 * Deployment Flow:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                     ACCOUNT DEPLOYMENT FLOW                                  │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │   1. Off-chain: Compute counterfactual address                              │
 * │      └─ getAddress(mpcPubKey, recoveryModule, dailyLimit, salt)            │
 * │                                                                             │
 * │   2. Fund the counterfactual address                                        │
 * │      └─ User sends ETH to computed address                                  │
 * │                                                                             │
 * │   3. First UserOperation triggers deployment                                │
 * │      └─ initCode = factory.address + createAccount(...) encoded             │
 * │                                                                             │
 * │   4. EntryPoint calls factory.createAccount()                               │
 * │      └─ Deploys ERC1967Proxy pointing to MpcSmartAccount                   │
 * │                                                                             │
 * │   5. Account is initialized and ready                                       │
 * │      └─ MPC public key set, recovery module configured                      │
 * │                                                                             │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract MpcSmartAccountFactory {
    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice The MpcSmartAccount implementation
    MpcSmartAccount public immutable accountImplementation;

    /// @notice The EntryPoint contract
    IEntryPoint public immutable entryPoint;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event AccountCreated(
        address indexed account, bytes mpcPublicKey, address indexed recoveryModule, uint256 dailyLimit
    );

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error AccountAlreadyDeployed(address account);
    error InvalidMpcPublicKey();
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deploy factory with implementation
     * @param _entryPoint The EntryPoint contract
     */
    constructor(
        IEntryPoint _entryPoint
    ) {
        entryPoint = _entryPoint;
        accountImplementation = new MpcSmartAccount(_entryPoint);
    }

    /*//////////////////////////////////////////////////////////////
                         FACTORY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new MPC smart account
     * @param mpcPublicKey The aggregated MPC public key (33 bytes compressed)
     * @param recoveryModule The recovery module address
     * @param dailyLimit Initial daily spending limit
     * @param salt Unique salt for CREATE2
     * @return account The deployed account address
     */
    function createAccount(
        bytes calldata mpcPublicKey,
        address recoveryModule,
        uint256 dailyLimit,
        uint256 salt
    ) external returns (MpcSmartAccount account) {
        if (mpcPublicKey.length != 33) {
            revert InvalidMpcPublicKey();
        }
        if (recoveryModule == address(0)) {
            revert ZeroAddress();
        }

        address addr = getAddress(mpcPublicKey, recoveryModule, dailyLimit, salt);

        // Check if already deployed
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(addr)
        }

        if (codeSize > 0) {
            return MpcSmartAccount(payable(addr));
        }

        // Deploy proxy
        bytes memory initData = abi.encodeCall(MpcSmartAccount.initialize, (mpcPublicKey, recoveryModule, dailyLimit));

        ERC1967Proxy proxy = new ERC1967Proxy{ salt: bytes32(salt) }(address(accountImplementation), initData);

        account = MpcSmartAccount(payable(address(proxy)));

        emit AccountCreated(address(account), mpcPublicKey, recoveryModule, dailyLimit);
    }

    /**
     * @notice Compute the counterfactual address for an account
     * @param mpcPublicKey The aggregated MPC public key
     * @param recoveryModule The recovery module address
     * @param dailyLimit Initial daily spending limit
     * @param salt Unique salt for CREATE2
     * @return The computed address
     */
    function getAddress(
        bytes calldata mpcPublicKey,
        address recoveryModule,
        uint256 dailyLimit,
        uint256 salt
    ) public view returns (address) {
        bytes memory initData = abi.encodeCall(MpcSmartAccount.initialize, (mpcPublicKey, recoveryModule, dailyLimit));

        bytes memory proxyBytecode =
            abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(address(accountImplementation), initData));

        bytes32 bytecodeHash = keccak256(proxyBytecode);

        return Create2.computeAddress(bytes32(salt), bytecodeHash, address(this));
    }

    /**
     * @notice Get the implementation address
     * @return The MpcSmartAccount implementation
     */
    function getImplementation() external view returns (address) {
        return address(accountImplementation);
    }
}
