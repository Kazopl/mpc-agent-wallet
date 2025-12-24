// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Script, console2 } from "forge-std/Script.sol";
import { MpcSmartAccountFactory } from "../src/MpcSmartAccountFactory.sol";
import { MpcRecoveryModule } from "../src/modules/MpcRecoveryModule.sol";
import { MpcSpendingLimitHook } from "../src/modules/MpcSpendingLimitHook.sol";
import { IEntryPoint } from "../src/interfaces/IEntryPoint.sol";

/**
 * @title Deploy Script
 * @notice Deploys the MPC Agent Wallet contracts
 *
 * Usage:
 * ```bash
 * # Local deployment (with anvil)
 * forge script script/Deploy.s.sol:DeployScript --rpc-url http://localhost:8545 --broadcast
 *
 * # Testnet deployment (e.g., Sepolia)
 * forge script script/Deploy.s.sol:DeployScript \
 *   --rpc-url $SEPOLIA_RPC_URL \
 *   --private-key $PRIVATE_KEY \
 *   --broadcast \
 *   --verify
 * ```
 */
contract DeployScript is Script {
    // EntryPoint v0.7 address (same on all chains)
    address public constant ENTRYPOINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function run() external {
        // Check if EntryPoint exists at the expected address
        address entryPoint = getEntryPoint();

        console2.log("=== MPC Agent Wallet Deployment ===");
        console2.log("Chain ID:", block.chainid);
        console2.log("EntryPoint:", entryPoint);
        console2.log("");

        vm.startBroadcast();

        // Deploy Recovery Module
        MpcRecoveryModule recoveryModule = new MpcRecoveryModule();
        console2.log("MpcRecoveryModule deployed at:", address(recoveryModule));

        // Deploy Spending Limit Hook
        MpcSpendingLimitHook spendingLimitHook = new MpcSpendingLimitHook();
        console2.log("MpcSpendingLimitHook deployed at:", address(spendingLimitHook));

        // Deploy Factory (includes implementation deployment)
        MpcSmartAccountFactory factory = new MpcSmartAccountFactory(IEntryPoint(entryPoint));
        console2.log("MpcSmartAccountFactory deployed at:", address(factory));
        console2.log("MpcSmartAccount implementation at:", factory.getImplementation());

        vm.stopBroadcast();

        console2.log("");
        console2.log("=== Deployment Complete ===");
        console2.log("");
        console2.log("To create an account:");
        console2.log("  factory.createAccount(mpcPublicKey, recoveryModule, dailyLimit, salt)");
    }

    function getEntryPoint() internal view returns (address) {
        // Check if running on a network with deployed EntryPoint
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(ENTRYPOINT_V07)
        }

        if (codeSize > 0) {
            return ENTRYPOINT_V07;
        }

        // For local testing, we might need to deploy a mock or use a different address
        // Check for environment variable
        address envEntryPoint = vm.envOr("ENTRYPOINT_ADDRESS", address(0));
        if (envEntryPoint != address(0)) {
            return envEntryPoint;
        }

        // Default to v0.7 address (caller should deploy EntryPoint first on local networks)
        return ENTRYPOINT_V07;
    }
}

/**
 * @title Create Account Script
 * @notice Creates an MPC smart account
 */
contract CreateAccountScript is Script {
    function run() external {
        // Read environment variables
        address factoryAddress = vm.envAddress("FACTORY_ADDRESS");
        address recoveryModuleAddress = vm.envAddress("RECOVERY_MODULE_ADDRESS");
        bytes memory mpcPublicKey = vm.envBytes("MPC_PUBLIC_KEY");
        uint256 dailyLimit = vm.envOr("DAILY_LIMIT", uint256(10 ether));
        uint256 salt = vm.envOr("SALT", uint256(0));

        MpcSmartAccountFactory factory = MpcSmartAccountFactory(factoryAddress);

        console2.log("=== Creating MPC Smart Account ===");
        console2.log("Factory:", factoryAddress);
        console2.log("Recovery Module:", recoveryModuleAddress);
        console2.log("Daily Limit:", dailyLimit);
        console2.log("Salt:", salt);

        // Compute counterfactual address
        address predictedAddress = factory.getAddress(mpcPublicKey, recoveryModuleAddress, dailyLimit, salt);
        console2.log("Predicted Address:", predictedAddress);

        vm.startBroadcast();

        // Create account
        address account = address(factory.createAccount(mpcPublicKey, recoveryModuleAddress, dailyLimit, salt));

        vm.stopBroadcast();

        console2.log("Account Created:", account);
        require(account == predictedAddress, "Address mismatch!");
    }
}
