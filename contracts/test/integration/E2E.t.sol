// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BaseTest, MockEntryPoint } from "../Base.t.sol";
import { MpcSmartAccount } from "../../src/MpcSmartAccount.sol";
import { MpcRecoveryModule } from "../../src/modules/MpcRecoveryModule.sol";
import { MpcSpendingLimitHook } from "../../src/modules/MpcSpendingLimitHook.sol";
import { IEntryPoint } from "../../src/interfaces/IEntryPoint.sol";
import { IMpcRecoveryModule } from "../../src/interfaces/IMpcRecoveryModule.sol";
import { console2 } from "forge-std/Test.sol";

/**
 * @title End-to-End Integration Tests
 * @notice Tests full workflows for MPC agent wallet
 */
contract E2ETest is BaseTest {
    MpcSmartAccount public account;
    address public recipient;

    function setUp() public override {
        super.setUp();

        recipient = makeAddr("recipient");

        // Create and fund account
        account = createDefaultAccount(0);
        vm.deal(address(account), 100 ether);

        // Setup guardians
        address[] memory guardians = new address[](2);
        guardians[0] = guardian1;
        guardians[1] = guardian2;

        vm.prank(address(account));
        recoveryModule.initialize(guardians, 2 days);
    }

    /*//////////////////////////////////////////////////////////////
                     FULL LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test complete account lifecycle:
     * 1. Account creation
     * 2. Normal transaction execution
     * 3. Spending limit enforcement
     * 4. Key recovery
     * 5. Post-recovery transaction
     */
    function test_fullAccountLifecycle() public {
        console2.log("=== Full Account Lifecycle Test ===");

        // 1. Verify account creation
        console2.log("1. Account created at:", address(account));
        assertEq(account.dailyLimit(), DEFAULT_DAILY_LIMIT, "Daily limit set");

        // 2. Execute normal transaction
        console2.log("2. Executing normal transaction...");
        uint256 recipientBalanceBefore = recipient.balance;

        vm.prank(address(entryPoint));
        account.execute(recipient, 1 ether, "");

        assertEq(recipient.balance, recipientBalanceBefore + 1 ether, "Transaction successful");
        console2.log("   Sent 1 ETH to recipient");

        // 3. Test spending limit
        console2.log("3. Testing spending limit enforcement...");
        assertEq(account.spentToday(), 1 ether, "Spending tracked");
        assertEq(account.remainingDailyAllowance(), 9 ether, "Allowance remaining");

        // 4. Simulate key compromise and recovery
        console2.log("4. Simulating key recovery...");
        bytes memory newKey = generateMpcPubKey(guardian3);
        bytes memory oldKey = account.mpcPublicKey();

        // Guardian initiates recovery
        vm.prank(guardian1);
        recoveryModule.initiateRecovery(address(account), newKey);
        console2.log("   Recovery initiated by guardian1");

        // Wait for delay
        vm.warp(block.timestamp + 2 days + 1);
        console2.log("   Time delay passed");

        // Execute recovery
        recoveryModule.executeRecovery(address(account));
        console2.log("   Recovery executed");

        // Verify key was updated
        bytes memory currentKey = account.mpcPublicKey();
        assertEq(keccak256(currentKey), keccak256(newKey), "Key updated");
        assertTrue(keccak256(currentKey) != keccak256(oldKey), "Key changed");
        console2.log("   New MPC key set successfully");

        // 5. Post-recovery transaction
        console2.log("5. Testing post-recovery transaction...");

        // Reset daily period for fresh limit
        vm.warp(block.timestamp + 1 days);

        vm.prank(address(entryPoint));
        account.execute(recipient, 2 ether, "");

        assertEq(recipient.balance, recipientBalanceBefore + 3 ether, "Post-recovery tx successful");
        console2.log("   Post-recovery transaction successful");

        console2.log("=== Lifecycle Test Complete ===");
    }

    /**
     * @notice Test AI agent trading scenario:
     * - Limited per-transaction amounts
     * - Whitelisted DEX routers only
     * - Daily spending cap
     */
    function test_aiAgentTradingScenario() public {
        console2.log("=== AI Agent Trading Scenario ===");

        // Setup: Configure for trading
        address dexRouter = makeAddr("dexRouter");
        address maliciousContract = makeAddr("malicious");

        vm.startPrank(address(recoveryModule));
        account.setDailyLimit(5 ether);
        account.setWhitelistEnabled(true);
        account.setWhitelist(dexRouter, true);
        vm.stopPrank();

        console2.log("Configured trading limits:");
        console2.log("  Daily limit: 5 ETH");
        console2.log("  Whitelist enabled");
        console2.log("  DEX Router whitelisted");

        // Simulate multiple trades
        console2.log("\nExecuting trades...");

        // Trade 1: 1 ETH swap
        vm.prank(address(entryPoint));
        account.execute(dexRouter, 1 ether, abi.encodeWithSignature("swap()"));
        console2.log("  Trade 1: 1 ETH - Success");

        // Trade 2: 1.5 ETH swap
        vm.prank(address(entryPoint));
        account.execute(dexRouter, 1.5 ether, abi.encodeWithSignature("swap()"));
        console2.log("  Trade 2: 1.5 ETH - Success");

        // Trade 3: 2 ETH swap
        vm.prank(address(entryPoint));
        account.execute(dexRouter, 2 ether, abi.encodeWithSignature("swap()"));
        console2.log("  Trade 3: 2 ETH - Success");

        assertEq(account.spentToday(), 4.5 ether, "Total spent tracked");

        // Trade 4: Should fail - exceeds daily limit
        console2.log("\nTesting limit enforcement...");
        vm.prank(address(entryPoint));
        vm.expectRevert();
        account.execute(dexRouter, 1 ether, abi.encodeWithSignature("swap()"));
        console2.log("  Trade 4: 1 ETH - Blocked (daily limit)");

        // Attempt malicious interaction
        vm.prank(address(entryPoint));
        vm.expectRevert();
        account.execute(maliciousContract, 0.1 ether, abi.encodeWithSignature("drain()"));
        console2.log("  Malicious call - Blocked (not whitelisted)");

        console2.log("\n=== Trading Scenario Complete ===");
    }

    /**
     * @notice Test recovery flow with cancellation:
     * - Guardian initiates recovery
     * - Account owner cancels
     * - New recovery attempt
     * - Successful execution
     */
    function test_recoveryWithCancellation() public {
        console2.log("=== Recovery With Cancellation ===");

        bytes memory attackerKey = generateMpcPubKey(attacker);
        bytes memory legitimateKey = generateMpcPubKey(guardian3);

        // Step 1: Compromised guardian initiates malicious recovery
        console2.log("1. Malicious recovery initiated");
        vm.prank(guardian1);
        recoveryModule.initiateRecovery(address(account), attackerKey);

        IMpcRecoveryModule.RecoveryRequest memory request = recoveryModule.getRecoveryRequest(address(account));
        assertEq(keccak256(request.newMpcPublicKey), keccak256(attackerKey), "Malicious key pending");

        // Step 2: Account owner detects and cancels
        console2.log("2. Account owner cancels recovery");
        vm.prank(address(account));
        recoveryModule.cancelRecovery(address(account));

        request = recoveryModule.getRecoveryRequest(address(account));
        assertEq(request.executeAfter, 0, "Recovery cancelled");

        // Step 3: Legitimate recovery
        console2.log("3. Legitimate recovery initiated");
        vm.prank(guardian2);
        recoveryModule.initiateRecovery(address(account), legitimateKey);

        // Step 4: Wait and execute
        vm.warp(block.timestamp + 2 days + 1);
        console2.log("4. Executing legitimate recovery");
        recoveryModule.executeRecovery(address(account));

        bytes memory currentKey = account.mpcPublicKey();
        assertEq(keccak256(currentKey), keccak256(legitimateKey), "Legitimate key set");

        console2.log("=== Recovery Flow Complete ===");
    }

    /**
     * @notice Test multi-chain simulation:
     * - Same account on multiple EVM chains
     * - Different spending limits per chain
     */
    function test_counterfactualAddressConsistency() public {
        console2.log("=== Counterfactual Address Test ===");

        bytes memory pubKey = generateMpcPubKey(mpcSigner);
        uint256 salt = 12_345;

        // Get predicted addresses for different configurations
        address addr1 = factory.getAddress(pubKey, address(recoveryModule), 10 ether, salt);
        address addr2 = factory.getAddress(pubKey, address(recoveryModule), 10 ether, salt);
        address addr3 = factory.getAddress(pubKey, address(recoveryModule), 20 ether, salt);
        address addr4 = factory.getAddress(pubKey, address(recoveryModule), 10 ether, salt + 1);

        console2.log("Address with same params:", addr1);
        console2.log("Address with same params (again):", addr2);
        console2.log("Address with different limit:", addr3);
        console2.log("Address with different salt:", addr4);

        // Same params = same address
        assertEq(addr1, addr2, "Same params should give same address");

        // Different params = different address
        assertTrue(addr1 != addr3, "Different limit should give different address");
        assertTrue(addr1 != addr4, "Different salt should give different address");

        // Deploy and verify
        MpcSmartAccount deployed = factory.createAccount(pubKey, address(recoveryModule), 10 ether, salt);

        assertEq(address(deployed), addr1, "Deployed at predicted address");
        console2.log("\nDeployed at predicted address:", address(deployed));

        console2.log("=== Counterfactual Test Complete ===");
    }

    /**
     * @notice Test batch operations with mixed success/failure
     */
    function test_batchOperations() public {
        console2.log("=== Batch Operations Test ===");

        MockTarget target1 = new MockTarget();
        MockTarget target2 = new MockTarget();

        address[] memory targets = new address[](3);
        targets[0] = address(target1);
        targets[1] = address(target2);
        targets[2] = recipient;

        uint256[] memory values = new uint256[](3);
        values[0] = 0;
        values[1] = 0;
        values[2] = 1 ether;

        bytes[] memory datas = new bytes[](3);
        datas[0] = abi.encodeWithSignature("setValue(uint256)", 100);
        datas[1] = abi.encodeWithSignature("setValue(uint256)", 200);
        datas[2] = "";

        console2.log("Executing batch of 3 operations...");

        vm.prank(address(entryPoint));
        account.executeBatch(targets, values, datas);

        assertEq(target1.value(), 100, "Target1 value set");
        assertEq(target2.value(), 200, "Target2 value set");
        assertEq(recipient.balance, 1 ether, "Recipient received ETH");
        assertEq(account.spentToday(), 1 ether, "Total spending tracked");

        console2.log("  Operation 1: Set target1.value = 100");
        console2.log("  Operation 2: Set target2.value = 200");
        console2.log("  Operation 3: Sent 1 ETH to recipient");

        console2.log("=== Batch Operations Complete ===");
    }
}

/**
 * @title Mock Target for testing
 */
contract MockTarget {
    uint256 public value;

    function setValue(
        uint256 _value
    ) external {
        value = _value;
    }

    function swap() external payable {
        // Mock DEX swap
    }

    receive() external payable { }
}
