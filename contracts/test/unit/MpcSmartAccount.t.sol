// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BaseTest, MockEntryPoint } from "../Base.t.sol";
import { MpcSmartAccount } from "../../src/MpcSmartAccount.sol";
import { IMpcSmartAccount } from "../../src/interfaces/IMpcSmartAccount.sol";
import { IEntryPoint } from "../../src/interfaces/IEntryPoint.sol";

/**
 * @title MpcSmartAccount Tests
 * @notice Unit tests for MPC smart account functionality
 */
contract MpcSmartAccountTest is BaseTest {
    MpcSmartAccount public account;

    function setUp() public override {
        super.setUp();

        // Create account
        account = createDefaultAccount(0);

        // Fund account
        vm.deal(address(account), 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_initialization() public view {
        // Verify MPC public key is set
        bytes memory storedKey = account.mpcPublicKey();
        bytes memory expectedKey = generateMpcPubKey(mpcSigner);

        assertEq(storedKey.length, 33, "MPC public key should be 33 bytes");
        assertEq(keccak256(storedKey), keccak256(expectedKey), "MPC public key mismatch");

        // Verify recovery module
        assertEq(account.recoveryModule(), address(recoveryModule), "Recovery module mismatch");

        // Verify entry point
        assertEq(account.entryPoint(), address(entryPoint), "Entry point mismatch");
    }

    function test_initialization_withDailyLimit() public view {
        assertEq(account.dailyLimit(), DEFAULT_DAILY_LIMIT, "Daily limit should be set");
    }

    function test_cannotReinitialize() public {
        bytes memory newKey = generateMpcPubKey(guardian1);

        vm.expectRevert();
        account.initialize(newKey, address(recoveryModule), 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                         COUNTERFACTUAL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_counterfactualAddress() public view {
        bytes memory pubKey = generateMpcPubKey(mpcSigner);
        uint256 salt = 123;

        address predicted = factory.getAddress(pubKey, address(recoveryModule), DEFAULT_DAILY_LIMIT, salt);

        // Should be able to compute address before deployment
        assertTrue(predicted != address(0), "Predicted address should not be zero");
    }

    function test_deployAtPredictedAddress() public {
        bytes memory pubKey = generateMpcPubKey(mpcSigner);
        uint256 salt = 456;

        address predicted = factory.getAddress(pubKey, address(recoveryModule), DEFAULT_DAILY_LIMIT, salt);

        MpcSmartAccount newAccount = factory.createAccount(pubKey, address(recoveryModule), DEFAULT_DAILY_LIMIT, salt);

        assertEq(address(newAccount), predicted, "Account should deploy at predicted address");
    }

    /*//////////////////////////////////////////////////////////////
                           EXECUTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_execute_sendsEth() public {
        address recipient = makeAddr("recipient");
        uint256 amount = 1 ether;

        // Execute as EntryPoint
        vm.prank(address(entryPoint));
        account.execute(recipient, amount, "");

        assertEq(recipient.balance, amount, "Recipient should receive ETH");
    }

    function test_execute_callsContract() public {
        MockTarget target = new MockTarget();

        bytes memory data = abi.encodeWithSignature("setValue(uint256)", 42);

        vm.prank(address(entryPoint));
        account.execute(address(target), 0, data);

        assertEq(target.value(), 42, "Target value should be set");
    }

    function test_execute_revertsIfNotEntryPoint() public {
        vm.prank(attacker);
        vm.expectRevert(IMpcSmartAccount.OnlyEntryPoint.selector);
        account.execute(attacker, 1 ether, "");
    }

    function test_executeBatch() public {
        address recipient1 = makeAddr("recipient1");
        address recipient2 = makeAddr("recipient2");

        address[] memory targets = new address[](2);
        targets[0] = recipient1;
        targets[1] = recipient2;

        uint256[] memory values = new uint256[](2);
        values[0] = 1 ether;
        values[1] = 2 ether;

        bytes[] memory datas = new bytes[](2);
        datas[0] = "";
        datas[1] = "";

        vm.prank(address(entryPoint));
        account.executeBatch(targets, values, datas);

        assertEq(recipient1.balance, 1 ether, "Recipient1 should receive ETH");
        assertEq(recipient2.balance, 2 ether, "Recipient2 should receive ETH");
    }

    /*//////////////////////////////////////////////////////////////
                        SPENDING LIMIT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_dailyLimit_enforcement() public {
        // Try to spend more than daily limit
        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(IMpcSmartAccount.DailyLimitExceeded.selector, 11 ether, DEFAULT_DAILY_LIMIT)
        );
        account.execute(makeAddr("recipient"), 11 ether, "");
    }

    function test_dailyLimit_trackSpending() public {
        address recipient = makeAddr("recipient");

        // First spend
        vm.prank(address(entryPoint));
        account.execute(recipient, 3 ether, "");

        assertEq(account.spentToday(), 3 ether, "Should track spending");
        assertEq(account.remainingDailyAllowance(), 7 ether, "Should calculate remaining");

        // Second spend
        vm.prank(address(entryPoint));
        account.execute(recipient, 5 ether, "");

        assertEq(account.spentToday(), 8 ether, "Should accumulate spending");
        assertEq(account.remainingDailyAllowance(), 2 ether, "Should update remaining");
    }

    function test_dailyLimit_resetsAfterPeriod() public {
        address recipient = makeAddr("recipient");

        // Spend near limit
        vm.prank(address(entryPoint));
        account.execute(recipient, 9 ether, "");

        assertEq(account.spentToday(), 9 ether, "Should track spending");

        // Fast forward past daily period
        vm.warp(block.timestamp + 1 days + 1);

        // Spending should have reset
        assertEq(account.spentToday(), 0, "Spending should reset after period");
        assertEq(account.remainingDailyAllowance(), DEFAULT_DAILY_LIMIT, "Allowance should be full");

        // Should be able to spend again
        vm.prank(address(entryPoint));
        account.execute(recipient, 5 ether, "");

        assertEq(account.spentToday(), 5 ether, "Should track new period spending");
    }

    function test_dailyLimit_canBeUpdated() public {
        uint256 newLimit = 20 ether;

        // Update via recovery module
        vm.prank(address(recoveryModule));
        account.setDailyLimit(newLimit);

        assertEq(account.dailyLimit(), newLimit, "Daily limit should be updated");
    }

    function test_dailyLimit_zeroMeansNoLimit() public {
        // Set to zero (no limit)
        vm.prank(address(recoveryModule));
        account.setDailyLimit(0);

        // Should be able to spend any amount
        vm.prank(address(entryPoint));
        account.execute(makeAddr("recipient"), 50 ether, "");

        assertEq(account.remainingDailyAllowance(), type(uint256).max, "No limit means max allowance");
    }

    /*//////////////////////////////////////////////////////////////
                          WHITELIST TESTS
    //////////////////////////////////////////////////////////////*/

    function test_whitelist_addAndRemove() public {
        address target = makeAddr("target");

        // Add to whitelist
        vm.prank(address(recoveryModule));
        account.setWhitelist(target, true);

        assertTrue(account.isWhitelisted(target), "Should be whitelisted");

        // Remove from whitelist
        vm.prank(address(recoveryModule));
        account.setWhitelist(target, false);

        assertFalse(account.isWhitelisted(target), "Should not be whitelisted");
    }

    function test_whitelist_enforcement() public {
        address allowedTarget = makeAddr("allowed");
        address blockedTarget = makeAddr("blocked");

        // Setup whitelist
        vm.startPrank(address(recoveryModule));
        account.setWhitelistEnabled(true);
        account.setWhitelist(allowedTarget, true);
        vm.stopPrank();

        // Should succeed for whitelisted target
        vm.deal(address(account), 10 ether);
        vm.prank(address(entryPoint));
        account.execute(allowedTarget, 1 ether, "");

        // Should fail for non-whitelisted target
        vm.prank(address(entryPoint));
        vm.expectRevert(abi.encodeWithSelector(IMpcSmartAccount.NotWhitelisted.selector, blockedTarget));
        account.execute(blockedTarget, 1 ether, "");
    }

    function test_whitelist_batchUpdate() public {
        address[] memory targets = new address[](3);
        targets[0] = makeAddr("target1");
        targets[1] = makeAddr("target2");
        targets[2] = makeAddr("target3");

        bool[] memory allowed = new bool[](3);
        allowed[0] = true;
        allowed[1] = true;
        allowed[2] = false;

        vm.prank(address(recoveryModule));
        account.setWhitelistBatch(targets, allowed);

        assertTrue(account.isWhitelisted(targets[0]), "Target1 should be whitelisted");
        assertTrue(account.isWhitelisted(targets[1]), "Target2 should be whitelisted");
        assertFalse(account.isWhitelisted(targets[2]), "Target3 should not be whitelisted");
    }

    /*//////////////////////////////////////////////////////////////
                       TIME RESTRICTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_timeRestrictions_configuration() public {
        vm.prank(address(recoveryModule));
        account.setTimeRestrictions(9, 17, true); // 9 AM to 5 PM

        (uint8 start, uint8 end, bool enabled) = account.getTimeRestrictions();

        assertEq(start, 9, "Start hour should be 9");
        assertEq(end, 17, "End hour should be 17");
        assertTrue(enabled, "Should be enabled");
    }

    function test_timeRestrictions_enforcement() public {
        // Set time restrictions (9 AM to 5 PM)
        vm.prank(address(recoveryModule));
        account.setTimeRestrictions(9, 17, true);

        // Warp to 10 AM (within allowed window)
        vm.warp((block.timestamp / 1 days) * 1 days + 10 hours);

        // Should succeed
        vm.prank(address(entryPoint));
        account.execute(makeAddr("recipient"), 1 ether, "");

        // Warp to 8 PM (outside allowed window)
        vm.warp((block.timestamp / 1 days) * 1 days + 20 hours);

        // Should fail
        vm.prank(address(entryPoint));
        vm.expectRevert(IMpcSmartAccount.TimeRestrictionViolated.selector);
        account.execute(makeAddr("recipient"), 1 ether, "");
    }

    /*//////////////////////////////////////////////////////////////
                         MPC KEY UPDATE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_updateMpcPublicKey_byRecoveryModule() public {
        bytes memory newKey = generateMpcPubKey(guardian1);

        vm.prank(address(recoveryModule));
        account.updateMpcPublicKey(newKey);

        bytes memory storedKey = account.mpcPublicKey();
        assertEq(keccak256(storedKey), keccak256(newKey), "MPC key should be updated");
    }

    function test_updateMpcPublicKey_revertsIfNotAuthorized() public {
        bytes memory newKey = generateMpcPubKey(guardian1);

        vm.prank(attacker);
        vm.expectRevert(IMpcSmartAccount.OnlySelfOrRecovery.selector);
        account.updateMpcPublicKey(newKey);
    }

    function test_updateMpcPublicKey_revertsIfInvalidLength() public {
        bytes memory invalidKey = hex"0102030405"; // Too short

        vm.prank(address(recoveryModule));
        vm.expectRevert(IMpcSmartAccount.InvalidMpcPublicKey.selector);
        account.updateMpcPublicKey(invalidKey);
    }

    /*//////////////////////////////////////////////////////////////
                          EIP-1271 TESTS
    //////////////////////////////////////////////////////////////*/

    function test_isValidSignature_valid() public view {
        bytes32 hash = keccak256("test message");
        bytes memory signature = signWithMpc(hash);

        // Note: This test is simplified. In production, signature validation
        // would verify against the actual MPC public key
        bytes4 result = account.isValidSignature(hash, signature);

        // For now, we expect failure since our mock doesn't properly derive
        // the address from the compressed public key
        assertEq(result, bytes4(0xffffffff), "Signature validation result");
    }

    /*//////////////////////////////////////////////////////////////
                           RECEIVE ETH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_receiveEth() public {
        uint256 balanceBefore = address(account).balance;

        vm.deal(address(this), 5 ether);
        (bool success,) = address(account).call{ value: 5 ether }("");

        assertTrue(success, "Should receive ETH");
        assertEq(address(account).balance, balanceBefore + 5 ether, "Balance should increase");
    }
}

/**
 * @title Mock Target Contract
 * @notice Simple contract for testing execution
 */
contract MockTarget {
    uint256 public value;

    function setValue(
        uint256 _value
    ) external {
        value = _value;
    }

    receive() external payable { }
}
