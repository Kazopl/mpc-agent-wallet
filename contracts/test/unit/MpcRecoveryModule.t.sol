// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BaseTest } from "../Base.t.sol";
import { MpcSmartAccount } from "../../src/MpcSmartAccount.sol";
import { MpcRecoveryModule } from "../../src/modules/MpcRecoveryModule.sol";
import { IMpcRecoveryModule } from "../../src/interfaces/IMpcRecoveryModule.sol";

/**
 * @title MpcRecoveryModule Tests
 * @notice Unit tests for MPC key recovery functionality
 */
contract MpcRecoveryModuleTest is BaseTest {
    MpcSmartAccount public account;
    address[] public guardians;

    function setUp() public override {
        super.setUp();

        // Create account
        account = createDefaultAccount(0);
        vm.deal(address(account), 100 ether);

        // Setup guardians array
        guardians = new address[](2);
        guardians[0] = guardian1;
        guardians[1] = guardian2;

        // Initialize recovery module for the account
        vm.prank(address(account));
        recoveryModule.initialize(guardians, 2 days);
    }

    /*//////////////////////////////////////////////////////////////
                       INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_initialization() public view {
        assertEq(recoveryModule.getRecoveryDelay(address(account)), 2 days, "Recovery delay should be set");

        assertTrue(recoveryModule.isGuardian(address(account), guardian1), "Guardian1 should be set");
        assertTrue(recoveryModule.isGuardian(address(account), guardian2), "Guardian2 should be set");
        assertFalse(recoveryModule.isGuardian(address(account), guardian3), "Guardian3 should not be set");
    }

    function test_getGuardians() public view {
        address[] memory storedGuardians = recoveryModule.getGuardians(address(account));

        assertEq(storedGuardians.length, 2, "Should have 2 guardians");
        assertEq(storedGuardians[0], guardian1, "First guardian should match");
        assertEq(storedGuardians[1], guardian2, "Second guardian should match");
    }

    /*//////////////////////////////////////////////////////////////
                      GUARDIAN MANAGEMENT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_addGuardian() public {
        vm.prank(address(account));
        recoveryModule.addGuardian(guardian3);

        assertTrue(recoveryModule.isGuardian(address(account), guardian3), "Guardian3 should be added");

        address[] memory storedGuardians = recoveryModule.getGuardians(address(account));
        assertEq(storedGuardians.length, 3, "Should have 3 guardians");
    }

    function test_addGuardian_revertsIfAlreadyExists() public {
        vm.prank(address(account));
        vm.expectRevert(IMpcRecoveryModule.GuardianAlreadyExists.selector);
        recoveryModule.addGuardian(guardian1);
    }

    function test_removeGuardian() public {
        // First add a third guardian so we can remove one
        vm.prank(address(account));
        recoveryModule.addGuardian(guardian3);

        // Now remove guardian2
        vm.prank(address(account));
        recoveryModule.removeGuardian(guardian2);

        assertFalse(recoveryModule.isGuardian(address(account), guardian2), "Guardian2 should be removed");

        address[] memory storedGuardians = recoveryModule.getGuardians(address(account));
        assertEq(storedGuardians.length, 2, "Should have 2 guardians");
    }

    function test_removeGuardian_revertsIfLastGuardian() public {
        // Remove guardian2 first
        vm.prank(address(account));
        recoveryModule.removeGuardian(guardian2);

        // Try to remove guardian1 (last one)
        vm.prank(address(account));
        vm.expectRevert(IMpcRecoveryModule.CannotRemoveLastGuardian.selector);
        recoveryModule.removeGuardian(guardian1);
    }

    function test_removeGuardian_cancelsPendingRecovery() public {
        bytes memory newKey = generateMpcPubKey(guardian3);

        // Initiate recovery
        vm.prank(guardian1);
        recoveryModule.initiateRecovery(address(account), newKey);

        IMpcRecoveryModule.RecoveryRequest memory requestBefore = recoveryModule.getRecoveryRequest(address(account));
        assertTrue(requestBefore.executeAfter > 0, "Recovery should be pending");

        // Add guardian3 first
        vm.prank(address(account));
        recoveryModule.addGuardian(guardian3);

        // Remove a guardian - should cancel pending recovery
        vm.prank(address(account));
        recoveryModule.removeGuardian(guardian2);

        IMpcRecoveryModule.RecoveryRequest memory requestAfter = recoveryModule.getRecoveryRequest(address(account));
        assertEq(requestAfter.executeAfter, 0, "Recovery should be cancelled");
    }

    /*//////////////////////////////////////////////////////////////
                       RECOVERY INITIATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_initiateRecovery() public {
        bytes memory newKey = generateMpcPubKey(guardian3);

        vm.prank(guardian1);
        recoveryModule.initiateRecovery(address(account), newKey);

        IMpcRecoveryModule.RecoveryRequest memory request = recoveryModule.getRecoveryRequest(address(account));

        assertEq(keccak256(request.newMpcPublicKey), keccak256(newKey), "New key should match");
        assertEq(request.initiator, guardian1, "Initiator should be guardian1");
        assertEq(request.executeAfter, block.timestamp + 2 days, "Execute after should be delay from now");
        assertFalse(request.executed, "Should not be executed");
    }

    function test_initiateRecovery_revertsIfNotGuardian() public {
        bytes memory newKey = generateMpcPubKey(guardian3);

        vm.prank(attacker);
        vm.expectRevert(IMpcRecoveryModule.NotGuardian.selector);
        recoveryModule.initiateRecovery(address(account), newKey);
    }

    function test_initiateRecovery_revertsIfAlreadyPending() public {
        bytes memory newKey = generateMpcPubKey(guardian3);

        // First initiation
        vm.prank(guardian1);
        recoveryModule.initiateRecovery(address(account), newKey);

        // Second initiation should revert
        vm.prank(guardian2);
        vm.expectRevert(IMpcRecoveryModule.RecoveryAlreadyPending.selector);
        recoveryModule.initiateRecovery(address(account), newKey);
    }

    function test_initiateRecovery_revertsIfInvalidKey() public {
        bytes memory invalidKey = hex"0102030405"; // Too short

        vm.prank(guardian1);
        vm.expectRevert(IMpcRecoveryModule.InvalidMpcPublicKey.selector);
        recoveryModule.initiateRecovery(address(account), invalidKey);
    }

    /*//////////////////////////////////////////////////////////////
                       RECOVERY EXECUTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_executeRecovery() public {
        bytes memory newKey = generateMpcPubKey(guardian3);
        bytes memory oldKey = account.mpcPublicKey();

        // Initiate recovery
        vm.prank(guardian1);
        recoveryModule.initiateRecovery(address(account), newKey);

        // Fast forward past delay
        vm.warp(block.timestamp + 2 days + 1);

        // Execute recovery
        recoveryModule.executeRecovery(address(account));

        // Verify key was updated
        bytes memory currentKey = account.mpcPublicKey();
        assertEq(keccak256(currentKey), keccak256(newKey), "MPC key should be updated");
        assertTrue(keccak256(currentKey) != keccak256(oldKey), "Key should have changed");

        // Verify request is marked as executed
        IMpcRecoveryModule.RecoveryRequest memory request = recoveryModule.getRecoveryRequest(address(account));
        assertTrue(request.executed, "Request should be marked executed");
    }

    function test_executeRecovery_revertsIfNotInitiated() public {
        vm.expectRevert(IMpcRecoveryModule.RecoveryNotInitiated.selector);
        recoveryModule.executeRecovery(address(account));
    }

    function test_executeRecovery_revertsIfDelayNotPassed() public {
        bytes memory newKey = generateMpcPubKey(guardian3);

        vm.prank(guardian1);
        recoveryModule.initiateRecovery(address(account), newKey);

        // Try to execute before delay
        vm.warp(block.timestamp + 1 days); // Only 1 day passed

        vm.expectRevert(IMpcRecoveryModule.RecoveryDelayNotPassed.selector);
        recoveryModule.executeRecovery(address(account));
    }

    function test_executeRecovery_revertsIfAlreadyExecuted() public {
        bytes memory newKey = generateMpcPubKey(guardian3);

        vm.prank(guardian1);
        recoveryModule.initiateRecovery(address(account), newKey);

        vm.warp(block.timestamp + 2 days + 1);
        recoveryModule.executeRecovery(address(account));

        // Try to execute again
        vm.expectRevert(IMpcRecoveryModule.RecoveryAlreadyExecuted.selector);
        recoveryModule.executeRecovery(address(account));
    }

    /*//////////////////////////////////////////////////////////////
                      RECOVERY CANCELLATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_cancelRecovery_byAccount() public {
        bytes memory newKey = generateMpcPubKey(guardian3);

        vm.prank(guardian1);
        recoveryModule.initiateRecovery(address(account), newKey);

        // Cancel by account
        vm.prank(address(account));
        recoveryModule.cancelRecovery(address(account));

        IMpcRecoveryModule.RecoveryRequest memory request = recoveryModule.getRecoveryRequest(address(account));
        assertEq(request.executeAfter, 0, "Recovery should be cancelled");
    }

    function test_cancelRecovery_byGuardian() public {
        bytes memory newKey = generateMpcPubKey(guardian3);

        vm.prank(guardian1);
        recoveryModule.initiateRecovery(address(account), newKey);

        // Cancel by guardian2
        vm.prank(guardian2);
        recoveryModule.cancelRecovery(address(account));

        IMpcRecoveryModule.RecoveryRequest memory request = recoveryModule.getRecoveryRequest(address(account));
        assertEq(request.executeAfter, 0, "Recovery should be cancelled");
    }

    function test_cancelRecovery_revertsIfNotAuthorized() public {
        bytes memory newKey = generateMpcPubKey(guardian3);

        vm.prank(guardian1);
        recoveryModule.initiateRecovery(address(account), newKey);

        // Try to cancel by attacker
        vm.prank(attacker);
        vm.expectRevert(IMpcRecoveryModule.OnlyAccountOrGuardian.selector);
        recoveryModule.cancelRecovery(address(account));
    }

    function test_cancelRecovery_revertsIfNotPending() public {
        vm.prank(address(account));
        vm.expectRevert(IMpcRecoveryModule.RecoveryNotInitiated.selector);
        recoveryModule.cancelRecovery(address(account));
    }

    /*//////////////////////////////////////////////////////////////
                      CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setRecoveryDelay() public {
        uint256 newDelay = 7 days;

        vm.prank(address(account));
        recoveryModule.setRecoveryDelay(newDelay);

        assertEq(recoveryModule.getRecoveryDelay(address(account)), newDelay, "Delay should be updated");
    }

    function test_setRecoveryDelay_revertsIfTooShort() public {
        vm.prank(address(account));
        vm.expectRevert(IMpcRecoveryModule.RecoveryDelayTooShort.selector);
        recoveryModule.setRecoveryDelay(30 minutes); // Below minimum
    }

    function test_setRecoveryDelay_revertsIfTooLong() public {
        vm.prank(address(account));
        vm.expectRevert(IMpcRecoveryModule.RecoveryDelayTooShort.selector);
        recoveryModule.setRecoveryDelay(60 days); // Above maximum
    }

    /*//////////////////////////////////////////////////////////////
                          HELPER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_canExecuteRecovery() public {
        bytes memory newKey = generateMpcPubKey(guardian3);

        assertFalse(recoveryModule.canExecuteRecovery(address(account)), "Should not be executable initially");

        vm.prank(guardian1);
        recoveryModule.initiateRecovery(address(account), newKey);

        assertFalse(recoveryModule.canExecuteRecovery(address(account)), "Should not be executable during delay");

        vm.warp(block.timestamp + 2 days + 1);

        assertTrue(recoveryModule.canExecuteRecovery(address(account)), "Should be executable after delay");

        recoveryModule.executeRecovery(address(account));

        assertFalse(recoveryModule.canExecuteRecovery(address(account)), "Should not be executable after execution");
    }

    function test_getTimeUntilExecution() public {
        bytes memory newKey = generateMpcPubKey(guardian3);

        assertEq(recoveryModule.getTimeUntilExecution(address(account)), 0, "Should be 0 with no pending recovery");

        vm.prank(guardian1);
        recoveryModule.initiateRecovery(address(account), newKey);

        assertEq(recoveryModule.getTimeUntilExecution(address(account)), 2 days, "Should be 2 days");

        vm.warp(block.timestamp + 1 days);

        assertEq(recoveryModule.getTimeUntilExecution(address(account)), 1 days, "Should be 1 day");

        vm.warp(block.timestamp + 1 days + 1);

        assertEq(recoveryModule.getTimeUntilExecution(address(account)), 0, "Should be 0 when ready");
    }
}
