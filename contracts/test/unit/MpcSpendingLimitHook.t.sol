// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BaseTest } from "../Base.t.sol";
import { MpcSpendingLimitHook } from "../../src/modules/MpcSpendingLimitHook.sol";
import { ISpendingLimitHook } from "../../src/interfaces/ISpendingLimitHook.sol";

/**
 * @title MpcSpendingLimitHook Tests
 * @notice Unit tests for spending limit enforcement
 */
contract MpcSpendingLimitHookTest is BaseTest {
    address public account;

    // Test addresses
    address public target1;
    address public target2;
    address public mockToken;

    function setUp() public override {
        super.setUp();

        account = makeAddr("account");
        target1 = makeAddr("target1");
        target2 = makeAddr("target2");
        mockToken = makeAddr("mockToken");

        vm.deal(account, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_configureSpending() public {
        vm.prank(account);
        spendingLimitHook.configureSpending(1 ether, 10 ether, 50 ether, false);

        ISpendingLimitHook.SpendingConfig memory config = spendingLimitHook.getConfig(account);

        assertEq(config.txLimit, 1 ether, "TX limit should be set");
        assertEq(config.dailyLimit, 10 ether, "Daily limit should be set");
        assertEq(config.weeklyLimit, 50 ether, "Weekly limit should be set");
        assertFalse(config.whitelistOnly, "Whitelist only should be false");
        assertTrue(config.enabled, "Should be enabled");
    }

    function test_configureSpending_revertsIfInvalidLimits() public {
        // Weekly limit less than daily limit
        vm.prank(account);
        vm.expectRevert(ISpendingLimitHook.InvalidLimit.selector);
        spendingLimitHook.configureSpending(1 ether, 50 ether, 10 ether, false);
    }

    function test_configureTokenLimit() public {
        vm.prank(account);
        spendingLimitHook.configureTokenLimit(mockToken, 1000 ether);

        ISpendingLimitHook.TokenLimit memory limit = spendingLimitHook.getTokenLimit(account, mockToken);

        assertEq(limit.dailyLimit, 1000 ether, "Token limit should be set");
        assertTrue(limit.enabled, "Should be enabled");
    }

    /*//////////////////////////////////////////////////////////////
                        WHITELIST TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setWhitelist() public {
        vm.prank(account);
        spendingLimitHook.setWhitelist(target1, true);

        assertTrue(spendingLimitHook.isWhitelisted(account, target1), "Should be whitelisted");
        assertFalse(spendingLimitHook.isWhitelisted(account, target2), "Should not be whitelisted");
    }

    function test_setWhitelistBatch() public {
        address[] memory targets = new address[](2);
        targets[0] = target1;
        targets[1] = target2;

        bool[] memory allowed = new bool[](2);
        allowed[0] = true;
        allowed[1] = true;

        vm.prank(account);
        spendingLimitHook.setWhitelistBatch(targets, allowed);

        assertTrue(spendingLimitHook.isWhitelisted(account, target1), "Target1 should be whitelisted");
        assertTrue(spendingLimitHook.isWhitelisted(account, target2), "Target2 should be whitelisted");
    }

    function test_whitelistEnforcement() public {
        // Configure with whitelist enforcement
        vm.startPrank(account);
        spendingLimitHook.configureSpending(1 ether, 10 ether, 50 ether, true);
        spendingLimitHook.setWhitelist(target1, true);
        vm.stopPrank();

        // Should succeed for whitelisted target
        vm.prank(account);
        spendingLimitHook.preHook(target1, 0.5 ether, "");

        // Should fail for non-whitelisted target
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(ISpendingLimitHook.TargetNotWhitelisted.selector, target2));
        spendingLimitHook.preHook(target2, 0.5 ether, "");
    }

    /*//////////////////////////////////////////////////////////////
                        ETH SPENDING LIMIT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_preHook_txLimitEnforcement() public {
        vm.prank(account);
        spendingLimitHook.configureSpending(1 ether, 10 ether, 50 ether, false);

        // Should succeed under limit
        vm.prank(account);
        spendingLimitHook.preHook(target1, 0.5 ether, "");

        // Should fail over limit
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(ISpendingLimitHook.TransactionLimitExceeded.selector, 2 ether, 1 ether));
        spendingLimitHook.preHook(target1, 2 ether, "");
    }

    function test_preHook_dailyLimitEnforcement() public {
        vm.prank(account);
        spendingLimitHook.configureSpending(5 ether, 10 ether, 50 ether, false);

        // First transaction
        vm.prank(account);
        bytes memory hookData1 = spendingLimitHook.preHook(target1, 4 ether, "");

        // Record spending
        vm.prank(account);
        spendingLimitHook.postHook(hookData1, true, "");

        // Second transaction
        vm.prank(account);
        bytes memory hookData2 = spendingLimitHook.preHook(target1, 4 ether, "");

        vm.prank(account);
        spendingLimitHook.postHook(hookData2, true, "");

        // Third transaction should exceed daily limit
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(ISpendingLimitHook.DailyLimitExceeded.selector, 11 ether, 10 ether));
        spendingLimitHook.preHook(target1, 3 ether, "");
    }

    function test_preHook_weeklyLimitEnforcement() public {
        vm.prank(account);
        spendingLimitHook.configureSpending(20 ether, 25 ether, 50 ether, false);

        // Spend across multiple days
        for (uint256 i = 0; i < 2; i++) {
            vm.prank(account);
            bytes memory hookData = spendingLimitHook.preHook(target1, 20 ether, "");

            vm.prank(account);
            spendingLimitHook.postHook(hookData, true, "");

            vm.warp(block.timestamp + 1 days);
        }

        // Should exceed weekly limit
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(ISpendingLimitHook.WeeklyLimitExceeded.selector, 60 ether, 50 ether));
        spendingLimitHook.preHook(target1, 20 ether, "");
    }

    /*//////////////////////////////////////////////////////////////
                       SPENDING TRACKER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_getSpending() public {
        vm.prank(account);
        spendingLimitHook.configureSpending(10 ether, 20 ether, 100 ether, false);

        // Initial state
        (uint256 dailySpent, uint256 weeklySpent, uint256 dailyRemaining, uint256 weeklyRemaining) =
            spendingLimitHook.getSpending(account);

        assertEq(dailySpent, 0, "Daily spent should be 0");
        assertEq(weeklySpent, 0, "Weekly spent should be 0");
        assertEq(dailyRemaining, 20 ether, "Daily remaining should be limit");
        assertEq(weeklyRemaining, 100 ether, "Weekly remaining should be limit");

        // After spending
        vm.prank(account);
        bytes memory hookData = spendingLimitHook.preHook(target1, 5 ether, "");

        vm.prank(account);
        spendingLimitHook.postHook(hookData, true, "");

        (dailySpent, weeklySpent, dailyRemaining, weeklyRemaining) = spendingLimitHook.getSpending(account);

        assertEq(dailySpent, 5 ether, "Daily spent should be 5 ether");
        assertEq(weeklySpent, 5 ether, "Weekly spent should be 5 ether");
        assertEq(dailyRemaining, 15 ether, "Daily remaining should be 15 ether");
        assertEq(weeklyRemaining, 95 ether, "Weekly remaining should be 95 ether");
    }

    function test_dailyReset() public {
        vm.prank(account);
        spendingLimitHook.configureSpending(20 ether, 20 ether, 100 ether, false);

        // Spend some
        vm.prank(account);
        bytes memory hookData = spendingLimitHook.preHook(target1, 15 ether, "");

        vm.prank(account);
        spendingLimitHook.postHook(hookData, true, "");

        // Fast forward past daily period
        vm.warp(block.timestamp + 1 days + 1);

        // Daily spending should reset
        (uint256 dailySpent,,,) = spendingLimitHook.getSpending(account);
        assertEq(dailySpent, 0, "Daily spent should reset");
    }

    function test_weeklyReset() public {
        vm.prank(account);
        spendingLimitHook.configureSpending(10 ether, 50 ether, 100 ether, false);

        // Spend some
        vm.prank(account);
        bytes memory hookData = spendingLimitHook.preHook(target1, 10 ether, "");

        vm.prank(account);
        spendingLimitHook.postHook(hookData, true, "");

        // Fast forward past weekly period
        vm.warp(block.timestamp + 7 days + 1);

        // Weekly spending should reset
        (, uint256 weeklySpent,,) = spendingLimitHook.getSpending(account);
        assertEq(weeklySpent, 0, "Weekly spent should reset");
    }

    /*//////////////////////////////////////////////////////////////
                       TOKEN LIMIT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_tokenLimitEnforcement() public {
        vm.prank(account);
        spendingLimitHook.configureSpending(10 ether, 100 ether, 1000 ether, false);

        vm.prank(account);
        spendingLimitHook.configureTokenLimit(mockToken, 100 ether);

        // Encode ERC-20 transfer call
        bytes memory transferData = abi.encodeWithSignature("transfer(address,uint256)", target1, 50 ether);

        // Should succeed under limit
        vm.prank(account);
        spendingLimitHook.preHook(mockToken, 0, transferData);

        // Record spending
        bytes memory hookData =
            abi.encode(uint256(0), mockToken, bytes4(keccak256("transfer(address,uint256)")), uint256(50 ether));
        vm.prank(account);
        spendingLimitHook.postHook(hookData, true, "");

        // Should exceed limit
        bytes memory transferData2 = abi.encodeWithSignature("transfer(address,uint256)", target1, 60 ether);

        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(ISpendingLimitHook.TokenDailyLimitExceeded.selector, mockToken, 110 ether, 100 ether)
        );
        spendingLimitHook.preHook(mockToken, 0, transferData2);
    }

    function test_getTokenSpending() public {
        vm.prank(account);
        spendingLimitHook.configureTokenLimit(mockToken, 100 ether);

        (uint256 spent, uint256 remaining, uint256 resetTime) = spendingLimitHook.getTokenSpending(account, mockToken);

        assertEq(spent, 0, "Spent should be 0");
        assertEq(remaining, 100 ether, "Remaining should be limit");
        assertTrue(resetTime > block.timestamp, "Reset time should be in future");
    }

    /*//////////////////////////////////////////////////////////////
                      ENABLE/DISABLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setLimitsEnabled() public {
        vm.prank(account);
        spendingLimitHook.configureSpending(1 ether, 10 ether, 50 ether, false);

        // Disable limits
        vm.prank(account);
        spendingLimitHook.setLimitsEnabled(false);

        ISpendingLimitHook.SpendingConfig memory config = spendingLimitHook.getConfig(account);
        assertFalse(config.enabled, "Should be disabled");

        // Should allow any amount when disabled
        vm.prank(account);
        spendingLimitHook.preHook(target1, 100 ether, "");
    }

    /*//////////////////////////////////////////////////////////////
                        POST HOOK TESTS
    //////////////////////////////////////////////////////////////*/

    function test_postHook_recordsSpending() public {
        vm.prank(account);
        spendingLimitHook.configureSpending(10 ether, 100 ether, 1000 ether, false);

        vm.prank(account);
        bytes memory hookData = spendingLimitHook.preHook(target1, 5 ether, "");

        vm.prank(account);
        spendingLimitHook.postHook(hookData, true, "");

        (uint256 dailySpent, uint256 weeklySpent,,) = spendingLimitHook.getSpending(account);

        assertEq(dailySpent, 5 ether, "Daily spent should be recorded");
        assertEq(weeklySpent, 5 ether, "Weekly spent should be recorded");
    }

    function test_postHook_doesNotRecordOnFailure() public {
        vm.prank(account);
        spendingLimitHook.configureSpending(10 ether, 100 ether, 1000 ether, false);

        vm.prank(account);
        bytes memory hookData = spendingLimitHook.preHook(target1, 5 ether, "");

        // Call postHook with success=false
        vm.prank(account);
        spendingLimitHook.postHook(hookData, false, "");

        (uint256 dailySpent,,,) = spendingLimitHook.getSpending(account);

        assertEq(dailySpent, 0, "Spending should not be recorded on failure");
    }

    /*//////////////////////////////////////////////////////////////
                          ZERO LIMIT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_zeroLimits_meansNoLimit() public {
        vm.prank(account);
        spendingLimitHook.configureSpending(0, 0, 0, false);

        // Should allow any amount
        vm.prank(account);
        spendingLimitHook.preHook(target1, 1000 ether, "");

        (,, uint256 dailyRemaining, uint256 weeklyRemaining) = spendingLimitHook.getSpending(account);

        assertEq(dailyRemaining, type(uint256).max, "Daily remaining should be max");
        assertEq(weeklyRemaining, type(uint256).max, "Weekly remaining should be max");
    }
}
