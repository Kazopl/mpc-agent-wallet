// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Test, console2 } from "forge-std/Test.sol";
import { MpcPaymaster } from "../../src/MpcPaymaster.sol";
import { IMpcPaymaster } from "../../src/interfaces/IMpcPaymaster.sol";
import { IEntryPoint } from "../../src/interfaces/IEntryPoint.sol";
import { BaseTest, MockEntryPoint } from "../Base.t.sol";

/**
 * @title MpcPaymaster Unit Tests
 * @notice Tests for the MpcPaymaster contract
 */
contract MpcPaymasterTest is BaseTest {
    /*//////////////////////////////////////////////////////////////
                               CONTRACTS
    //////////////////////////////////////////////////////////////*/

    MpcPaymaster public paymaster;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 public constant GLOBAL_DAILY_LIMIT = 100 ether;
    uint256 public constant DEFAULT_ACCOUNT_LIMIT = 10 ether;
    uint256 public constant DEFAULT_DAILY_ACCOUNT_LIMIT = 1 ether;

    /*//////////////////////////////////////////////////////////////
                                ACTORS
    //////////////////////////////////////////////////////////////*/

    address public paymasterOwner;
    address public sponsoredAccount1;
    address public sponsoredAccount2;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        // Create actors
        (paymasterOwner,) = makeAddrAndKey("paymasterOwner");
        (sponsoredAccount1,) = makeAddrAndKey("sponsoredAccount1");
        (sponsoredAccount2,) = makeAddrAndKey("sponsoredAccount2");

        // Deploy paymaster
        paymaster = new MpcPaymaster(
            IEntryPoint(address(entryPoint)),
            paymasterOwner,
            GLOBAL_DAILY_LIMIT
        );

        // Fund paymaster
        vm.deal(paymasterOwner, 1000 ether);
        vm.prank(paymasterOwner);
        paymaster.deposit{ value: 100 ether }();
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsParameters() public view {
        assertEq(address(paymaster.entryPoint()), address(entryPoint));
        assertEq(paymaster.owner(), paymasterOwner);
        assertEq(paymaster.globalDailyLimit(), GLOBAL_DAILY_LIMIT);
    }

    function test_Constructor_RevertOnZeroEntryPoint() public {
        vm.expectRevert(IMpcPaymaster.ZeroAddress.selector);
        new MpcPaymaster(IEntryPoint(address(0)), paymasterOwner, GLOBAL_DAILY_LIMIT);
    }

    function test_Constructor_RevertOnZeroOwner() public {
        vm.expectRevert(IMpcPaymaster.ZeroAddress.selector);
        new MpcPaymaster(IEntryPoint(address(entryPoint)), address(0), GLOBAL_DAILY_LIMIT);
    }

    /*//////////////////////////////////////////////////////////////
                      SPONSORSHIP MANAGEMENT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SponsorAccount_Success() public {
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        assertTrue(paymaster.isSponsored(sponsoredAccount1));

        IMpcPaymaster.SponsorshipConfig memory config = paymaster.getSponsorshipConfig(sponsoredAccount1);
        assertTrue(config.active);
        assertEq(config.limit, DEFAULT_ACCOUNT_LIMIT);
        assertEq(config.dailyLimit, DEFAULT_DAILY_ACCOUNT_LIMIT);
        assertEq(config.spent, 0);
        assertEq(config.dailySpent, 0);
    }

    function test_SponsorAccount_EmitsEvent() public {
        vm.expectEmit(true, false, false, true);
        emit IMpcPaymaster.AccountSponsored(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);
    }

    function test_SponsorAccount_RevertOnNonOwner() public {
        vm.prank(attacker);
        vm.expectRevert(IMpcPaymaster.OnlyOwner.selector);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);
    }

    function test_SponsorAccount_RevertOnZeroAddress() public {
        vm.prank(paymasterOwner);
        vm.expectRevert(IMpcPaymaster.ZeroAddress.selector);
        paymaster.sponsorAccount(address(0), DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);
    }

    function test_SponsorAccount_RevertOnAlreadySponsored() public {
        vm.startPrank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        vm.expectRevert(abi.encodeWithSelector(IMpcPaymaster.AlreadySponsored.selector, sponsoredAccount1));
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);
        vm.stopPrank();
    }

    function test_SponsorAccountBatch_Success() public {
        address[] memory accounts = new address[](2);
        accounts[0] = sponsoredAccount1;
        accounts[1] = sponsoredAccount2;

        uint256[] memory limits = new uint256[](2);
        limits[0] = DEFAULT_ACCOUNT_LIMIT;
        limits[1] = DEFAULT_ACCOUNT_LIMIT * 2;

        uint256[] memory dailyLimits = new uint256[](2);
        dailyLimits[0] = DEFAULT_DAILY_ACCOUNT_LIMIT;
        dailyLimits[1] = DEFAULT_DAILY_ACCOUNT_LIMIT * 2;

        vm.prank(paymasterOwner);
        paymaster.sponsorAccountBatch(accounts, limits, dailyLimits);

        assertTrue(paymaster.isSponsored(sponsoredAccount1));
        assertTrue(paymaster.isSponsored(sponsoredAccount2));

        IMpcPaymaster.SponsorshipConfig memory config1 = paymaster.getSponsorshipConfig(sponsoredAccount1);
        assertEq(config1.limit, DEFAULT_ACCOUNT_LIMIT);

        IMpcPaymaster.SponsorshipConfig memory config2 = paymaster.getSponsorshipConfig(sponsoredAccount2);
        assertEq(config2.limit, DEFAULT_ACCOUNT_LIMIT * 2);
    }

    function test_RevokeSponsorshipFor_Success() public {
        // First sponsor
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        assertTrue(paymaster.isSponsored(sponsoredAccount1));

        // Then revoke
        vm.prank(paymasterOwner);
        paymaster.revokeSponsorshipFor(sponsoredAccount1);

        assertFalse(paymaster.isSponsored(sponsoredAccount1));
    }

    function test_RevokeSponsorshipFor_EmitsEvent() public {
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        vm.expectEmit(true, false, false, false);
        emit IMpcPaymaster.SponsorshipRevoked(sponsoredAccount1);

        vm.prank(paymasterOwner);
        paymaster.revokeSponsorshipFor(sponsoredAccount1);
    }

    function test_RevokeSponsorshipFor_RevertOnNotSponsored() public {
        vm.prank(paymasterOwner);
        vm.expectRevert(abi.encodeWithSelector(IMpcPaymaster.NotSponsored.selector, sponsoredAccount1));
        paymaster.revokeSponsorshipFor(sponsoredAccount1);
    }

    function test_UpdateSponsorshipLimits_Success() public {
        vm.startPrank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        uint256 newLimit = 50 ether;
        uint256 newDailyLimit = 5 ether;
        paymaster.updateSponsorshipLimits(sponsoredAccount1, newLimit, newDailyLimit);
        vm.stopPrank();

        IMpcPaymaster.SponsorshipConfig memory config = paymaster.getSponsorshipConfig(sponsoredAccount1);
        assertEq(config.limit, newLimit);
        assertEq(config.dailyLimit, newDailyLimit);
    }

    function test_SetGlobalDailyLimit_Success() public {
        uint256 newLimit = 200 ether;

        vm.prank(paymasterOwner);
        paymaster.setGlobalDailyLimit(newLimit);

        assertEq(paymaster.globalDailyLimit(), newLimit);
    }

    function test_TransferOwnership_Success() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(paymasterOwner);
        paymaster.transferOwnership(newOwner);

        assertEq(paymaster.owner(), newOwner);
    }

    /*//////////////////////////////////////////////////////////////
                           GETTER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetRemainingSponsorship_Unlimited() public {
        // Sponsor with unlimited (0) limits
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, 0, 0);

        (uint256 totalRemaining, uint256 dailyRemaining) = paymaster.getRemainingSponsorship(sponsoredAccount1);

        assertEq(totalRemaining, type(uint256).max);
        assertEq(dailyRemaining, type(uint256).max);
    }

    function test_GetRemainingSponsorship_WithLimits() public {
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        (uint256 totalRemaining, uint256 dailyRemaining) = paymaster.getRemainingSponsorship(sponsoredAccount1);

        assertEq(totalRemaining, DEFAULT_ACCOUNT_LIMIT);
        assertEq(dailyRemaining, DEFAULT_DAILY_ACCOUNT_LIMIT);
    }

    function test_GetRemainingSponsorship_NotSponsored() public view {
        (uint256 totalRemaining, uint256 dailyRemaining) = paymaster.getRemainingSponsorship(sponsoredAccount1);

        assertEq(totalRemaining, 0);
        assertEq(dailyRemaining, 0);
    }

    function test_GetGlobalDailyStats() public view {
        (uint256 limit, uint256 spent, uint256 remaining) = paymaster.getGlobalDailyStats();

        assertEq(limit, GLOBAL_DAILY_LIMIT);
        assertEq(spent, 0);
        assertEq(remaining, GLOBAL_DAILY_LIMIT);
    }

    function test_GetDeposit() public view {
        uint256 deposit = paymaster.getDeposit();
        assertEq(deposit, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                          FUNDING TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Deposit_Success() public {
        uint256 initialDeposit = paymaster.getDeposit();

        vm.deal(guardian1, 10 ether);
        vm.prank(guardian1);
        paymaster.deposit{ value: 5 ether }();

        assertEq(paymaster.getDeposit(), initialDeposit + 5 ether);
    }

    function test_Deposit_EmitsEvent() public {
        vm.deal(guardian1, 10 ether);

        vm.expectEmit(true, false, false, true);
        emit IMpcPaymaster.PaymasterFunded(guardian1, 5 ether);

        vm.prank(guardian1);
        paymaster.deposit{ value: 5 ether }();
    }

    function test_Receive_DepositsToEntryPoint() public {
        uint256 initialDeposit = paymaster.getDeposit();

        vm.deal(guardian1, 10 ether);
        vm.prank(guardian1);
        (bool success,) = address(paymaster).call{ value: 5 ether }("");
        assertTrue(success);

        assertEq(paymaster.getDeposit(), initialDeposit + 5 ether);
    }

    function test_WithdrawTo_Success() public {
        uint256 initialDeposit = paymaster.getDeposit();
        address payable recipient = payable(makeAddr("recipient"));

        vm.prank(paymasterOwner);
        paymaster.withdrawTo(recipient, 10 ether);

        assertEq(paymaster.getDeposit(), initialDeposit - 10 ether);
        assertEq(recipient.balance, 10 ether);
    }

    function test_WithdrawTo_RevertOnNonOwner() public {
        vm.prank(attacker);
        vm.expectRevert(IMpcPaymaster.OnlyOwner.selector);
        paymaster.withdrawTo(payable(attacker), 10 ether);
    }

    /*//////////////////////////////////////////////////////////////
                    VALIDATE PAYMASTER USEROP TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ValidatePaymasterUserOp_Success() public {
        // Sponsor account
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        // Create UserOp
        IEntryPoint.PackedUserOperation memory userOp = createUserOp(sponsoredAccount1, 0, "");

        uint256 maxCost = 0.1 ether;

        // Call from entryPoint
        vm.prank(address(entryPoint));
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(
            userOp,
            keccak256("test"),
            maxCost
        );

        assertEq(validationData, 0); // Success

        // Decode context
        (address account, uint256 cost) = abi.decode(context, (address, uint256));
        assertEq(account, sponsoredAccount1);
        assertEq(cost, maxCost);
    }

    function test_ValidatePaymasterUserOp_RevertOnNotSponsored() public {
        IEntryPoint.PackedUserOperation memory userOp = createUserOp(sponsoredAccount1, 0, "");

        vm.prank(address(entryPoint));
        vm.expectRevert(abi.encodeWithSelector(IMpcPaymaster.NotSponsored.selector, sponsoredAccount1));
        paymaster.validatePaymasterUserOp(userOp, keccak256("test"), 0.1 ether);
    }

    function test_ValidatePaymasterUserOp_RevertOnTotalLimitExceeded() public {
        // Sponsor with low limit
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, 0.05 ether, DEFAULT_DAILY_ACCOUNT_LIMIT);

        IEntryPoint.PackedUserOperation memory userOp = createUserOp(sponsoredAccount1, 0, "");

        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                IMpcPaymaster.SponsorshipLimitExceeded.selector,
                sponsoredAccount1,
                0.1 ether,
                0.05 ether
            )
        );
        paymaster.validatePaymasterUserOp(userOp, keccak256("test"), 0.1 ether);
    }

    function test_ValidatePaymasterUserOp_RevertOnDailyLimitExceeded() public {
        // Sponsor with low daily limit
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, 0.05 ether);

        IEntryPoint.PackedUserOperation memory userOp = createUserOp(sponsoredAccount1, 0, "");

        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                IMpcPaymaster.DailyLimitExceeded.selector,
                sponsoredAccount1,
                0.1 ether,
                0.05 ether
            )
        );
        paymaster.validatePaymasterUserOp(userOp, keccak256("test"), 0.1 ether);
    }

    function test_ValidatePaymasterUserOp_RevertOnGlobalLimitExceeded() public {
        // Set low global limit
        vm.prank(paymasterOwner);
        paymaster.setGlobalDailyLimit(0.05 ether);

        // Sponsor account with higher limit
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        IEntryPoint.PackedUserOperation memory userOp = createUserOp(sponsoredAccount1, 0, "");

        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                IMpcPaymaster.GlobalDailyLimitExceeded.selector,
                0.1 ether,
                0.05 ether
            )
        );
        paymaster.validatePaymasterUserOp(userOp, keccak256("test"), 0.1 ether);
    }

    function test_ValidatePaymasterUserOp_RevertOnInsufficientDeposit() public {
        // Withdraw most funds
        vm.prank(paymasterOwner);
        paymaster.withdrawTo(payable(paymasterOwner), 99.9 ether);

        // Sponsor account
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        IEntryPoint.PackedUserOperation memory userOp = createUserOp(sponsoredAccount1, 0, "");

        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                IMpcPaymaster.InsufficientDeposit.selector,
                0.2 ether, // requested maxCost
                0.1 ether  // remaining deposit
            )
        );
        paymaster.validatePaymasterUserOp(userOp, keccak256("test"), 0.2 ether);
    }

    function test_ValidatePaymasterUserOp_RevertOnNonEntryPoint() public {
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        IEntryPoint.PackedUserOperation memory userOp = createUserOp(sponsoredAccount1, 0, "");

        vm.prank(attacker);
        vm.expectRevert(IMpcPaymaster.OnlyEntryPoint.selector);
        paymaster.validatePaymasterUserOp(userOp, keccak256("test"), 0.1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                           POST OP TESTS
    //////////////////////////////////////////////////////////////*/

    function test_PostOp_RecordsSpending() public {
        // Sponsor account
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        bytes memory context = abi.encode(sponsoredAccount1, 0.1 ether);
        uint256 actualGasCost = 0.05 ether;

        vm.prank(address(entryPoint));
        paymaster.postOp(IMpcPaymaster.PostOpMode.OpSucceeded, context, actualGasCost, 10 gwei);

        IMpcPaymaster.SponsorshipConfig memory config = paymaster.getSponsorshipConfig(sponsoredAccount1);
        assertEq(config.spent, actualGasCost);
        assertEq(config.dailySpent, actualGasCost);
        assertEq(paymaster.globalDailySpent(), actualGasCost);
    }

    function test_PostOp_EmitsEvent() public {
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        bytes memory context = abi.encode(sponsoredAccount1, 0.1 ether);
        uint256 actualGasCost = 0.05 ether;

        vm.expectEmit(true, false, false, true);
        emit IMpcPaymaster.GasSponsored(sponsoredAccount1, actualGasCost, actualGasCost);

        vm.prank(address(entryPoint));
        paymaster.postOp(IMpcPaymaster.PostOpMode.OpSucceeded, context, actualGasCost, 10 gwei);
    }

    function test_PostOp_SkipsOnPostOpReverted() public {
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        bytes memory context = abi.encode(sponsoredAccount1, 0.1 ether);
        uint256 actualGasCost = 0.05 ether;

        vm.prank(address(entryPoint));
        paymaster.postOp(IMpcPaymaster.PostOpMode.PostOpReverted, context, actualGasCost, 10 gwei);

        // No spending recorded
        IMpcPaymaster.SponsorshipConfig memory config = paymaster.getSponsorshipConfig(sponsoredAccount1);
        assertEq(config.spent, 0);
    }

    function test_PostOp_RecordsOnOpReverted() public {
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        bytes memory context = abi.encode(sponsoredAccount1, 0.1 ether);
        uint256 actualGasCost = 0.05 ether;

        vm.prank(address(entryPoint));
        paymaster.postOp(IMpcPaymaster.PostOpMode.OpReverted, context, actualGasCost, 10 gwei);

        // Spending still recorded (gas was used even though op reverted)
        IMpcPaymaster.SponsorshipConfig memory config = paymaster.getSponsorshipConfig(sponsoredAccount1);
        assertEq(config.spent, actualGasCost);
    }

    /*//////////////////////////////////////////////////////////////
                        DAILY RESET TESTS
    //////////////////////////////////////////////////////////////*/

    function test_DailyReset_AccountSpending() public {
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        // Record some spending
        bytes memory context = abi.encode(sponsoredAccount1, 0.1 ether);
        vm.prank(address(entryPoint));
        paymaster.postOp(IMpcPaymaster.PostOpMode.OpSucceeded, context, 0.05 ether, 10 gwei);

        // Verify spending recorded
        IMpcPaymaster.SponsorshipConfig memory configBefore = paymaster.getSponsorshipConfig(sponsoredAccount1);
        assertEq(configBefore.dailySpent, 0.05 ether);

        // Advance time past daily reset
        vm.warp(block.timestamp + 1 days + 1);

        // Trigger a validation which will reset the period
        IEntryPoint.PackedUserOperation memory userOp = createUserOp(sponsoredAccount1, 0, "");
        vm.prank(address(entryPoint));
        paymaster.validatePaymasterUserOp(userOp, keccak256("test"), 0.01 ether);

        // Daily spent should be reset
        (,uint256 dailyRemaining) = paymaster.getRemainingSponsorship(sponsoredAccount1);
        assertEq(dailyRemaining, DEFAULT_DAILY_ACCOUNT_LIMIT);
    }

    function test_GlobalDailyReset() public {
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        // Record some spending
        bytes memory context = abi.encode(sponsoredAccount1, 0.1 ether);
        vm.prank(address(entryPoint));
        paymaster.postOp(IMpcPaymaster.PostOpMode.OpSucceeded, context, 0.05 ether, 10 gwei);

        assertEq(paymaster.globalDailySpent(), 0.05 ether);

        // Advance time past daily reset
        vm.warp(block.timestamp + 1 days + 1);

        // Trigger validation to reset global period
        IEntryPoint.PackedUserOperation memory userOp = createUserOp(sponsoredAccount1, 0, "");
        vm.prank(address(entryPoint));
        paymaster.validatePaymasterUserOp(userOp, keccak256("test"), 0.01 ether);

        // Global remaining should be full
        (,, uint256 remaining) = paymaster.getGlobalDailyStats();
        assertEq(remaining, GLOBAL_DAILY_LIMIT);
    }

    /*//////////////////////////////////////////////////////////////
                    UNLIMITED SPONSORSHIP TESTS
    //////////////////////////////////////////////////////////////*/

    function test_UnlimitedSponsorship() public {
        // Sponsor with unlimited (0 = unlimited)
        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, 0, 0);

        IEntryPoint.PackedUserOperation memory userOp = createUserOp(sponsoredAccount1, 0, "");

        // Should succeed with large amount
        vm.prank(address(entryPoint));
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(
            userOp,
            keccak256("test"),
            50 ether
        );

        assertEq(validationData, 0);
        assertTrue(context.length > 0);
    }

    function test_UnlimitedGlobalLimit() public {
        // Set global limit to 0 (unlimited)
        vm.prank(paymasterOwner);
        paymaster.setGlobalDailyLimit(0);

        vm.prank(paymasterOwner);
        paymaster.sponsorAccount(sponsoredAccount1, DEFAULT_ACCOUNT_LIMIT, DEFAULT_DAILY_ACCOUNT_LIMIT);

        IEntryPoint.PackedUserOperation memory userOp = createUserOp(sponsoredAccount1, 0, "");

        // Should succeed - global limit not applied when 0
        vm.prank(address(entryPoint));
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(
            userOp,
            keccak256("test"),
            0.5 ether
        );

        assertEq(validationData, 0);
        assertTrue(context.length > 0);
    }
}
