// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BaseTest, MockEntryPoint } from "../Base.t.sol";
import { MpcSmartAccount } from "../../src/MpcSmartAccount.sol";
import { MpcSessionKeyModule } from "../../src/modules/MpcSessionKeyModule.sol";
import { ISessionKeyModule } from "../../src/interfaces/ISessionKeyModule.sol";
import { IEntryPoint } from "../../src/interfaces/IEntryPoint.sol";

/**
 * @title MpcSessionKeyModule Tests
 * @notice Unit tests for session key functionality
 */
contract MpcSessionKeyModuleTest is BaseTest {
    MpcSmartAccount public account;

    // Additional session key signers
    address public sessionKey2;
    uint256 public sessionKey2Key;

    function setUp() public override {
        super.setUp();

        // Create additional session key
        (sessionKey2, sessionKey2Key) = makeAddrAndKey("sessionKey2");

        // Create account
        account = createDefaultAccount(0);

        // Fund account
        vm.deal(address(account), 100 ether);

        // Set session key module on account
        vm.prank(address(recoveryModule));
        account.setSessionKeyModule(address(sessionKeyModule));
    }

    /*//////////////////////////////////////////////////////////////
                      SESSION KEY CREATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_createSessionKey_basic() public {
        // Create session key params
        ISessionKeyModule.SessionKeyParams memory params = ISessionKeyModule.SessionKeyParams({
            signer: sessionKeySigner,
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            spendingLimit: 1 ether,
            whitelist: new address[](0),
            selectors: new bytes4[](0)
        });

        // Create session key from the account
        vm.prank(address(account));
        sessionKeyModule.createSessionKey(params);

        // Verify session key was created
        ISessionKeyModule.SessionKey memory sk = sessionKeyModule.getSessionKey(address(account), sessionKeySigner);
        assertEq(sk.signer, sessionKeySigner, "Signer should match");
        assertEq(sk.validAfter, params.validAfter, "ValidAfter should match");
        assertEq(sk.validUntil, params.validUntil, "ValidUntil should match");
        assertEq(sk.spendingLimit, 1 ether, "Spending limit should match");
        assertEq(sk.spent, 0, "Spent should be 0");
        assertFalse(sk.revoked, "Should not be revoked");
    }

    function test_createSessionKey_withWhitelist() public {
        address[] memory whitelist = new address[](2);
        whitelist[0] = makeAddr("allowed1");
        whitelist[1] = makeAddr("allowed2");

        ISessionKeyModule.SessionKeyParams memory params = ISessionKeyModule.SessionKeyParams({
            signer: sessionKeySigner,
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            spendingLimit: 1 ether,
            whitelist: whitelist,
            selectors: new bytes4[](0)
        });

        vm.prank(address(account));
        sessionKeyModule.createSessionKey(params);

        assertTrue(
            sessionKeyModule.isTargetAllowed(address(account), sessionKeySigner, whitelist[0]), "Should allow whitelist[0]"
        );
        assertTrue(
            sessionKeyModule.isTargetAllowed(address(account), sessionKeySigner, whitelist[1]), "Should allow whitelist[1]"
        );
        assertFalse(
            sessionKeyModule.isTargetAllowed(address(account), sessionKeySigner, makeAddr("blocked")),
            "Should not allow non-whitelisted"
        );
    }

    function test_createSessionKey_withSelectors() public {
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = bytes4(keccak256("transfer(address,uint256)"));
        selectors[1] = bytes4(keccak256("approve(address,uint256)"));

        ISessionKeyModule.SessionKeyParams memory params = ISessionKeyModule.SessionKeyParams({
            signer: sessionKeySigner,
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            spendingLimit: 1 ether,
            whitelist: new address[](0),
            selectors: selectors
        });

        vm.prank(address(account));
        sessionKeyModule.createSessionKey(params);

        assertTrue(
            sessionKeyModule.isSelectorAllowed(address(account), sessionKeySigner, selectors[0]),
            "Should allow selector[0]"
        );
        assertTrue(
            sessionKeyModule.isSelectorAllowed(address(account), sessionKeySigner, selectors[1]),
            "Should allow selector[1]"
        );
        assertFalse(
            sessionKeyModule.isSelectorAllowed(address(account), sessionKeySigner, bytes4(0xdeadbeef)),
            "Should not allow unlisted selector"
        );
    }

    function test_createSessionKey_revertsInvalidParams() public {
        // Zero signer
        ISessionKeyModule.SessionKeyParams memory params = ISessionKeyModule.SessionKeyParams({
            signer: address(0),
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            spendingLimit: 1 ether,
            whitelist: new address[](0),
            selectors: new bytes4[](0)
        });

        vm.prank(address(account));
        vm.expectRevert(ISessionKeyModule.InvalidSessionKeyParams.selector);
        sessionKeyModule.createSessionKey(params);
    }

    function test_createSessionKey_revertsInvalidTimeRange() public {
        // validUntil <= validAfter
        ISessionKeyModule.SessionKeyParams memory params = ISessionKeyModule.SessionKeyParams({
            signer: sessionKeySigner,
            validAfter: uint48(block.timestamp + 1 days),
            validUntil: uint48(block.timestamp),
            spendingLimit: 1 ether,
            whitelist: new address[](0),
            selectors: new bytes4[](0)
        });

        vm.prank(address(account));
        vm.expectRevert(ISessionKeyModule.InvalidSessionKeyParams.selector);
        sessionKeyModule.createSessionKey(params);
    }

    function test_createSessionKey_revertsExceedsMaxDuration() public {
        // Duration > 30 days
        ISessionKeyModule.SessionKeyParams memory params = ISessionKeyModule.SessionKeyParams({
            signer: sessionKeySigner,
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 31 days),
            spendingLimit: 1 ether,
            whitelist: new address[](0),
            selectors: new bytes4[](0)
        });

        vm.prank(address(account));
        vm.expectRevert(ISessionKeyModule.InvalidSessionKeyParams.selector);
        sessionKeyModule.createSessionKey(params);
    }

    /*//////////////////////////////////////////////////////////////
                      SESSION KEY REVOCATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_revokeSessionKey() public {
        // Create session key
        _createDefaultSessionKey();

        assertTrue(sessionKeyModule.isSessionKeyValid(address(account), sessionKeySigner), "Should be valid initially");

        // Revoke
        vm.prank(address(account));
        sessionKeyModule.revokeSessionKey(sessionKeySigner);

        // Verify revoked
        ISessionKeyModule.SessionKey memory sk = sessionKeyModule.getSessionKey(address(account), sessionKeySigner);
        assertTrue(sk.revoked, "Should be revoked");
        assertFalse(
            sessionKeyModule.isSessionKeyValid(address(account), sessionKeySigner), "Should not be valid after revocation"
        );
    }

    function test_revokeSessionKey_revertsNotFound() public {
        vm.prank(address(account));
        vm.expectRevert(ISessionKeyModule.SessionKeyNotFound.selector);
        sessionKeyModule.revokeSessionKey(makeAddr("unknown"));
    }

    /*//////////////////////////////////////////////////////////////
                       SIGNATURE VALIDATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_validateSessionKey_validSignature() public {
        _createDefaultSessionKey();

        bytes32 userOpHash = keccak256("test user op");
        bytes memory signature = signWithSessionKey(userOpHash, sessionKeySigner, sessionKeySignerKey);

        uint256 validationData =
            sessionKeyModule.validateSessionKey(address(account), userOpHash, signature);

        // Check that validation succeeds (time bounds in upper bits, 0 in lower bits)
        // The lower 160 bits should be 0 (no aggregator, no sig failure)
        assertEq(validationData & type(uint160).max, 0, "Should validate successfully");
    }

    function test_validateSessionKey_invalidSignature() public {
        _createDefaultSessionKey();

        bytes32 userOpHash = keccak256("test user op");
        // Sign with wrong key
        bytes memory signature = signWithSessionKey(userOpHash, sessionKeySigner, mpcSignerKey);

        uint256 validationData =
            sessionKeyModule.validateSessionKey(address(account), userOpHash, signature);

        // Should return 1 (SIG_VALIDATION_FAILED)
        assertEq(validationData, 1, "Should fail validation");
    }

    function test_validateSessionKey_revoked() public {
        _createDefaultSessionKey();

        // Revoke the session key
        vm.prank(address(account));
        sessionKeyModule.revokeSessionKey(sessionKeySigner);

        bytes32 userOpHash = keccak256("test user op");
        bytes memory signature = signWithSessionKey(userOpHash, sessionKeySigner, sessionKeySignerKey);

        uint256 validationData =
            sessionKeyModule.validateSessionKey(address(account), userOpHash, signature);

        assertEq(validationData, 1, "Should fail validation for revoked key");
    }

    /*//////////////////////////////////////////////////////////////
                    SPENDING VALIDATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_validateAndRecordSpending_success() public {
        _createDefaultSessionKey();

        address target = makeAddr("recipient");

        // Validate and record spending (called by account)
        vm.prank(address(account));
        sessionKeyModule.validateAndRecordSpending(address(account), sessionKeySigner, target, 0.5 ether, "");

        // Check spent amount
        ISessionKeyModule.SessionKey memory sk = sessionKeyModule.getSessionKey(address(account), sessionKeySigner);
        assertEq(sk.spent, 0.5 ether, "Should record spending");

        // Check remaining
        uint256 remaining = sessionKeyModule.getRemainingSpending(address(account), sessionKeySigner);
        assertEq(remaining, 0.5 ether, "Should have 0.5 ETH remaining");
    }

    function test_validateAndRecordSpending_exceedsLimit() public {
        _createDefaultSessionKey();

        address target = makeAddr("recipient");

        vm.prank(address(account));
        vm.expectRevert(
            abi.encodeWithSelector(ISessionKeyModule.SessionKeySpendingLimitExceeded.selector, 1.5 ether, 1 ether)
        );
        sessionKeyModule.validateAndRecordSpending(address(account), sessionKeySigner, target, 1.5 ether, "");
    }

    function test_validateAndRecordSpending_targetNotWhitelisted() public {
        // Create session key with whitelist
        address[] memory whitelist = new address[](1);
        whitelist[0] = makeAddr("allowed");

        ISessionKeyModule.SessionKeyParams memory params = ISessionKeyModule.SessionKeyParams({
            signer: sessionKeySigner,
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            spendingLimit: 1 ether,
            whitelist: whitelist,
            selectors: new bytes4[](0)
        });

        vm.prank(address(account));
        sessionKeyModule.createSessionKey(params);

        address blockedTarget = makeAddr("blocked");

        vm.prank(address(account));
        vm.expectRevert(abi.encodeWithSelector(ISessionKeyModule.SessionKeyTargetNotWhitelisted.selector, blockedTarget));
        sessionKeyModule.validateAndRecordSpending(address(account), sessionKeySigner, blockedTarget, 0.1 ether, "");
    }

    function test_validateAndRecordSpending_selectorNotAllowed() public {
        // Create session key with selector restriction
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(keccak256("transfer(address,uint256)"));

        ISessionKeyModule.SessionKeyParams memory params = ISessionKeyModule.SessionKeyParams({
            signer: sessionKeySigner,
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            spendingLimit: 1 ether,
            whitelist: new address[](0),
            selectors: selectors
        });

        vm.prank(address(account));
        sessionKeyModule.createSessionKey(params);

        address target = makeAddr("target");
        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", target, 100);

        vm.prank(address(account));
        vm.expectRevert(
            abi.encodeWithSelector(
                ISessionKeyModule.SessionKeySelectorNotAllowed.selector, bytes4(keccak256("approve(address,uint256)"))
            )
        );
        sessionKeyModule.validateAndRecordSpending(address(account), sessionKeySigner, target, 0, data);
    }

    function test_validateAndRecordSpending_expired() public {
        _createDefaultSessionKey();

        // Fast forward past expiry
        vm.warp(block.timestamp + 2 days);

        address target = makeAddr("recipient");

        vm.prank(address(account));
        vm.expectRevert(ISessionKeyModule.SessionKeyExpired.selector);
        sessionKeyModule.validateAndRecordSpending(address(account), sessionKeySigner, target, 0.1 ether, "");
    }

    function test_validateAndRecordSpending_notYetValid() public {
        // Create session key that starts in the future
        ISessionKeyModule.SessionKeyParams memory params = ISessionKeyModule.SessionKeyParams({
            signer: sessionKeySigner,
            validAfter: uint48(block.timestamp + 1 hours),
            validUntil: uint48(block.timestamp + 1 days),
            spendingLimit: 1 ether,
            whitelist: new address[](0),
            selectors: new bytes4[](0)
        });

        vm.prank(address(account));
        sessionKeyModule.createSessionKey(params);

        address target = makeAddr("recipient");

        vm.prank(address(account));
        vm.expectRevert(ISessionKeyModule.SessionKeyNotYetValid.selector);
        sessionKeyModule.validateAndRecordSpending(address(account), sessionKeySigner, target, 0.1 ether, "");
    }

    /*//////////////////////////////////////////////////////////////
                       GETTER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_getActiveSessionKeys() public {
        // Create two session keys
        _createDefaultSessionKey();

        ISessionKeyModule.SessionKeyParams memory params2 = ISessionKeyModule.SessionKeyParams({
            signer: sessionKey2,
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            spendingLimit: 2 ether,
            whitelist: new address[](0),
            selectors: new bytes4[](0)
        });

        vm.prank(address(account));
        sessionKeyModule.createSessionKey(params2);

        address[] memory activeKeys = sessionKeyModule.getActiveSessionKeys(address(account));
        assertEq(activeKeys.length, 2, "Should have 2 active keys");

        // Revoke one
        vm.prank(address(account));
        sessionKeyModule.revokeSessionKey(sessionKeySigner);

        activeKeys = sessionKeyModule.getActiveSessionKeys(address(account));
        assertEq(activeKeys.length, 1, "Should have 1 active key after revocation");
        assertEq(activeKeys[0], sessionKey2, "Remaining key should be sessionKey2");
    }

    function test_getRemainingSpending_noLimit() public {
        // Create session key with no spending limit
        ISessionKeyModule.SessionKeyParams memory params = ISessionKeyModule.SessionKeyParams({
            signer: sessionKeySigner,
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            spendingLimit: 0, // No limit
            whitelist: new address[](0),
            selectors: new bytes4[](0)
        });

        vm.prank(address(account));
        sessionKeyModule.createSessionKey(params);

        uint256 remaining = sessionKeyModule.getRemainingSpending(address(account), sessionKeySigner);
        assertEq(remaining, type(uint256).max, "Should return max for no limit");
    }

    /*//////////////////////////////////////////////////////////////
                    INTEGRATION WITH SMART ACCOUNT
    //////////////////////////////////////////////////////////////*/

    function test_integration_executeWithSessionKey() public {
        _createDefaultSessionKey();

        address recipient = makeAddr("recipient");
        uint256 amount = 0.5 ether;

        // Create user op with session key signature
        bytes memory callData = encodeExecute(recipient, amount, "");
        IEntryPoint.PackedUserOperation memory userOp = createUserOp(address(account), 0, callData);

        // Sign with session key
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        userOp.signature = signWithSessionKey(userOpHash, sessionKeySigner, sessionKeySignerKey);

        // Execute
        IEntryPoint.PackedUserOperation[] memory ops = new IEntryPoint.PackedUserOperation[](1);
        ops[0] = userOp;

        entryPoint.handleOps(ops, payable(beneficiary));

        // Verify recipient received funds
        assertEq(recipient.balance, amount, "Recipient should receive ETH");

        // Verify spending was recorded
        ISessionKeyModule.SessionKey memory sk = sessionKeyModule.getSessionKey(address(account), sessionKeySigner);
        assertEq(sk.spent, amount, "Spending should be recorded");
    }

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _createDefaultSessionKey() internal {
        ISessionKeyModule.SessionKeyParams memory params = ISessionKeyModule.SessionKeyParams({
            signer: sessionKeySigner,
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            spendingLimit: 1 ether,
            whitelist: new address[](0),
            selectors: new bytes4[](0)
        });

        vm.prank(address(account));
        sessionKeyModule.createSessionKey(params);
    }
}
