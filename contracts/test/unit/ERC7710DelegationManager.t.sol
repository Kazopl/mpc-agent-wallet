// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Test, console2 } from "forge-std/Test.sol";
import { ERC7710DelegationManager } from "../../src/ERC7710DelegationManager.sol";
import { IERC7710 } from "../../src/interfaces/IERC7710.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title Mock Smart Account for ERC-7710 Tests
 * @notice A simplified smart account that validates signatures via ECDSA
 */
contract MockSmartAccount {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    address public owner;
    ERC7710DelegationManager public delegationManager;

    // EIP-1271 magic values
    bytes4 internal constant EIP1271_SUCCESS = 0x1626ba7e;
    bytes4 internal constant EIP1271_FAILED = 0xffffffff;

    constructor(address _owner) {
        owner = _owner;
    }

    function setDelegationManager(address _delegationManager) external {
        delegationManager = ERC7710DelegationManager(_delegationManager);
    }

    /**
     * @notice EIP-1271 signature validation
     * @dev Validates that the signature was created by the owner
     */
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        // Recover signer from signature (signature is already over the EIP-712 digest)
        address recovered = hash.recover(signature);

        if (recovered == owner) {
            return EIP1271_SUCCESS;
        }

        return EIP1271_FAILED;
    }

    /**
     * @notice Execute a call from the delegation manager
     */
    function executeFromDelegation(
        address target,
        uint256 value,
        bytes calldata data
    ) external returns (bytes memory) {
        require(msg.sender == address(delegationManager), "Only delegation manager");

        (bool success, bytes memory returnData) = target.call{ value: value }(data);
        require(success, "Execution failed");

        return returnData;
    }

    receive() external payable {}
}

/**
 * @title ERC7710DelegationManager Tests
 * @notice Unit tests for ERC-7710 delegation manager (ERC-7715 on-chain component)
 */
contract ERC7710DelegationManagerTest is Test {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    ERC7710DelegationManager public delegationManager;
    MockSmartAccount public account;

    // Account owner - signs permission contexts
    address public accountOwner;
    uint256 public accountOwnerKey;

    // Authorized signer (AI agent) - can redeem delegations
    address public authorizedSigner;
    uint256 public authorizedSignerKey;

    // Test permission data
    bytes32 public testPermissionId;

    // Events
    event DelegationRegistered(
        bytes32 indexed permissionId,
        address indexed account,
        address indexed signer,
        uint48 expiry
    );
    event DelegationRevoked(bytes32 indexed permissionId, address indexed account);
    event DelegationRedeemed(
        bytes32 indexed permissionId,
        address indexed account,
        address indexed signer,
        uint256 actionCount
    );

    function setUp() public {
        // Create account owner (who signs permission contexts)
        (accountOwner, accountOwnerKey) = makeAddrAndKey("accountOwner");

        // Create authorized signer (AI agent who redeems delegations)
        (authorizedSigner, authorizedSignerKey) = makeAddrAndKey("authorizedSigner");

        // Deploy delegation manager (no session key module for these tests)
        delegationManager = new ERC7710DelegationManager(address(0));

        // Deploy mock smart account owned by accountOwner
        account = new MockSmartAccount(accountOwner);
        account.setDelegationManager(address(delegationManager));

        // Fund account
        vm.deal(address(account), 100 ether);

        // Generate test permission ID
        testPermissionId = keccak256(abi.encodePacked("test-permission", block.timestamp));
    }

    /*//////////////////////////////////////////////////////////////
                      DELEGATION REGISTRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_registerDelegation_success() public {
        bytes memory permissionContext = _createPermissionContext(
            testPermissionId,
            authorizedSigner,
            address(account),
            block.chainid,
            uint48(block.timestamp + 1 days),
            1 ether,
            new address[](0),
            new bytes4[](0)
        );

        vm.prank(address(account));
        vm.expectEmit(true, true, true, true);
        emit DelegationRegistered(
            testPermissionId,
            address(account),
            authorizedSigner,
            uint48(block.timestamp + 1 days)
        );
        delegationManager.registerDelegation(permissionContext);

        // Verify delegation is registered
        assertTrue(
            delegationManager.isDelegationValid(testPermissionId, address(account)),
            "Delegation should be valid"
        );
    }

    function test_registerDelegation_revertsNonAccount() public {
        bytes memory permissionContext = _createPermissionContext(
            testPermissionId,
            authorizedSigner,
            address(account),
            block.chainid,
            uint48(block.timestamp + 1 days),
            1 ether,
            new address[](0),
            new bytes4[](0)
        );

        // Try to register from attacker address
        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        vm.expectRevert(IERC7710.AccountMismatch.selector);
        delegationManager.registerDelegation(permissionContext);
    }

    function test_registerDelegation_revertsWrongChain() public {
        bytes memory permissionContext = _createPermissionContext(
            testPermissionId,
            authorizedSigner,
            address(account),
            999, // Wrong chain ID
            uint48(block.timestamp + 1 days),
            1 ether,
            new address[](0),
            new bytes4[](0)
        );

        vm.prank(address(account));
        vm.expectRevert(IERC7710.ChainMismatch.selector);
        delegationManager.registerDelegation(permissionContext);
    }

    function test_registerDelegation_revertsAlreadyRegistered() public {
        bytes memory permissionContext = _createPermissionContext(
            testPermissionId,
            authorizedSigner,
            address(account),
            block.chainid,
            uint48(block.timestamp + 1 days),
            1 ether,
            new address[](0),
            new bytes4[](0)
        );

        // Register first time
        vm.prank(address(account));
        delegationManager.registerDelegation(permissionContext);

        // Try to register again
        vm.prank(address(account));
        vm.expectRevert(IERC7710.PermissionAlreadyRegistered.selector);
        delegationManager.registerDelegation(permissionContext);
    }

    /*//////////////////////////////////////////////////////////////
                       DELEGATION REVOCATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_revokeDelegation_byAccount() public {
        _registerTestDelegation();

        vm.prank(address(account));
        vm.expectEmit(true, true, false, false);
        emit DelegationRevoked(testPermissionId, address(account));
        delegationManager.revokeDelegation(testPermissionId);

        assertFalse(
            delegationManager.isDelegationValid(testPermissionId, address(account)),
            "Delegation should not be valid after revocation"
        );
    }

    function test_revokeDelegation_revertsNonExistent() public {
        vm.prank(address(account));
        vm.expectRevert(IERC7710.InvalidPermissionContext.selector);
        delegationManager.revokeDelegation(testPermissionId);
    }

    /*//////////////////////////////////////////////////////////////
                       DELEGATION REDEMPTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_redeemDelegation_simpleTransfer() public {
        _registerTestDelegation();

        address recipient = makeAddr("recipient");
        uint256 transferAmount = 0.5 ether;

        IERC7710.Action[] memory actions = new IERC7710.Action[](1);
        actions[0] = IERC7710.Action({
            to: recipient,
            value: transferAmount,
            data: ""
        });

        bytes memory permissionContext = _createPermissionContext(
            testPermissionId,
            authorizedSigner,
            address(account),
            block.chainid,
            uint48(block.timestamp + 1 days),
            1 ether,
            new address[](0),
            new bytes4[](0)
        );

        uint256 recipientBalanceBefore = recipient.balance;

        vm.prank(authorizedSigner);
        delegationManager.redeemDelegation(permissionContext, actions);

        assertEq(
            recipient.balance,
            recipientBalanceBefore + transferAmount,
            "Recipient should receive transfer"
        );
    }

    function test_redeemDelegation_revertsWrongSigner() public {
        _registerTestDelegation();

        IERC7710.Action[] memory actions = new IERC7710.Action[](1);
        actions[0] = IERC7710.Action({
            to: makeAddr("recipient"),
            value: 0.1 ether,
            data: ""
        });

        bytes memory permissionContext = _createPermissionContext(
            testPermissionId,
            authorizedSigner,
            address(account),
            block.chainid,
            uint48(block.timestamp + 1 days),
            1 ether,
            new address[](0),
            new bytes4[](0)
        );

        address attacker = makeAddr("attacker");
        vm.prank(attacker); // Wrong signer
        vm.expectRevert(IERC7710.InvalidSigner.selector);
        delegationManager.redeemDelegation(permissionContext, actions);
    }

    function test_redeemDelegation_revertsExpired() public {
        bytes memory permissionContext = _createPermissionContext(
            testPermissionId,
            authorizedSigner,
            address(account),
            block.chainid,
            uint48(block.timestamp + 1 hours),
            1 ether,
            new address[](0),
            new bytes4[](0)
        );

        vm.prank(address(account));
        delegationManager.registerDelegation(permissionContext);

        // Fast forward past expiry
        vm.warp(block.timestamp + 2 hours);

        IERC7710.Action[] memory actions = new IERC7710.Action[](1);
        actions[0] = IERC7710.Action({
            to: makeAddr("recipient"),
            value: 0.1 ether,
            data: ""
        });

        vm.prank(authorizedSigner);
        vm.expectRevert(IERC7710.PermissionExpired.selector);
        delegationManager.redeemDelegation(permissionContext, actions);
    }

    function test_redeemDelegation_revertsRevoked() public {
        _registerTestDelegation();

        // Revoke delegation
        vm.prank(address(account));
        delegationManager.revokeDelegation(testPermissionId);

        bytes memory permissionContext = _createPermissionContext(
            testPermissionId,
            authorizedSigner,
            address(account),
            block.chainid,
            uint48(block.timestamp + 1 days),
            1 ether,
            new address[](0),
            new bytes4[](0)
        );

        IERC7710.Action[] memory actions = new IERC7710.Action[](1);
        actions[0] = IERC7710.Action({
            to: makeAddr("recipient"),
            value: 0.1 ether,
            data: ""
        });

        vm.prank(authorizedSigner);
        vm.expectRevert(IERC7710.PermissionRevoked.selector);
        delegationManager.redeemDelegation(permissionContext, actions);
    }

    function test_redeemDelegation_revertsSpendingLimitExceeded() public {
        _registerTestDelegation(); // 1 ETH limit

        IERC7710.Action[] memory actions = new IERC7710.Action[](1);
        actions[0] = IERC7710.Action({
            to: makeAddr("recipient"),
            value: 1.5 ether, // Exceeds 1 ETH limit
            data: ""
        });

        bytes memory permissionContext = _createPermissionContext(
            testPermissionId,
            authorizedSigner,
            address(account),
            block.chainid,
            uint48(block.timestamp + 1 days),
            1 ether,
            new address[](0),
            new bytes4[](0)
        );

        vm.prank(authorizedSigner);
        vm.expectRevert(
            abi.encodeWithSelector(IERC7710.SpendingLimitExceeded.selector, 1.5 ether, 1 ether)
        );
        delegationManager.redeemDelegation(permissionContext, actions);
    }

    function test_redeemDelegation_tracksSpending() public {
        _registerTestDelegation(); // 1 ETH limit

        bytes memory permissionContext = _createPermissionContext(
            testPermissionId,
            authorizedSigner,
            address(account),
            block.chainid,
            uint48(block.timestamp + 1 days),
            1 ether,
            new address[](0),
            new bytes4[](0)
        );

        // First redemption: 0.4 ETH
        IERC7710.Action[] memory actions1 = new IERC7710.Action[](1);
        actions1[0] = IERC7710.Action({
            to: makeAddr("recipient"),
            value: 0.4 ether,
            data: ""
        });

        vm.prank(authorizedSigner);
        delegationManager.redeemDelegation(permissionContext, actions1);

        // Second redemption: 0.4 ETH (total 0.8 ETH)
        vm.prank(authorizedSigner);
        delegationManager.redeemDelegation(permissionContext, actions1);

        // Check remaining allowance
        uint256 remaining = delegationManager.getRemainingAllowance(testPermissionId, address(account));
        assertEq(remaining, 0.2 ether, "Should have 0.2 ETH remaining");

        // Third redemption should fail: 0.4 ETH would exceed limit
        vm.prank(authorizedSigner);
        vm.expectRevert(
            abi.encodeWithSelector(IERC7710.SpendingLimitExceeded.selector, 0.4 ether, 0.2 ether)
        );
        delegationManager.redeemDelegation(permissionContext, actions1);
    }

    function test_redeemDelegation_revertsTargetNotWhitelisted() public {
        address[] memory whitelist = new address[](1);
        whitelist[0] = makeAddr("allowed");

        bytes memory permissionContext = _createPermissionContext(
            testPermissionId,
            authorizedSigner,
            address(account),
            block.chainid,
            uint48(block.timestamp + 1 days),
            1 ether,
            whitelist,
            new bytes4[](0)
        );

        vm.prank(address(account));
        delegationManager.registerDelegation(permissionContext);

        address notWhitelisted = makeAddr("notWhitelisted");

        IERC7710.Action[] memory actions = new IERC7710.Action[](1);
        actions[0] = IERC7710.Action({
            to: notWhitelisted,
            value: 0.1 ether,
            data: ""
        });

        vm.prank(authorizedSigner);
        vm.expectRevert(abi.encodeWithSelector(IERC7710.TargetNotAllowed.selector, notWhitelisted));
        delegationManager.redeemDelegation(permissionContext, actions);
    }

    function test_redeemDelegation_withWhitelist() public {
        address allowed = makeAddr("allowed");
        address[] memory whitelist = new address[](1);
        whitelist[0] = allowed;

        bytes memory permissionContext = _createPermissionContext(
            testPermissionId,
            authorizedSigner,
            address(account),
            block.chainid,
            uint48(block.timestamp + 1 days),
            1 ether,
            whitelist,
            new bytes4[](0)
        );

        vm.prank(address(account));
        delegationManager.registerDelegation(permissionContext);

        IERC7710.Action[] memory actions = new IERC7710.Action[](1);
        actions[0] = IERC7710.Action({
            to: allowed,
            value: 0.1 ether,
            data: ""
        });

        uint256 balanceBefore = allowed.balance;

        vm.prank(authorizedSigner);
        delegationManager.redeemDelegation(permissionContext, actions);

        assertEq(allowed.balance, balanceBefore + 0.1 ether, "Whitelisted address should receive");
    }

    function test_redeemDelegation_revertsSelectorNotAllowed() public {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(keccak256("transfer(address,uint256)"));

        bytes memory permissionContext = _createPermissionContext(
            testPermissionId,
            authorizedSigner,
            address(account),
            block.chainid,
            uint48(block.timestamp + 1 days),
            1 ether,
            new address[](0),
            selectors
        );

        vm.prank(address(account));
        delegationManager.registerDelegation(permissionContext);

        bytes4 notAllowedSelector = bytes4(keccak256("approve(address,uint256)"));

        IERC7710.Action[] memory actions = new IERC7710.Action[](1);
        actions[0] = IERC7710.Action({
            to: makeAddr("target"),
            value: 0,
            data: abi.encodeWithSelector(notAllowedSelector, address(this), 100)
        });

        vm.prank(authorizedSigner);
        vm.expectRevert(abi.encodeWithSelector(IERC7710.SelectorNotAllowed.selector, notAllowedSelector));
        delegationManager.redeemDelegation(permissionContext, actions);
    }

    function test_redeemDelegation_multipleActions() public {
        _registerTestDelegation(); // 1 ETH limit

        address recipient1 = makeAddr("recipient1");
        address recipient2 = makeAddr("recipient2");

        IERC7710.Action[] memory actions = new IERC7710.Action[](2);
        actions[0] = IERC7710.Action({
            to: recipient1,
            value: 0.3 ether,
            data: ""
        });
        actions[1] = IERC7710.Action({
            to: recipient2,
            value: 0.4 ether,
            data: ""
        });

        bytes memory permissionContext = _createPermissionContext(
            testPermissionId,
            authorizedSigner,
            address(account),
            block.chainid,
            uint48(block.timestamp + 1 days),
            1 ether,
            new address[](0),
            new bytes4[](0)
        );

        uint256 balance1Before = recipient1.balance;
        uint256 balance2Before = recipient2.balance;

        vm.prank(authorizedSigner);
        delegationManager.redeemDelegation(permissionContext, actions);

        assertEq(recipient1.balance, balance1Before + 0.3 ether);
        assertEq(recipient2.balance, balance2Before + 0.4 ether);

        // Total spending should be 0.7 ETH
        uint256 remaining = delegationManager.getRemainingAllowance(testPermissionId, address(account));
        assertEq(remaining, 0.3 ether);
    }

    /*//////////////////////////////////////////////////////////////
                           GETTER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_isDelegationValid() public {
        assertFalse(
            delegationManager.isDelegationValid(testPermissionId, address(account)),
            "Should not be valid before registration"
        );

        _registerTestDelegation();

        assertTrue(
            delegationManager.isDelegationValid(testPermissionId, address(account)),
            "Should be valid after registration"
        );

        // Revoke
        vm.prank(address(account));
        delegationManager.revokeDelegation(testPermissionId);

        assertFalse(
            delegationManager.isDelegationValid(testPermissionId, address(account)),
            "Should not be valid after revocation"
        );
    }

    function test_isDelegationValid_expired() public {
        bytes memory permissionContext = _createPermissionContext(
            testPermissionId,
            authorizedSigner,
            address(account),
            block.chainid,
            uint48(block.timestamp + 1 hours),
            1 ether,
            new address[](0),
            new bytes4[](0)
        );

        vm.prank(address(account));
        delegationManager.registerDelegation(permissionContext);

        assertTrue(
            delegationManager.isDelegationValid(testPermissionId, address(account)),
            "Should be valid initially"
        );

        // Fast forward past expiry
        vm.warp(block.timestamp + 2 hours);

        assertFalse(
            delegationManager.isDelegationValid(testPermissionId, address(account)),
            "Should not be valid after expiry"
        );
    }

    function test_getRemainingAllowance() public {
        _registerTestDelegation(); // 1 ETH limit

        uint256 remaining = delegationManager.getRemainingAllowance(testPermissionId, address(account));
        assertEq(remaining, 1 ether, "Should have full allowance initially");
    }

    function test_getRemainingAllowance_revoked() public {
        _registerTestDelegation();

        vm.prank(address(account));
        delegationManager.revokeDelegation(testPermissionId);

        uint256 remaining = delegationManager.getRemainingAllowance(testPermissionId, address(account));
        assertEq(remaining, 0, "Should return 0 for revoked delegation");
    }

    function test_getRemainingAllowance_noLimit() public {
        bytes memory permissionContext = _createPermissionContext(
            testPermissionId,
            authorizedSigner,
            address(account),
            block.chainid,
            uint48(block.timestamp + 1 days),
            0, // No spending limit
            new address[](0),
            new bytes4[](0)
        );

        vm.prank(address(account));
        delegationManager.registerDelegation(permissionContext);

        uint256 remaining = delegationManager.getRemainingAllowance(testPermissionId, address(account));
        assertEq(remaining, type(uint256).max, "Should return max for unlimited");
    }

    function test_getDelegationInfo() public {
        _registerTestDelegation();

        (
            address signer,
            uint48 expiry,
            uint256 spent,
            bool revoked
        ) = delegationManager.getDelegationInfo(testPermissionId, address(account));

        assertEq(signer, authorizedSigner, "Signer should match");
        assertEq(expiry, uint48(block.timestamp + 1 days), "Expiry should match");
        assertEq(spent, 0, "Spent should be 0 initially");
        assertFalse(revoked, "Should not be revoked");
    }

    function test_domainSeparator() public view {
        bytes32 separator = delegationManager.domainSeparator();
        assertTrue(separator != bytes32(0), "Domain separator should not be zero");
    }

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _registerTestDelegation() internal {
        bytes memory permissionContext = _createPermissionContext(
            testPermissionId,
            authorizedSigner,
            address(account),
            block.chainid,
            uint48(block.timestamp + 1 days),
            1 ether,
            new address[](0),
            new bytes4[](0)
        );

        vm.prank(address(account));
        delegationManager.registerDelegation(permissionContext);
    }

    function _createPermissionContext(
        bytes32 permissionId,
        address signer,
        address accountAddr,
        uint256 chainId,
        uint48 expiry,
        uint256 nativeAllowance,
        address[] memory whitelist,
        bytes4[] memory selectors
    ) internal view returns (bytes memory) {
        // Create signature signed by account owner
        bytes memory signature = _signPermission(
            permissionId,
            signer,
            accountAddr,
            chainId,
            expiry,
            nativeAllowance,
            whitelist,
            selectors
        );

        return abi.encode(
            permissionId,
            signer,
            accountAddr,
            chainId,
            expiry,
            nativeAllowance,
            whitelist,
            selectors,
            signature
        );
    }

    function _signPermission(
        bytes32 permissionId,
        address signer,
        address accountAddr,
        uint256 chainId,
        uint48 expiry,
        uint256 nativeAllowance,
        address[] memory whitelist,
        bytes4[] memory selectors
    ) internal view returns (bytes memory) {
        bytes32 whitelistHash = keccak256(abi.encodePacked(whitelist));
        bytes32 selectorsHash = keccak256(abi.encodePacked(selectors));

        bytes32 structHash = keccak256(
            abi.encode(
                delegationManager.PERMISSION_TYPEHASH(),
                permissionId,
                signer,
                accountAddr,
                chainId,
                expiry,
                nativeAllowance,
                whitelistHash,
                selectorsHash
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", delegationManager.domainSeparator(), structHash)
        );

        // Sign with account owner's key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(accountOwnerKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
