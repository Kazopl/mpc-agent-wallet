// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BaseTest } from "../Base.t.sol";
import { MpcSmartAccount } from "../../src/MpcSmartAccount.sol";
import { MpcAgentIdentityModule, IMpcAgentIdentityModule } from "../../src/modules/MpcAgentIdentityModule.sol";
import { IERC7579Module } from "../../src/interfaces/IERC7579Module.sol";
import { IIdentityRegistry, IReputationRegistry, IValidationRegistry } from "../../src/interfaces/IERC8004.sol";

/**
 * @title Mock Identity Registry
 * @notice Simplified Identity Registry for testing
 */
contract MockIdentityRegistry is IIdentityRegistry {
    uint256 private _nextAgentId = 1;
    mapping(uint256 => string) private _agentURIs;
    mapping(uint256 => address) private _agentWallets;
    mapping(uint256 => address) private _agentOwners;
    mapping(uint256 => mapping(string => bytes)) private _metadata;

    function register(
        string calldata uri
    ) external returns (uint256 agentId) {
        agentId = _nextAgentId++;
        _agentURIs[agentId] = uri;
        _agentOwners[agentId] = msg.sender;
        emit AgentRegistered(agentId, msg.sender, uri);
    }

    function setAgentURI(uint256 agentId, string calldata newURI) external {
        string memory oldURI = _agentURIs[agentId];
        _agentURIs[agentId] = newURI;
        emit AgentURIUpdated(agentId, oldURI, newURI);
    }

    function setAgentWallet(uint256 agentId, address wallet, uint256, bytes calldata) external {
        _agentWallets[agentId] = wallet;
        emit AgentWalletSet(agentId, wallet);
    }

    function getAgentWallet(
        uint256 agentId
    ) external view returns (address) {
        return _agentWallets[agentId];
    }

    function getMetadata(uint256 agentId, string calldata key) external view returns (bytes memory) {
        return _metadata[agentId][key];
    }

    function setMetadata(uint256 agentId, string calldata key, bytes calldata value) external {
        _metadata[agentId][key] = value;
        emit AgentMetadataSet(agentId, key, value);
    }

    function agentURI(
        uint256 agentId
    ) external view returns (string memory) {
        return _agentURIs[agentId];
    }

    function ownerOf(
        uint256 agentId
    ) external view returns (address) {
        return _agentOwners[agentId];
    }
}

/**
 * @title Mock Reputation Registry
 * @notice Simplified Reputation Registry for testing
 */
contract MockReputationRegistry is IReputationRegistry {
    mapping(uint256 => FeedbackData[]) private _feedbacks;

    function giveFeedback(
        uint256 agentId,
        int128 value,
        uint8 decimals,
        string calldata tag1,
        string calldata tag2,
        bytes32 proofOfPayment
    ) external returns (uint64 feedbackIndex) {
        feedbackIndex = uint64(_feedbacks[agentId].length);
        _feedbacks[agentId].push(
            FeedbackData({
                reviewer: msg.sender,
                value: value,
                decimals: decimals,
                tag1: tag1,
                tag2: tag2,
                proofOfPayment: proofOfPayment,
                timestamp: uint64(block.timestamp),
                revoked: false
            })
        );
        emit FeedbackGiven(agentId, msg.sender, value, decimals, tag1, tag2, feedbackIndex);
    }

    function revokeFeedback(uint256 agentId, uint64 feedbackIndex) external {
        if (feedbackIndex >= _feedbacks[agentId].length) {
            revert FeedbackNotFound(agentId, feedbackIndex);
        }
        if (_feedbacks[agentId][feedbackIndex].revoked) {
            revert FeedbackAlreadyRevoked(agentId, feedbackIndex);
        }
        _feedbacks[agentId][feedbackIndex].revoked = true;
        emit FeedbackRevoked(agentId, msg.sender, feedbackIndex);
    }

    function getSummary(uint256 agentId, address[] calldata, string calldata, string calldata)
        external
        view
        returns (ReputationSummary memory summary)
    {
        FeedbackData[] storage feedbacks = _feedbacks[agentId];
        int128 aggregate;
        uint64 count;
        for (uint256 i = 0; i < feedbacks.length; i++) {
            if (!feedbacks[i].revoked) {
                aggregate += feedbacks[i].value;
                count++;
            }
        }
        return ReputationSummary({ feedbackCount: count, aggregateValue: aggregate, decimals: 18 });
    }

    function getFeedback(uint256 agentId, uint64 feedbackIndex) external view returns (FeedbackData memory) {
        return _feedbacks[agentId][feedbackIndex];
    }

    function getFeedbackCount(
        uint256 agentId
    ) external view returns (uint64) {
        return uint64(_feedbacks[agentId].length);
    }
}

/**
 * @title Mock Validation Registry
 * @notice Simplified Validation Registry for testing
 */
contract MockValidationRegistry is IValidationRegistry {
    mapping(bytes32 => ValidationRequest) private _requests;
    mapping(uint256 => bytes32[]) private _agentValidations;
    mapping(address => bytes32[]) private _validatorRequests;
    uint256 private _nonce;

    function validationRequest(address validator, uint256 agentId, string calldata requestURI, bytes32 contentHash)
        external
        returns (bytes32 requestHash)
    {
        requestHash = keccak256(abi.encodePacked(msg.sender, validator, agentId, _nonce++));
        _requests[requestHash] = ValidationRequest({
            requester: msg.sender,
            validator: validator,
            agentId: agentId,
            requestURI: requestURI,
            contentHash: contentHash,
            timestamp: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + 7 days),
            response: ValidationResponse.Pending,
            responseData: "",
            trustModel: TrustModel.Reputation
        });
        _agentValidations[agentId].push(requestHash);
        _validatorRequests[validator].push(requestHash);
        emit ValidationRequested(requestHash, agentId, validator, requestURI, contentHash);
    }

    function validationResponse(bytes32 requestHash, ValidationResponse response, bytes calldata responseData)
        external
    {
        ValidationRequest storage request = _requests[requestHash];
        if (request.requester == address(0)) {
            revert RequestNotFound(requestHash);
        }
        if (msg.sender != request.validator) {
            revert NotDesignatedValidator(requestHash, msg.sender);
        }
        request.response = response;
        request.responseData = responseData;
        emit ValidationResponded(requestHash, response, responseData);
    }

    function getValidationStatus(
        bytes32 requestHash
    ) external view returns (ValidationRequest memory) {
        return _requests[requestHash];
    }

    function getAgentValidations(
        uint256 agentId
    ) external view returns (bytes32[] memory) {
        return _agentValidations[agentId];
    }

    function getValidatorRequests(
        address validator
    ) external view returns (bytes32[] memory) {
        return _validatorRequests[validator];
    }

    function isExpired(
        bytes32 requestHash
    ) external view returns (bool) {
        return block.timestamp > _requests[requestHash].expiresAt;
    }
}

/**
 * @title MpcAgentIdentityModule Tests
 * @notice Unit tests for ERC-8004 agent identity integration
 */
contract MpcAgentIdentityModuleTest is BaseTest {
    MpcSmartAccount public account;
    MpcAgentIdentityModule public agentIdentityModule;
    MockIdentityRegistry public mockIdentityRegistry;
    MockReputationRegistry public mockReputationRegistry;
    MockValidationRegistry public mockValidationRegistry;

    address public validator;
    string constant AGENT_URI = "ipfs://QmTestAgentRegistrationFile";
    string constant UPDATED_URI = "ipfs://QmUpdatedAgentRegistrationFile";

    function setUp() public override {
        super.setUp();

        // Create mock registries
        mockIdentityRegistry = new MockIdentityRegistry();
        mockReputationRegistry = new MockReputationRegistry();
        mockValidationRegistry = new MockValidationRegistry();

        // Deploy agent identity module with mock registries
        agentIdentityModule = new MpcAgentIdentityModule(
            address(mockIdentityRegistry), address(mockReputationRegistry), address(mockValidationRegistry)
        );

        // Create account
        account = createDefaultAccount(0);
        vm.deal(address(account), 100 ether);

        // Setup validator
        (validator,) = makeAddrAndKey("validator");
    }

    /*//////////////////////////////////////////////////////////////
                       INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_onInstall_withoutAutoRegistration() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall("");

        assertTrue(agentIdentityModule.isInitialized(address(account)), "Module should be initialized");
        assertFalse(agentIdentityModule.isRegisteredAgent(address(account)), "Should not be registered");
    }

    function test_onInstall_withAutoRegistration() public {
        bytes memory initData = abi.encode(AGENT_URI);

        vm.prank(address(account));
        agentIdentityModule.onInstall(initData);

        assertTrue(agentIdentityModule.isInitialized(address(account)), "Module should be initialized");
        assertTrue(agentIdentityModule.isRegisteredAgent(address(account)), "Should be registered");

        IMpcAgentIdentityModule.AgentConfig memory config = agentIdentityModule.getAgentConfig(address(account));
        assertEq(config.agentId, 1, "Agent ID should be 1");
        assertEq(config.agentURI, AGENT_URI, "Agent URI should match");
    }

    function test_onInstall_revertsIfAlreadyInitialized() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall("");

        vm.prank(address(account));
        vm.expectRevert(abi.encodeWithSelector(IERC7579Module.AlreadyInitialized.selector, address(account)));
        agentIdentityModule.onInstall("");
    }

    function test_onUninstall() public {
        bytes memory initData = abi.encode(AGENT_URI);

        vm.prank(address(account));
        agentIdentityModule.onInstall(initData);

        vm.prank(address(account));
        agentIdentityModule.onUninstall("");

        assertFalse(agentIdentityModule.isInitialized(address(account)), "Module should not be initialized");
        assertFalse(agentIdentityModule.isRegisteredAgent(address(account)), "Should not be registered");
    }

    function test_onUninstall_revertsIfNotInitialized() public {
        vm.prank(address(account));
        vm.expectRevert(abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(account)));
        agentIdentityModule.onUninstall("");
    }

    function test_isModuleType() public view {
        assertTrue(agentIdentityModule.isModuleType(2), "Should be Type 2 Executor");
        assertFalse(agentIdentityModule.isModuleType(1), "Should not be Type 1 Validator");
        assertFalse(agentIdentityModule.isModuleType(3), "Should not be Type 3 Fallback");
        assertFalse(agentIdentityModule.isModuleType(4), "Should not be Type 4 Hook");
    }

    /*//////////////////////////////////////////////////////////////
                     AGENT REGISTRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_registerAgent() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall("");

        vm.prank(address(account));
        uint256 agentId = agentIdentityModule.registerAgent(AGENT_URI);

        assertEq(agentId, 1, "Agent ID should be 1");
        assertTrue(agentIdentityModule.isRegisteredAgent(address(account)), "Should be registered");

        IMpcAgentIdentityModule.AgentConfig memory config = agentIdentityModule.getAgentConfig(address(account));
        assertEq(config.agentId, 1, "Config agent ID should match");
        assertEq(config.agentURI, AGENT_URI, "Config URI should match");
    }

    function test_registerAgent_revertsIfNotInstalled() public {
        vm.prank(address(account));
        vm.expectRevert(abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(account)));
        agentIdentityModule.registerAgent(AGENT_URI);
    }

    function test_registerAgent_revertsIfAlreadyRegistered() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall(abi.encode(AGENT_URI));

        vm.prank(address(account));
        vm.expectRevert(IMpcAgentIdentityModule.AgentAlreadyRegistered.selector);
        agentIdentityModule.registerAgent(AGENT_URI);
    }

    function test_registerAgent_revertsIfEmptyURI() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall("");

        vm.prank(address(account));
        vm.expectRevert(IMpcAgentIdentityModule.InvalidAgentURI.selector);
        agentIdentityModule.registerAgent("");
    }

    function test_updateAgentURI() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall(abi.encode(AGENT_URI));

        vm.prank(address(account));
        agentIdentityModule.updateAgentURI(UPDATED_URI);

        IMpcAgentIdentityModule.AgentConfig memory config = agentIdentityModule.getAgentConfig(address(account));
        assertEq(config.agentURI, UPDATED_URI, "URI should be updated");
    }

    function test_updateAgentURI_revertsIfNotRegistered() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall("");

        vm.prank(address(account));
        vm.expectRevert(IMpcAgentIdentityModule.AgentNotRegistered.selector);
        agentIdentityModule.updateAgentURI(UPDATED_URI);
    }

    function test_updateAgentURI_revertsIfEmptyURI() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall(abi.encode(AGENT_URI));

        vm.prank(address(account));
        vm.expectRevert(IMpcAgentIdentityModule.InvalidAgentURI.selector);
        agentIdentityModule.updateAgentURI("");
    }

    function test_setAgentWallet() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall(abi.encode(AGENT_URI));

        address walletToLink = makeAddr("linkedWallet");
        bytes memory signature = hex"1234";

        vm.prank(address(account));
        agentIdentityModule.setAgentWallet(walletToLink, block.timestamp + 1 days, signature);

        uint256 agentId = agentIdentityModule.getAgentId(address(account));
        address linkedWallet = agentIdentityModule.getAgentWallet(agentId);
        assertEq(linkedWallet, walletToLink, "Wallet should be linked");
    }

    function test_setAgentWallet_revertsIfNotRegistered() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall("");

        vm.prank(address(account));
        vm.expectRevert(IMpcAgentIdentityModule.AgentNotRegistered.selector);
        agentIdentityModule.setAgentWallet(makeAddr("wallet"), block.timestamp + 1 days, "");
    }

    /*//////////////////////////////////////////////////////////////
                       REPUTATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_giveFeedback() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall(abi.encode(AGENT_URI));

        MpcSmartAccount account2 = createDefaultAccount(1);
        vm.prank(address(account2));
        agentIdentityModule.onInstall(abi.encode("ipfs://QmOtherAgent"));

        uint256 targetAgentId = agentIdentityModule.getAgentId(address(account2));

        vm.prank(address(account));
        uint64 feedbackIndex =
            agentIdentityModule.giveFeedback(targetAgentId, 100, 18, "reliability", "trading", bytes32(0));

        assertEq(feedbackIndex, 0, "Feedback index should be 0");

        IReputationRegistry.FeedbackData memory feedback = mockReputationRegistry.getFeedback(targetAgentId, 0);
        assertEq(feedback.value, 100, "Feedback value should match");
        assertEq(feedback.tag1, "reliability", "Tag1 should match");
        assertEq(feedback.tag2, "trading", "Tag2 should match");
    }

    function test_giveFeedback_revertsIfNotInstalled() public {
        vm.prank(address(account));
        vm.expectRevert(abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(account)));
        agentIdentityModule.giveFeedback(1, 100, 18, "tag1", "tag2", bytes32(0));
    }

    function test_giveFeedback_revertsIfZeroValue() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall(abi.encode(AGENT_URI));

        vm.prank(address(account));
        vm.expectRevert(IMpcAgentIdentityModule.InvalidFeedbackValue.selector);
        agentIdentityModule.giveFeedback(1, 0, 18, "tag1", "tag2", bytes32(0));
    }

    function test_giveFeedback_negative() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall(abi.encode(AGENT_URI));

        MpcSmartAccount account2 = createDefaultAccount(1);
        vm.prank(address(account2));
        agentIdentityModule.onInstall(abi.encode("ipfs://QmOtherAgent"));

        uint256 targetAgentId = agentIdentityModule.getAgentId(address(account2));

        vm.prank(address(account));
        agentIdentityModule.giveFeedback(targetAgentId, -50, 18, "dishonesty", "scam", bytes32(0));

        IReputationRegistry.FeedbackData memory feedback = mockReputationRegistry.getFeedback(targetAgentId, 0);
        assertEq(feedback.value, -50, "Negative feedback value should match");
    }

    function test_revokeFeedback() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall(abi.encode(AGENT_URI));

        MpcSmartAccount account2 = createDefaultAccount(1);
        vm.prank(address(account2));
        agentIdentityModule.onInstall(abi.encode("ipfs://QmOtherAgent"));

        uint256 targetAgentId = agentIdentityModule.getAgentId(address(account2));

        vm.prank(address(account));
        uint64 feedbackIndex =
            agentIdentityModule.giveFeedback(targetAgentId, 100, 18, "reliability", "trading", bytes32(0));

        vm.prank(address(account));
        agentIdentityModule.revokeFeedback(targetAgentId, feedbackIndex);

        IReputationRegistry.FeedbackData memory feedback = mockReputationRegistry.getFeedback(targetAgentId, 0);
        assertTrue(feedback.revoked, "Feedback should be revoked");
    }

    function test_getReputationSummary() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall(abi.encode(AGENT_URI));

        MpcSmartAccount account2 = createDefaultAccount(1);
        vm.prank(address(account2));
        agentIdentityModule.onInstall(abi.encode("ipfs://QmOtherAgent"));

        uint256 targetAgentId = agentIdentityModule.getAgentId(address(account2));

        vm.prank(address(account));
        agentIdentityModule.giveFeedback(targetAgentId, 100, 18, "reliability", "", bytes32(0));

        vm.prank(address(account));
        agentIdentityModule.giveFeedback(targetAgentId, 50, 18, "quality", "", bytes32(0));

        address[] memory clients = new address[](0);
        IReputationRegistry.ReputationSummary memory summary =
            agentIdentityModule.getReputationSummary(targetAgentId, clients, "", "");

        assertEq(summary.feedbackCount, 2, "Should have 2 feedbacks");
        assertEq(summary.aggregateValue, 150, "Aggregate should be 150");
    }

    /*//////////////////////////////////////////////////////////////
                       VALIDATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_requestValidation() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall(abi.encode(AGENT_URI));

        string memory requestURI = "ipfs://QmValidationRequest";
        bytes32 contentHash = keccak256("test content");

        vm.prank(address(account));
        bytes32 requestHash = agentIdentityModule.requestValidation(validator, requestURI, contentHash);

        assertTrue(requestHash != bytes32(0), "Request hash should not be zero");

        IValidationRegistry.ValidationRequest memory request = agentIdentityModule.getValidationStatus(requestHash);
        assertEq(request.validator, validator, "Validator should match");
        assertEq(request.requestURI, requestURI, "Request URI should match");
        assertEq(request.contentHash, contentHash, "Content hash should match");
        assertEq(uint8(request.response), uint8(IValidationRegistry.ValidationResponse.Pending), "Should be pending");
    }

    function test_requestValidation_revertsIfNotRegistered() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall("");

        vm.prank(address(account));
        vm.expectRevert(IMpcAgentIdentityModule.AgentNotRegistered.selector);
        agentIdentityModule.requestValidation(validator, "ipfs://request", bytes32(0));
    }

    function test_requestValidation_revertsIfZeroValidator() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall(abi.encode(AGENT_URI));

        vm.prank(address(account));
        vm.expectRevert(IMpcAgentIdentityModule.InvalidValidator.selector);
        agentIdentityModule.requestValidation(address(0), "ipfs://request", bytes32(0));
    }

    function test_validationResponse() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall(abi.encode(AGENT_URI));

        string memory requestURI = "ipfs://QmValidationRequest";
        bytes32 contentHash = keccak256("test content");

        vm.prank(address(account));
        bytes32 requestHash = agentIdentityModule.requestValidation(validator, requestURI, contentHash);

        vm.prank(validator);
        mockValidationRegistry.validationResponse(
            requestHash, IValidationRegistry.ValidationResponse.Approved, abi.encode("TEE attestation data")
        );

        IValidationRegistry.ValidationRequest memory request = agentIdentityModule.getValidationStatus(requestHash);
        assertEq(uint8(request.response), uint8(IValidationRegistry.ValidationResponse.Approved), "Should be approved");
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_getAgentId() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall(abi.encode(AGENT_URI));

        uint256 agentId = agentIdentityModule.getAgentId(address(account));
        assertEq(agentId, 1, "Agent ID should be 1");
    }

    function test_getAgentId_returnsZeroIfNotRegistered() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall("");

        uint256 agentId = agentIdentityModule.getAgentId(address(account));
        assertEq(agentId, 0, "Agent ID should be 0");
    }

    function test_isRegisteredAgent() public {
        vm.prank(address(account));
        agentIdentityModule.onInstall("");

        assertFalse(agentIdentityModule.isRegisteredAgent(address(account)), "Should not be registered");

        vm.prank(address(account));
        agentIdentityModule.registerAgent(AGENT_URI);

        assertTrue(agentIdentityModule.isRegisteredAgent(address(account)), "Should be registered");
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_registerAgent(
        string calldata uri
    ) public {
        vm.assume(bytes(uri).length > 0);
        vm.assume(bytes(uri).length < 1000);

        vm.prank(address(account));
        agentIdentityModule.onInstall("");

        vm.prank(address(account));
        uint256 agentId = agentIdentityModule.registerAgent(uri);

        assertTrue(agentId > 0, "Agent ID should be positive");
        assertTrue(agentIdentityModule.isRegisteredAgent(address(account)), "Should be registered");
    }

    function testFuzz_giveFeedback(int128 value) public {
        vm.assume(value != 0);

        vm.prank(address(account));
        agentIdentityModule.onInstall(abi.encode(AGENT_URI));

        MpcSmartAccount account2 = createDefaultAccount(1);
        vm.prank(address(account2));
        agentIdentityModule.onInstall(abi.encode("ipfs://QmOtherAgent"));

        uint256 targetAgentId = agentIdentityModule.getAgentId(address(account2));

        vm.prank(address(account));
        agentIdentityModule.giveFeedback(targetAgentId, value, 18, "tag", "", bytes32(0));

        IReputationRegistry.FeedbackData memory feedback = mockReputationRegistry.getFeedback(targetAgentId, 0);
        assertEq(feedback.value, value, "Feedback value should match");
    }
}
