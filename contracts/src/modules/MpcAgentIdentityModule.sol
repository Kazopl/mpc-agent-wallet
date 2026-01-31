// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IERC7579Module } from "../interfaces/IERC7579Module.sol";
import {
    IIdentityRegistry,
    IReputationRegistry,
    IValidationRegistry,
    ERC8004Addresses
} from "../interfaces/IERC8004.sol";

/**
 * @title IMpcAgentIdentityModule
 * @notice Interface for MPC agent identity management module
 */
interface IMpcAgentIdentityModule {
    struct AgentConfig {
        uint256 agentId;
        string agentURI;
        bool autoFeedback;
    }

    event AgentRegistered(address indexed account, uint256 indexed agentId, string agentURI);
    event AgentURIUpdated(address indexed account, uint256 indexed agentId, string newURI);
    event AgentWalletLinked(address indexed account, uint256 indexed agentId, address wallet);
    event FeedbackSubmitted(
        address indexed account, uint256 indexed targetAgentId, int128 value, string tag1, string tag2
    );
    event ValidationRequested(
        address indexed account, uint256 indexed agentId, address validator, bytes32 requestHash
    );

    error NotAccountOwner();
    error AgentNotRegistered();
    error AgentAlreadyRegistered();
    error InvalidAgentURI();
    error InvalidFeedbackValue();
    error InvalidValidator();
    error RegistryCallFailed();
}

/**
 * @title MpcAgentIdentityModule
 * @author MPC Agent Wallet SDK
 * @notice Enables AI agent registration and reputation management via ERC-8004
 * @dev Implements IERC7579Module (Type 2: Executor) for ERC-7579 compatibility
 *
 * @dev Key features:
 *      - Register AI agents in ERC-8004 Identity Registry
 *      - Update agent registration URIs
 *      - Link wallet addresses to agent identities
 *      - Submit reputation feedback for other agents
 *      - Request validation attestations
 *
 * Integration with ERC-8004:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                    MPC AGENT IDENTITY MODULE                                │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │   ┌──────────────────┐         ┌──────────────────────┐                    │
 * │   │  MpcSmartAccount │────────►│ MpcAgentIdentityModule│                   │
 * │   │                  │         │                      │                    │
 * │   └──────────────────┘         └──────────┬───────────┘                    │
 * │                                           │                                │
 * │                    ┌──────────────────────┼──────────────────────┐         │
 * │                    │                      │                      │         │
 * │                    ▼                      ▼                      ▼         │
 * │         ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐   │
 * │         │    Identity     │   │   Reputation    │   │   Validation    │   │
 * │         │    Registry     │   │    Registry     │   │    Registry     │   │
 * │         │   (ERC-721)     │   │                 │   │                 │   │
 * │         └─────────────────┘   └─────────────────┘   └─────────────────┘   │
 * │                                                                             │
 * │   Features:                                                                 │
 * │   • Portable agent identities (ERC-721 NFTs)                               │
 * │   • On-chain reputation with tagged feedback                                │
 * │   • TEE/zkML/stake-based validation attestations                           │
 * │                                                                             │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract MpcAgentIdentityModule is IMpcAgentIdentityModule, IERC7579Module {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 public constant MODULE_TYPE = 2;

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    mapping(address => AgentConfig) internal _agentConfigs;
    mapping(address => bool) internal _initialized;

    IIdentityRegistry public immutable identityRegistry;
    IReputationRegistry public immutable reputationRegistry;
    IValidationRegistry public immutable validationRegistry;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _identityRegistry, address _reputationRegistry, address _validationRegistry) {
        identityRegistry = IIdentityRegistry(
            _identityRegistry == address(0) ? ERC8004Addresses.IDENTITY_REGISTRY : _identityRegistry
        );
        reputationRegistry = IReputationRegistry(
            _reputationRegistry == address(0) ? ERC8004Addresses.REPUTATION_REGISTRY : _reputationRegistry
        );
        validationRegistry = IValidationRegistry(
            _validationRegistry == address(0) ? ERC8004Addresses.VALIDATION_REGISTRY : _validationRegistry
        );
    }

    /*//////////////////////////////////////////////////////////////
                              MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyInstalledAccount() {
        if (!_initialized[msg.sender]) {
            revert NotInitialized(msg.sender);
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                       ERC-7579 MODULE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IERC7579Module
     * @dev Initializes agent identity module for the calling account
     *      Data format: abi.encode(agentURI) or empty bytes for no auto-registration
     */
    function onInstall(
        bytes calldata data
    ) external override {
        address account = msg.sender;

        if (_initialized[account]) {
            revert AlreadyInitialized(account);
        }

        _initialized[account] = true;

        if (data.length > 0) {
            string memory agentURI = abi.decode(data, (string));
            if (bytes(agentURI).length > 0) {
                _registerAgent(account, agentURI);
            }
        }

        emit ModuleInstalled(account);
    }

    /**
     * @inheritdoc IERC7579Module
     * @dev Cleans up agent identity configuration for the calling account
     */
    function onUninstall(
        bytes calldata
    ) external override {
        address account = msg.sender;

        if (!_initialized[account]) {
            revert NotInitialized(account);
        }

        delete _agentConfigs[account];
        _initialized[account] = false;

        emit ModuleUninstalled(account);
    }

    /**
     * @inheritdoc IERC7579Module
     * @dev This is an Executor module (Type 2)
     */
    function isModuleType(
        uint256 moduleTypeId
    ) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE;
    }

    /**
     * @inheritdoc IERC7579Module
     */
    function isInitialized(
        address account
    ) external view override returns (bool) {
        return _initialized[account];
    }

    /*//////////////////////////////////////////////////////////////
                        AGENT REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register the calling account as an AI agent
     * @param agentURI URI pointing to the agent registration file
     * @return agentId The assigned agent identifier
     */
    function registerAgent(
        string calldata agentURI
    ) external onlyInstalledAccount returns (uint256 agentId) {
        address account = msg.sender;

        if (_agentConfigs[account].agentId != 0) {
            revert AgentAlreadyRegistered();
        }

        return _registerAgent(account, agentURI);
    }

    /**
     * @notice Update the agent's registration URI
     * @param newURI The new registration file URI
     */
    function updateAgentURI(
        string calldata newURI
    ) external onlyInstalledAccount {
        address account = msg.sender;
        uint256 agentId = _agentConfigs[account].agentId;

        if (agentId == 0) {
            revert AgentNotRegistered();
        }

        if (bytes(newURI).length == 0) {
            revert InvalidAgentURI();
        }

        identityRegistry.setAgentURI(agentId, newURI);
        _agentConfigs[account].agentURI = newURI;

        emit AgentURIUpdated(account, agentId, newURI);
    }

    /**
     * @notice Link a wallet address to the agent identity
     * @param wallet The wallet address to link
     * @param deadline Signature expiration timestamp
     * @param signature Wallet owner's signature authorizing the link
     */
    function setAgentWallet(address wallet, uint256 deadline, bytes calldata signature) external onlyInstalledAccount {
        address account = msg.sender;
        uint256 agentId = _agentConfigs[account].agentId;

        if (agentId == 0) {
            revert AgentNotRegistered();
        }

        identityRegistry.setAgentWallet(agentId, wallet, deadline, signature);

        emit AgentWalletLinked(account, agentId, wallet);
    }

    /*//////////////////////////////////////////////////////////////
                          REPUTATION MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit feedback for another agent
     * @param targetAgentId The agent to provide feedback for
     * @param value The feedback value (positive or negative, scaled by decimals)
     * @param decimals The decimal precision of the value
     * @param tag1 Primary categorization tag (e.g., "reliability")
     * @param tag2 Secondary categorization tag (e.g., "trading")
     * @param proofOfPayment Hash of payment transaction (bytes32(0) if none)
     * @return feedbackIndex The index of the submitted feedback
     */
    function giveFeedback(
        uint256 targetAgentId,
        int128 value,
        uint8 decimals,
        string calldata tag1,
        string calldata tag2,
        bytes32 proofOfPayment
    ) external onlyInstalledAccount returns (uint64 feedbackIndex) {
        address account = msg.sender;

        if (value == 0) {
            revert InvalidFeedbackValue();
        }

        feedbackIndex = reputationRegistry.giveFeedback(targetAgentId, value, decimals, tag1, tag2, proofOfPayment);

        emit FeedbackSubmitted(account, targetAgentId, value, tag1, tag2);
    }

    /**
     * @notice Revoke previously submitted feedback
     * @param targetAgentId The agent the feedback was for
     * @param feedbackIndex The index of feedback to revoke
     */
    function revokeFeedback(uint256 targetAgentId, uint64 feedbackIndex) external onlyInstalledAccount {
        reputationRegistry.revokeFeedback(targetAgentId, feedbackIndex);
    }

    /**
     * @notice Get reputation summary for an agent
     * @param agentId The agent identifier
     * @param clients Filter by specific reviewer addresses (empty for all)
     * @param tag1 Filter by primary tag (empty string for all)
     * @param tag2 Filter by secondary tag (empty string for all)
     * @return summary The aggregated reputation data
     */
    function getReputationSummary(
        uint256 agentId,
        address[] calldata clients,
        string calldata tag1,
        string calldata tag2
    ) external view returns (IReputationRegistry.ReputationSummary memory summary) {
        return reputationRegistry.getSummary(agentId, clients, tag1, tag2);
    }

    /*//////////////////////////////////////////////////////////////
                          VALIDATION MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Request validation from an independent validator
     * @param validator The designated validator address
     * @param requestURI URI pointing to validation request details
     * @param contentHash Hash of the content to validate
     * @return requestHash Unique identifier for the request
     */
    function requestValidation(address validator, string calldata requestURI, bytes32 contentHash)
        external
        onlyInstalledAccount
        returns (bytes32 requestHash)
    {
        address account = msg.sender;
        uint256 agentId = _agentConfigs[account].agentId;

        if (agentId == 0) {
            revert AgentNotRegistered();
        }

        if (validator == address(0)) {
            revert InvalidValidator();
        }

        requestHash = validationRegistry.validationRequest(validator, agentId, requestURI, contentHash);

        emit ValidationRequested(account, agentId, validator, requestHash);
    }

    /**
     * @notice Get validation request status
     * @param requestHash The request identifier
     * @return request The validation request data
     */
    function getValidationStatus(
        bytes32 requestHash
    ) external view returns (IValidationRegistry.ValidationRequest memory request) {
        return validationRegistry.getValidationStatus(requestHash);
    }

    /*//////////////////////////////////////////////////////////////
                             VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get the agent configuration for an account
     * @param account The account address
     * @return config The agent configuration
     */
    function getAgentConfig(
        address account
    ) external view returns (AgentConfig memory config) {
        return _agentConfigs[account];
    }

    /**
     * @notice Get the agent ID for an account
     * @param account The account address
     * @return The agent ID (0 if not registered)
     */
    function getAgentId(
        address account
    ) external view returns (uint256) {
        return _agentConfigs[account].agentId;
    }

    /**
     * @notice Check if an account is a registered agent
     * @param account The account address
     * @return True if the account is a registered agent
     */
    function isRegisteredAgent(
        address account
    ) external view returns (bool) {
        return _agentConfigs[account].agentId != 0;
    }

    /**
     * @notice Get the wallet linked to an agent
     * @param agentId The agent identifier
     * @return The linked wallet address
     */
    function getAgentWallet(
        uint256 agentId
    ) external view returns (address) {
        return identityRegistry.getAgentWallet(agentId);
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _registerAgent(address account, string memory agentURI) internal returns (uint256 agentId) {
        if (bytes(agentURI).length == 0) {
            revert InvalidAgentURI();
        }

        agentId = identityRegistry.register(agentURI);

        _agentConfigs[account] = AgentConfig({ agentId: agentId, agentURI: agentURI, autoFeedback: false });

        emit AgentRegistered(account, agentId, agentURI);
    }
}
