// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title IIdentityRegistry
 * @notice ERC-8004 Identity Registry interface for AI agent registration
 * @dev Provides portable agent handles (ERC-721) pointing to registration files
 *
 * Deployed Address (deterministic across all networks):
 * 0x7177a6867296406881E20d6647232314736Dd09A
 */
interface IIdentityRegistry {
    struct AgentMetadata {
        string key;
        bytes value;
    }

    event AgentRegistered(uint256 indexed agentId, address indexed registrant, string agentURI);
    event AgentURIUpdated(uint256 indexed agentId, string oldURI, string newURI);
    event AgentWalletSet(uint256 indexed agentId, address indexed wallet);
    event AgentMetadataSet(uint256 indexed agentId, string key, bytes value);

    error AgentNotFound(uint256 agentId);
    error NotAgentOwner(uint256 agentId, address caller);
    error InvalidAgentURI();
    error InvalidSignature();
    error SignatureExpired();
    error WalletAlreadyLinked(address wallet);

    /**
     * @notice Register a new AI agent
     * @param agentURI URI pointing to the agent registration file (IPFS, Arweave, etc.)
     * @return agentId The unique agent identifier (ERC-721 token ID)
     */
    function register(
        string calldata agentURI
    ) external returns (uint256 agentId);

    /**
     * @notice Update an agent's registration URI
     * @param agentId The agent identifier
     * @param newURI The new registration file URI
     */
    function setAgentURI(uint256 agentId, string calldata newURI) external;

    /**
     * @notice Link a wallet address to an agent (with signature authorization)
     * @param agentId The agent identifier
     * @param wallet The wallet address to link
     * @param deadline Signature expiration timestamp
     * @param signature Wallet owner's signature authorizing the link
     */
    function setAgentWallet(uint256 agentId, address wallet, uint256 deadline, bytes calldata signature) external;

    /**
     * @notice Get the wallet address linked to an agent
     * @param agentId The agent identifier
     * @return The linked wallet address (address(0) if none)
     */
    function getAgentWallet(
        uint256 agentId
    ) external view returns (address);

    /**
     * @notice Get metadata value for an agent
     * @param agentId The agent identifier
     * @param key The metadata key
     * @return The metadata value
     */
    function getMetadata(uint256 agentId, string calldata key) external view returns (bytes memory);

    /**
     * @notice Set metadata value for an agent
     * @param agentId The agent identifier
     * @param key The metadata key
     * @param value The metadata value
     */
    function setMetadata(uint256 agentId, string calldata key, bytes calldata value) external;

    /**
     * @notice Get the registration URI for an agent
     * @param agentId The agent identifier
     * @return The agent registration URI
     */
    function agentURI(
        uint256 agentId
    ) external view returns (string memory);

    /**
     * @notice Get the owner of an agent
     * @param agentId The agent identifier
     * @return The owner address
     */
    function ownerOf(
        uint256 agentId
    ) external view returns (address);
}

/**
 * @title IReputationRegistry
 * @notice ERC-8004 Reputation Registry interface for feedback signals
 * @dev Provides on-chain composable reputation with tagged feedback
 *
 * Deployed Address (deterministic across all networks):
 * 0xB5048e3ef1DA4E04deB6f7d0423D06F63869e322
 */
interface IReputationRegistry {
    struct FeedbackData {
        address reviewer;
        int128 value;
        uint8 decimals;
        string tag1;
        string tag2;
        bytes32 proofOfPayment;
        uint64 timestamp;
        bool revoked;
    }

    struct ReputationSummary {
        uint64 feedbackCount;
        int128 aggregateValue;
        uint8 decimals;
    }

    event FeedbackGiven(
        uint256 indexed agentId,
        address indexed reviewer,
        int128 value,
        uint8 decimals,
        string tag1,
        string tag2,
        uint64 feedbackIndex
    );
    event FeedbackRevoked(uint256 indexed agentId, address indexed reviewer, uint64 feedbackIndex);

    error AgentNotRegistered(uint256 agentId);
    error FeedbackNotFound(uint256 agentId, uint64 feedbackIndex);
    error FeedbackAlreadyRevoked(uint256 agentId, uint64 feedbackIndex);
    error NotFeedbackOwner(uint64 feedbackIndex, address caller);
    error InvalidFeedbackValue();

    /**
     * @notice Submit feedback for an agent
     * @param agentId The agent identifier
     * @param value The feedback value (positive or negative)
     * @param decimals The decimal precision of the value
     * @param tag1 Primary categorization tag
     * @param tag2 Secondary categorization tag
     * @param proofOfPayment Hash of payment transaction (optional, bytes32(0) if none)
     * @return feedbackIndex The index of the submitted feedback
     */
    function giveFeedback(
        uint256 agentId,
        int128 value,
        uint8 decimals,
        string calldata tag1,
        string calldata tag2,
        bytes32 proofOfPayment
    ) external returns (uint64 feedbackIndex);

    /**
     * @notice Revoke previously submitted feedback
     * @param agentId The agent identifier
     * @param feedbackIndex The index of feedback to revoke
     */
    function revokeFeedback(uint256 agentId, uint64 feedbackIndex) external;

    /**
     * @notice Get aggregated reputation summary for an agent
     * @param agentId The agent identifier
     * @param clients Filter by specific reviewer addresses (empty for all)
     * @param tag1 Filter by primary tag (empty string for all)
     * @param tag2 Filter by secondary tag (empty string for all)
     * @return summary The aggregated reputation data
     */
    function getSummary(
        uint256 agentId,
        address[] calldata clients,
        string calldata tag1,
        string calldata tag2
    ) external view returns (ReputationSummary memory summary);

    /**
     * @notice Get specific feedback by index
     * @param agentId The agent identifier
     * @param feedbackIndex The feedback index
     * @return feedback The feedback data
     */
    function getFeedback(uint256 agentId, uint64 feedbackIndex) external view returns (FeedbackData memory feedback);

    /**
     * @notice Get total feedback count for an agent
     * @param agentId The agent identifier
     * @return The total number of feedback entries
     */
    function getFeedbackCount(
        uint256 agentId
    ) external view returns (uint64);
}

/**
 * @title IValidationRegistry
 * @notice ERC-8004 Validation Registry interface for independent attestations
 * @dev Supports TEE, zkML, and stake-based validation models
 *
 * Deployed Address (deterministic across all networks):
 * 0x662b40A526cb4017d947e71eAF6753BF3eeE66d8
 */
interface IValidationRegistry {
    enum ValidationResponse {
        Pending,
        Approved,
        Rejected,
        Expired
    }

    enum TrustModel {
        Reputation,
        CryptoEconomic,
        TeeAttestation,
        ZkMl
    }

    struct ValidationRequest {
        address requester;
        address validator;
        uint256 agentId;
        string requestURI;
        bytes32 contentHash;
        uint64 timestamp;
        uint64 expiresAt;
        ValidationResponse response;
        bytes responseData;
        TrustModel trustModel;
    }

    event ValidationRequested(
        bytes32 indexed requestHash,
        uint256 indexed agentId,
        address indexed validator,
        string requestURI,
        bytes32 contentHash
    );
    event ValidationResponded(bytes32 indexed requestHash, ValidationResponse response, bytes responseData);
    event ValidationExpired(bytes32 indexed requestHash);

    error RequestNotFound(bytes32 requestHash);
    error RequestAlreadyExists(bytes32 requestHash);
    error RequestExpired(bytes32 requestHash);
    error RequestAlreadyResponded(bytes32 requestHash);
    error NotDesignatedValidator(bytes32 requestHash, address caller);
    error InvalidRequestURI();
    error InvalidValidator();

    /**
     * @notice Submit a validation request
     * @param validator The designated validator address
     * @param agentId The agent requesting validation
     * @param requestURI URI pointing to validation request details
     * @param contentHash Hash of the content to validate
     * @return requestHash Unique identifier for the request
     */
    function validationRequest(
        address validator,
        uint256 agentId,
        string calldata requestURI,
        bytes32 contentHash
    ) external returns (bytes32 requestHash);

    /**
     * @notice Submit a validation response
     * @param requestHash The request identifier
     * @param response The validation response (Approved/Rejected)
     * @param responseData Additional response data (attestation, proof, etc.)
     */
    function validationResponse(bytes32 requestHash, ValidationResponse response, bytes calldata responseData)
        external;

    /**
     * @notice Get validation request status
     * @param requestHash The request identifier
     * @return request The validation request data
     */
    function getValidationStatus(
        bytes32 requestHash
    ) external view returns (ValidationRequest memory request);

    /**
     * @notice Get all validation requests for an agent
     * @param agentId The agent identifier
     * @return requestHashes Array of request hashes
     */
    function getAgentValidations(
        uint256 agentId
    ) external view returns (bytes32[] memory requestHashes);

    /**
     * @notice Get validation requests by validator
     * @param validator The validator address
     * @return requestHashes Array of request hashes
     */
    function getValidatorRequests(
        address validator
    ) external view returns (bytes32[] memory requestHashes);

    /**
     * @notice Check if a validation request has expired
     * @param requestHash The request identifier
     * @return True if expired
     */
    function isExpired(
        bytes32 requestHash
    ) external view returns (bool);
}

/**
 * @title ERC8004Addresses
 * @notice Deterministic deployment addresses for ERC-8004 registries
 * @dev These addresses are the same across all EVM networks
 */
library ERC8004Addresses {
    address internal constant IDENTITY_REGISTRY = 0x7177a6867296406881E20d6647232314736Dd09A;
    address internal constant REPUTATION_REGISTRY = 0xB5048e3ef1DA4E04deB6f7d0423D06F63869e322;
    address internal constant VALIDATION_REGISTRY = 0x662b40A526cb4017d947e71eAF6753BF3eeE66d8;
}
