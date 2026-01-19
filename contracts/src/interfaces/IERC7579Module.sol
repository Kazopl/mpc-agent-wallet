// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ERC7579ModuleTypes
 * @notice Module type constants for ERC-7579 compliance
 */
library ERC7579ModuleTypes {
    /// @notice Validator module type (validates signatures)
    /// @dev Example: Session key validators, multisig validators
    uint256 internal constant MODULE_TYPE_VALIDATOR = 1;

    /// @notice Executor module type (executes actions)
    /// @dev Example: Recovery modules, automation modules
    uint256 internal constant MODULE_TYPE_EXECUTOR = 2;

    /// @notice Fallback handler module type
    /// @dev Example: ERC-721/1155 receivers, custom handlers
    uint256 internal constant MODULE_TYPE_FALLBACK = 3;

    /// @notice Hook module type (pre/post execution)
    /// @dev Example: Spending limit hooks, allowlist hooks
    uint256 internal constant MODULE_TYPE_HOOK = 4;
}

/**
 * @title IERC7579Module
 * @notice Standard interface for ERC-7579 smart account modules
 * @dev ERC-7579 defines a modular smart account architecture with standardized module interfaces.
 *      This enables interoperability between different smart account implementations.
 *
 * Module Types (defined in ERC7579ModuleTypes library):
 * - Type 1: Validator - Validates signatures and operations
 * - Type 2: Executor - Executes operations on behalf of the account
 * - Type 3: Fallback Handler - Handles fallback calls
 * - Type 4: Hook - Pre/post execution hooks
 *
 * Reference: https://eips.ethereum.org/EIPS/eip-7579
 */
interface IERC7579Module {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Emitted when module is installed on an account
     * @param account The smart account address
     */
    event ModuleInstalled(address indexed account);

    /**
     * @notice Emitted when module is uninstalled from an account
     * @param account The smart account address
     */
    event ModuleUninstalled(address indexed account);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when initialization data is invalid
    error InvalidInitData();

    /// @notice Thrown when uninstall data is invalid
    error InvalidUninstallData();

    /// @notice Thrown when module is already initialized for account
    error AlreadyInitialized(address account);

    /// @notice Thrown when module is not initialized for account
    error NotInitialized(address account);

    /*//////////////////////////////////////////////////////////////
                          LIFECYCLE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Called when the module is installed on a smart account
     * @dev Should initialize module state for the calling account.
     *      MUST revert if initialization fails or data is invalid.
     *      MUST emit ModuleInstalled event on success.
     * @param data Initialization data (module-specific encoding)
     */
    function onInstall(bytes calldata data) external;

    /**
     * @notice Called when the module is uninstalled from a smart account
     * @dev Should clean up module state for the calling account.
     *      MUST emit ModuleUninstalled event on success.
     *      MAY revert if cleanup fails.
     * @param data Cleanup/deinitialization data (module-specific encoding)
     */
    function onUninstall(bytes calldata data) external;

    /*//////////////////////////////////////////////////////////////
                          TYPE IDENTIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if this module is of a specific type
     * @dev A module can support multiple types (e.g., both Validator and Hook)
     * @param moduleTypeId The module type to check (1-4)
     * @return True if this module implements the specified type
     */
    function isModuleType(uint256 moduleTypeId) external view returns (bool);

    /**
     * @notice Check if module is initialized for a specific account
     * @param account The smart account address
     * @return True if initialized
     */
    function isInitialized(address account) external view returns (bool);
}

/**
 * @title IERC7579AccountConfig
 * @notice Account configuration interface for ERC-7579 compliance
 * @dev Implemented by smart accounts that support modular architecture
 */
interface IERC7579AccountConfig {
    /**
     * @notice Get account implementation identifier
     * @return accountId Unique identifier for this account implementation
     */
    function accountId() external view returns (string memory accountId);

    /**
     * @notice Check if account supports an execution mode
     * @param mode Execution mode identifier
     * @return True if supported
     */
    function supportsExecutionMode(bytes32 mode) external view returns (bool);

    /**
     * @notice Check if account supports a module type
     * @param moduleTypeId Module type ID (1-4)
     * @return True if module type is supported
     */
    function supportsModule(uint256 moduleTypeId) external view returns (bool);
}

/**
 * @title IERC7579ModuleConfig
 * @notice Module configuration interface for smart accounts
 * @dev Allows dynamic installation/uninstallation of modules
 */
interface IERC7579ModuleConfig {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Emitted when a module is installed
     * @param moduleTypeId Type of module installed
     * @param module Module address
     */
    event ModuleInstalled(uint256 moduleTypeId, address module);

    /**
     * @notice Emitted when a module is uninstalled
     * @param moduleTypeId Type of module uninstalled
     * @param module Module address
     */
    event ModuleUninstalled(uint256 moduleTypeId, address module);

    /*//////////////////////////////////////////////////////////////
                          MODULE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Install a module on the account
     * @param moduleTypeId Type of module (1-4)
     * @param module Module contract address
     * @param initData Initialization data for the module
     */
    function installModule(
        uint256 moduleTypeId,
        address module,
        bytes calldata initData
    ) external;

    /**
     * @notice Uninstall a module from the account
     * @param moduleTypeId Type of module (1-4)
     * @param module Module contract address
     * @param deInitData Cleanup data for the module
     */
    function uninstallModule(
        uint256 moduleTypeId,
        address module,
        bytes calldata deInitData
    ) external;

    /**
     * @notice Check if a module is installed
     * @param moduleTypeId Type of module (1-4)
     * @param module Module contract address
     * @param additionalContext Additional context for the check (module-specific)
     * @return True if module is installed and active
     */
    function isModuleInstalled(
        uint256 moduleTypeId,
        address module,
        bytes calldata additionalContext
    ) external view returns (bool);
}
