/**
 * ERC-7715 JSON-RPC method handlers
 *
 * Implements the four ERC-7715 JSON-RPC methods:
 * - wallet_requestExecutionPermissions
 * - wallet_revokeExecutionPermission
 * - wallet_getSupportedExecutionPermissions
 * - wallet_getGrantedExecutionPermissions
 */

import type { Address } from '../types';
import type {
  ERC7715Method,
  ERC7715RpcRequest,
  GetGrantedExecutionPermissionsParams,
  GetSupportedExecutionPermissionsParams,
  GrantedPermissionsResponse,
  PermissionRequest,
  PermissionResponse,
  PermissionRevocationResponse,
  RequestExecutionPermissionsParams,
  RevokeExecutionPermissionParams,
  SupportedPermissionsResponse,
} from './types';
import { ERC7715ErrorCode, isValidChainIdHex, isValidPermissionId } from './types';
import type { PermissionManager } from './manager';

// ============================================================================
// Error Classes
// ============================================================================

/**
 * ERC-7715 RPC error
 */
export class ERC7715RpcError extends Error {
  constructor(
    public readonly code: ERC7715ErrorCode,
    message: string,
    public readonly data?: unknown
  ) {
    super(message);
    this.name = 'ERC7715RpcError';
  }

  toJSON(): { code: number; message: string; data?: unknown } {
    return {
      code: this.code,
      message: this.message,
      data: this.data,
    };
  }
}

// ============================================================================
// RPC Handler Types
// ============================================================================

export type RpcHandler<TParams, TResult> = (params: TParams) => Promise<TResult>;

export interface ERC7715RpcHandlers {
  wallet_requestExecutionPermissions: RpcHandler<
    RequestExecutionPermissionsParams,
    PermissionResponse
  >;
  wallet_revokeExecutionPermission: RpcHandler<
    RevokeExecutionPermissionParams,
    PermissionRevocationResponse
  >;
  wallet_getSupportedExecutionPermissions: RpcHandler<
    GetSupportedExecutionPermissionsParams,
    SupportedPermissionsResponse
  >;
  wallet_getGrantedExecutionPermissions: RpcHandler<
    GetGrantedExecutionPermissionsParams,
    GrantedPermissionsResponse
  >;
}

// ============================================================================
// Request Execution Permissions Handler
// ============================================================================

/**
 * Create handler for wallet_requestExecutionPermissions
 *
 * Requests new execution permissions from the wallet. The wallet may prompt
 * the user for approval before granting permissions.
 */
export function createRequestExecutionPermissionsHandler(
  permissionManager: PermissionManager,
  options: {
    /** Callback to prompt user for approval */
    onApprovalRequest?: (request: PermissionRequest) => Promise<boolean>;
    /** Account address to use if not specified in request */
    defaultAccount?: Address;
  } = {}
): RpcHandler<RequestExecutionPermissionsParams, PermissionResponse> {
  return async (params) => {
    // Validate params
    if (!params || !params[0]) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        'Missing permission request parameter'
      );
    }

    const request = params[0];

    // Validate chain ID
    if (!isValidChainIdHex(request.chainId)) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        `Invalid chain ID format: ${request.chainId}`
      );
    }

    // Validate expiry
    const now = Math.floor(Date.now() / 1000);
    if (request.expiry <= now) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        'Permission expiry must be in the future'
      );
    }

    // Validate permissions array
    if (!request.permissions || request.permissions.length === 0) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        'At least one permission must be requested'
      );
    }

    // Check if chain is supported
    if (!permissionManager.isChainSupported(request.chainId)) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.ChainNotSupported,
        `Chain ${request.chainId} is not supported`
      );
    }

    // Validate requested permissions are supported
    const supported = permissionManager.getSupportedPermissions(request.chainId);
    for (const permission of request.permissions) {
      const supportedPermission = supported.permissions.find(
        (p) => p.type === permission.type
      );
      if (!supportedPermission) {
        throw new ERC7715RpcError(
          ERC7715ErrorCode.UnsupportedPermission,
          `Permission type '${permission.type}' is not supported`
        );
      }
    }

    // Request user approval if callback provided
    if (options.onApprovalRequest) {
      const approved = await options.onApprovalRequest(request);
      if (!approved) {
        throw new ERC7715RpcError(
          ERC7715ErrorCode.PermissionDenied,
          'User denied the permission request'
        );
      }
    }

    // Grant the permission
    const accountAddress = request.address ?? options.defaultAccount;
    if (!accountAddress) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        'No account address specified and no default account configured'
      );
    }

    const response = await permissionManager.grantPermission({
      ...request,
      address: accountAddress,
    });

    return response;
  };
}

// ============================================================================
// Revoke Execution Permission Handler
// ============================================================================

/**
 * Create handler for wallet_revokeExecutionPermission
 *
 * Revokes a previously granted permission.
 */
export function createRevokeExecutionPermissionHandler(
  permissionManager: PermissionManager
): RpcHandler<RevokeExecutionPermissionParams, PermissionRevocationResponse> {
  return async (params) => {
    // Validate params
    if (!params || !params[0]) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        'Missing revocation request parameter'
      );
    }

    const request = params[0];

    // Validate permission ID
    if (!isValidPermissionId(request.permissionId)) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        `Invalid permission ID format: ${request.permissionId}`
      );
    }

    // Validate chain ID
    if (!isValidChainIdHex(request.chainId)) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        `Invalid chain ID format: ${request.chainId}`
      );
    }

    // Check if permission exists
    const permission = permissionManager.getPermission(request.permissionId);
    if (!permission) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        `Permission not found: ${request.permissionId}`
      );
    }

    // Check if already revoked
    const info = permissionManager.getPermissionInfo(request.permissionId);
    if (info?.status === 'revoked') {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.PermissionRevoked,
        'Permission has already been revoked'
      );
    }

    // Revoke the permission
    const response = await permissionManager.revokePermission(request.permissionId);

    return response;
  };
}

// ============================================================================
// Get Supported Execution Permissions Handler
// ============================================================================

/**
 * Create handler for wallet_getSupportedExecutionPermissions
 *
 * Returns the list of permission types supported by the wallet for a given chain.
 */
export function createGetSupportedExecutionPermissionsHandler(
  permissionManager: PermissionManager
): RpcHandler<GetSupportedExecutionPermissionsParams, SupportedPermissionsResponse> {
  return async (params) => {
    // Validate params
    if (!params || !params[0]) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        'Missing chain ID parameter'
      );
    }

    const { chainId } = params[0];

    // Validate chain ID
    if (!isValidChainIdHex(chainId)) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        `Invalid chain ID format: ${chainId}`
      );
    }

    // Check if chain is supported
    if (!permissionManager.isChainSupported(chainId)) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.ChainNotSupported,
        `Chain ${chainId} is not supported`
      );
    }

    return permissionManager.getSupportedPermissions(chainId);
  };
}

// ============================================================================
// Get Granted Execution Permissions Handler
// ============================================================================

/**
 * Create handler for wallet_getGrantedExecutionPermissions
 *
 * Returns all granted permissions for a given account and chain.
 */
export function createGetGrantedExecutionPermissionsHandler(
  permissionManager: PermissionManager,
  options: {
    /** Default account address if not specified in query */
    defaultAccount?: Address;
  } = {}
): RpcHandler<GetGrantedExecutionPermissionsParams, GrantedPermissionsResponse> {
  return async (params) => {
    // Validate params
    if (!params || !params[0]) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        'Missing query parameter'
      );
    }

    const query = params[0];

    // Validate chain ID
    if (!isValidChainIdHex(query.chainId)) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        `Invalid chain ID format: ${query.chainId}`
      );
    }

    const accountAddress = query.address ?? options.defaultAccount;
    if (!accountAddress) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        'No account address specified and no default account configured'
      );
    }

    return permissionManager.getGrantedPermissions({
      chainId: query.chainId,
      address: accountAddress,
    });
  };
}

// ============================================================================
// RPC Router
// ============================================================================

/**
 * Configuration for creating an ERC-7715 RPC router
 */
export interface ERC7715RpcRouterConfig {
  /** Permission manager instance */
  permissionManager: PermissionManager;
  /** Default account address */
  defaultAccount?: Address;
  /** Callback to prompt user for approval */
  onApprovalRequest?: (request: PermissionRequest) => Promise<boolean>;
}

/**
 * Create a complete ERC-7715 RPC router
 *
 * @example
 * ```typescript
 * const router = createERC7715RpcRouter({
 *   permissionManager,
 *   defaultAccount: walletAddress,
 *   onApprovalRequest: async (request) => {
 *     // Show approval UI to user
 *     return await showApprovalDialog(request);
 *   },
 * });
 *
 * // Handle incoming RPC request
 * const result = await router.handleRequest({
 *   method: 'wallet_requestExecutionPermissions',
 *   params: [permissionRequest],
 * });
 * ```
 */
export function createERC7715RpcRouter(config: ERC7715RpcRouterConfig): {
  handlers: ERC7715RpcHandlers;
  handleRequest: <T = unknown>(request: ERC7715RpcRequest) => Promise<T>;
} {
  const handlers: ERC7715RpcHandlers = {
    wallet_requestExecutionPermissions: createRequestExecutionPermissionsHandler(
      config.permissionManager,
      {
        defaultAccount: config.defaultAccount,
        onApprovalRequest: config.onApprovalRequest,
      }
    ),
    wallet_revokeExecutionPermission: createRevokeExecutionPermissionHandler(
      config.permissionManager
    ),
    wallet_getSupportedExecutionPermissions: createGetSupportedExecutionPermissionsHandler(
      config.permissionManager
    ),
    wallet_getGrantedExecutionPermissions: createGetGrantedExecutionPermissionsHandler(
      config.permissionManager,
      {
        defaultAccount: config.defaultAccount,
      }
    ),
  };

  const handleRequest = async <T = unknown>(request: ERC7715RpcRequest): Promise<T> => {
    const handler = handlers[request.method];
    if (!handler) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        `Unknown method: ${request.method}`
      );
    }

    // Type assertion needed due to union type handling
    return handler(request.params as never) as Promise<T>;
  };

  return { handlers, handleRequest };
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Check if a method is an ERC-7715 method
 */
export function isERC7715Method(method: string): method is ERC7715Method {
  const erc7715Methods: ERC7715Method[] = [
    'wallet_requestExecutionPermissions',
    'wallet_revokeExecutionPermission',
    'wallet_getSupportedExecutionPermissions',
    'wallet_getGrantedExecutionPermissions',
  ];
  return erc7715Methods.includes(method as ERC7715Method);
}

/**
 * Create a JSON-RPC error response
 */
export function createRpcErrorResponse(
  id: string | number | null,
  error: ERC7715RpcError
): {
  jsonrpc: '2.0';
  id: string | number | null;
  error: { code: number; message: string; data?: unknown };
} {
  return {
    jsonrpc: '2.0',
    id,
    error: error.toJSON(),
  };
}

/**
 * Create a JSON-RPC success response
 */
export function createRpcSuccessResponse<T>(
  id: string | number | null,
  result: T
): {
  jsonrpc: '2.0';
  id: string | number | null;
  result: T;
} {
  return {
    jsonrpc: '2.0',
    id,
    result,
  };
}
