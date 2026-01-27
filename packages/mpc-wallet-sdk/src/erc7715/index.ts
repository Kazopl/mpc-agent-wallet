/**
 * ERC-7715 wallet execution permissions module
 *
 * Provides types and utilities for implementing ERC-7715 compliant
 * permission management in AI agent wallets.
 *
 * ERC-7715 defines a standard JSON-RPC interface for dapps and AI agents
 * to request fine-grained permissions from wallets to execute transactions
 * on the user's behalf.
 *
 * @example
 * ```typescript
 * import {
 *   ERC7715Provider,
 *   PermissionManager,
 *   createERC7715Provider,
 * } from '@mpc-wallet/sdk/erc7715';
 *
 * // Create a provider for handling permission requests
 * const provider = createERC7715Provider({
 *   accountAddress: walletAddress,
 *   chainId: '0x1',
 *   onApprovalRequest: async (request) => {
 *     return await showApprovalDialog(request);
 *   },
 * });
 *
 * // Request permissions
 * const permission = await provider.requestPermissions({
 *   chainId: '0x1',
 *   expiry: Math.floor(Date.now() / 1000) + 86400,
 *   signer: { type: 'account', data: { id: agentAddress } },
 *   permissions: [{
 *     type: 'native-token-transfer',
 *     data: { allowance: '0xDE0B6B3A7640000' },
 *     required: true,
 *   }],
 * });
 *
 * // Execute with permission
 * const result = await provider.executeWithPermission(
 *   permission.permissionsContext,
 *   [{ to: recipient, value: '0x38D7EA4C68000', data: '0x' }]
 * );
 * ```
 */

// Types
export * from './types';

// Permission Manager
export {
  PermissionManager,
  type PermissionManagerConfig,
} from './manager';

// JSON-RPC Handlers
export {
  ERC7715RpcError,
  createERC7715RpcRouter,
  createRequestExecutionPermissionsHandler,
  createRevokeExecutionPermissionHandler,
  createGetSupportedExecutionPermissionsHandler,
  createGetGrantedExecutionPermissionsHandler,
  isERC7715Method,
  createRpcErrorResponse,
  createRpcSuccessResponse,
  type ERC7715RpcHandlers,
  type ERC7715RpcRouterConfig,
  type RpcHandler,
} from './rpc';

// Provider
export {
  ERC7715Provider,
  PermissionRequestBuilder,
  createERC7715Provider,
  type ERC7715ProviderConfig,
  type EIP1193Provider,
  type EIP1193RequestArguments,
  type EIP1193EventType,
  type ConnectionInfo,
} from './provider';
