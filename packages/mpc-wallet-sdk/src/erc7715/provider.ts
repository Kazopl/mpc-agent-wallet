/**
 * ERC-7715 Provider
 *
 * EIP-1193 compatible provider for handling ERC-7715 permission requests.
 * This provider can be used by dapps and AI agents to request and use
 * execution permissions from wallets.
 */

import type { Address, HexString } from '../types';
import { MpcWalletError, ErrorCode } from '../types';
import type {
  Action,
  ChainIdHex,
  ExecutionResponse,
  GrantedPermissionsQuery,
  GrantedPermissionsResponse,
  Permission,
  PermissionId,
  PermissionRequest,
  PermissionResponse,
  PermissionRevocationRequest,
  PermissionRevocationResponse,
  PermissionsContext,
  Policy,
  SignerInfo,
  SupportedPermissionsResponse,
} from './types';
import { ERC7715ErrorCode, isValidChainIdHex } from './types';
import { PermissionManager, type PermissionManagerConfig } from './manager';
import {
  createERC7715RpcRouter,
  ERC7715RpcError,
  isERC7715Method,
} from './rpc';

// ============================================================================
// Types
// ============================================================================

/**
 * EIP-1193 provider event types
 */
export type EIP1193EventType =
  | 'connect'
  | 'disconnect'
  | 'chainChanged'
  | 'accountsChanged'
  | 'message';

/**
 * EIP-1193 provider request arguments
 */
export interface EIP1193RequestArguments {
  method: string;
  params?: unknown[] | object;
}

/**
 * EIP-1193 provider interface
 */
export interface EIP1193Provider {
  request(args: EIP1193RequestArguments): Promise<unknown>;
  on(event: EIP1193EventType, listener: (...args: unknown[]) => void): void;
  removeListener(event: EIP1193EventType, listener: (...args: unknown[]) => void): void;
}

/**
 * ERC-7715 Provider configuration
 */
export interface ERC7715ProviderConfig {
  /** Account address for the wallet */
  accountAddress: Address;
  /** Chain ID (hex format) */
  chainId: ChainIdHex;
  /** Permission manager configuration */
  permissionManagerConfig?: PermissionManagerConfig;
  /** Existing permission manager instance */
  permissionManager?: PermissionManager;
  /** Callback to prompt user for approval */
  onApprovalRequest?: (request: PermissionRequest) => Promise<boolean>;
  /** Callback when a permission is granted */
  onPermissionGranted?: (response: PermissionResponse) => void;
  /** Callback when a permission is revoked */
  onPermissionRevoked?: (response: PermissionRevocationResponse) => void;
  /** Callback to sign and execute actions */
  onExecuteActions?: (
    context: PermissionsContext,
    actions: readonly Action[]
  ) => Promise<HexString>;
}

/**
 * Provider connection info
 */
export interface ConnectionInfo {
  chainId: ChainIdHex;
}

// ============================================================================
// Event Emitter
// ============================================================================

type EventListener = (...args: unknown[]) => void;

class EventEmitter {
  private listeners: Map<string, Set<EventListener>> = new Map();

  on(event: string, listener: EventListener): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(listener);
  }

  removeListener(event: string, listener: EventListener): void {
    this.listeners.get(event)?.delete(listener);
  }

  emit(event: string, ...args: unknown[]): void {
    for (const listener of this.listeners.get(event) ?? []) {
      try {
        listener(...args);
      } catch (error) {
        console.error(`Error in event listener for ${event}:`, error);
      }
    }
  }

  removeAllListeners(event?: string): void {
    if (event) {
      this.listeners.delete(event);
    } else {
      this.listeners.clear();
    }
  }
}

// ============================================================================
// ERC-7715 Provider
// ============================================================================

/**
 * ERC-7715 Provider
 *
 * An EIP-1193 compatible provider that handles ERC-7715 wallet execution permissions.
 * This provider can be used by dapps and AI agents to:
 * - Request permissions from the wallet
 * - Execute actions using granted permissions
 * - Query supported and granted permissions
 *
 * @example
 * ```typescript
 * // Create provider
 * const provider = new ERC7715Provider({
 *   accountAddress: walletAddress,
 *   chainId: '0x1',
 *   onApprovalRequest: async (request) => {
 *     // Show approval UI
 *     return await showApprovalDialog(request);
 *   },
 *   onExecuteActions: async (context, actions) => {
 *     // Execute actions through smart account
 *     return await smartAccount.execute(context, actions);
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
 * const txHash = await provider.executeWithPermission(
 *   permission.permissionsContext,
 *   [{ to: recipient, value: '0x38D7EA4C68000', data: '0x' }]
 * );
 * ```
 */
export class ERC7715Provider implements EIP1193Provider {
  private readonly permissionManager: PermissionManager;
  private readonly accountAddress: Address;
  private chainId: ChainIdHex;
  private readonly events: EventEmitter;
  private readonly rpcRouter: ReturnType<typeof createERC7715RpcRouter>;
  private readonly onExecuteActions?: ERC7715ProviderConfig['onExecuteActions'];
  private readonly onPermissionGranted?: ERC7715ProviderConfig['onPermissionGranted'];
  private readonly onPermissionRevoked?: ERC7715ProviderConfig['onPermissionRevoked'];
  private connected = false;

  constructor(config: ERC7715ProviderConfig) {
    this.accountAddress = config.accountAddress;
    this.chainId = config.chainId;
    this.events = new EventEmitter();
    this.onExecuteActions = config.onExecuteActions;
    this.onPermissionGranted = config.onPermissionGranted;
    this.onPermissionRevoked = config.onPermissionRevoked;

    // Initialize permission manager
    this.permissionManager = config.permissionManager ?? new PermissionManager({
      supportedChains: [config.chainId],
      ...config.permissionManagerConfig,
    });

    // Initialize RPC router
    this.rpcRouter = createERC7715RpcRouter({
      permissionManager: this.permissionManager,
      defaultAccount: this.accountAddress,
      onApprovalRequest: config.onApprovalRequest,
    });

    // Auto-connect
    this.connect();
  }

  // ============================================================================
  // EIP-1193 Interface
  // ============================================================================

  /**
   * Send an RPC request
   */
  async request(args: EIP1193RequestArguments): Promise<unknown> {
    const { method, params } = args;

    // Handle standard Ethereum methods
    switch (method) {
      case 'eth_chainId':
        return this.chainId;

      case 'eth_accounts':
        return this.connected ? [this.accountAddress] : [];

      case 'eth_requestAccounts':
        return [this.accountAddress];

      case 'net_version':
        return String(parseInt(this.chainId, 16));

      case 'wallet_switchEthereumChain':
        return this.switchChain(params as [{ chainId: ChainIdHex }]);
    }

    // Handle ERC-7715 methods
    if (isERC7715Method(method)) {
      const result = await this.rpcRouter.handleRequest({
        method,
        params: params as unknown[],
      });

      // Emit events for permission changes
      if (method === 'wallet_requestExecutionPermissions') {
        this.onPermissionGranted?.(result as PermissionResponse);
        this.events.emit('permissionGranted', result);
      } else if (method === 'wallet_revokeExecutionPermission') {
        this.onPermissionRevoked?.(result as PermissionRevocationResponse);
        this.events.emit('permissionRevoked', result);
      }

      return result;
    }

    throw new ERC7715RpcError(
      ERC7715ErrorCode.InvalidRequest,
      `Unsupported method: ${method}`
    );
  }

  /**
   * Register an event listener
   */
  on(event: EIP1193EventType | string, listener: EventListener): void {
    this.events.on(event, listener);
  }

  /**
   * Remove an event listener
   */
  removeListener(event: EIP1193EventType | string, listener: EventListener): void {
    this.events.removeListener(event, listener);
  }

  // ============================================================================
  // Connection Management
  // ============================================================================

  /**
   * Connect the provider
   */
  connect(): void {
    if (!this.connected) {
      this.connected = true;
      this.events.emit('connect', { chainId: this.chainId });
    }
  }

  /**
   * Disconnect the provider
   */
  disconnect(): void {
    if (this.connected) {
      this.connected = false;
      this.events.emit('disconnect', {
        code: 4900,
        message: 'Provider disconnected',
      });
    }
  }

  /**
   * Check if connected
   */
  isConnected(): boolean {
    return this.connected;
  }

  /**
   * Switch to a different chain
   */
  private async switchChain(params: [{ chainId: ChainIdHex }]): Promise<null> {
    const newChainId = params[0].chainId;

    if (!isValidChainIdHex(newChainId)) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        `Invalid chain ID: ${newChainId}`
      );
    }

    if (!this.permissionManager.isChainSupported(newChainId)) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.ChainNotSupported,
        `Chain ${newChainId} is not supported`
      );
    }

    const oldChainId = this.chainId;
    this.chainId = newChainId;

    if (oldChainId !== newChainId) {
      this.events.emit('chainChanged', newChainId);
    }

    return null;
  }

  // ============================================================================
  // High-Level Permission Methods
  // ============================================================================

  /**
   * Request execution permissions
   *
   * @example
   * ```typescript
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
   * ```
   */
  async requestPermissions(request: Omit<PermissionRequest, 'address'>): Promise<PermissionResponse> {
    const fullRequest: PermissionRequest = {
      ...request,
      address: this.accountAddress,
    };

    return this.request({
      method: 'wallet_requestExecutionPermissions',
      params: [fullRequest],
    }) as Promise<PermissionResponse>;
  }

  /**
   * Revoke an existing permission
   */
  async revokePermission(permissionId: PermissionId): Promise<PermissionRevocationResponse> {
    const request: PermissionRevocationRequest = {
      permissionId,
      chainId: this.chainId,
    };

    return this.request({
      method: 'wallet_revokeExecutionPermission',
      params: [request],
    }) as Promise<PermissionRevocationResponse>;
  }

  /**
   * Get supported execution permissions
   */
  async getSupportedPermissions(
    chainId?: ChainIdHex
  ): Promise<SupportedPermissionsResponse> {
    return this.request({
      method: 'wallet_getSupportedExecutionPermissions',
      params: [{ chainId: chainId ?? this.chainId }],
    }) as Promise<SupportedPermissionsResponse>;
  }

  /**
   * Get granted execution permissions
   */
  async getGrantedPermissions(
    query?: Partial<GrantedPermissionsQuery>
  ): Promise<GrantedPermissionsResponse> {
    const fullQuery: GrantedPermissionsQuery = {
      chainId: query?.chainId ?? this.chainId,
      address: query?.address ?? this.accountAddress,
    };

    return this.request({
      method: 'wallet_getGrantedExecutionPermissions',
      params: [fullQuery],
    }) as Promise<GrantedPermissionsResponse>;
  }

  // ============================================================================
  // Execution Methods
  // ============================================================================

  /**
   * Execute actions using a granted permission
   *
   * @example
   * ```typescript
   * const txHash = await provider.executeWithPermission(
   *   permission.permissionsContext,
   *   [{
   *     to: '0x1234...',
   *     value: '0x38D7EA4C68000', // 0.001 ETH
   *     data: '0x',
   *   }]
   * );
   * ```
   */
  async executeWithPermission(
    permissionsContext: PermissionsContext,
    actions: readonly Action[]
  ): Promise<ExecutionResponse> {
    // Validate permissions context
    const validation = this.permissionManager.validatePermissionsContext(permissionsContext);
    if (!validation.valid) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        validation.error ?? 'Invalid permissions context'
      );
    }

    // Get the permission
    const permission = this.permissionManager.getPermission(validation.permissionId!);
    if (!permission) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        'Permission not found'
      );
    }

    // Validate actions against permission
    this.validateActionsAgainstPermission(actions, permission);

    // Execute through callback if provided
    if (this.onExecuteActions) {
      const txHash = await this.onExecuteActions(permissionsContext, actions);
      return {
        transactionHash: txHash,
        success: true,
      };
    }

    // Default: sign with session key
    const sessionKey = this.permissionManager.getSessionKeyForPermission(validation.permissionId!);
    if (!sessionKey) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'No session key found for permission'
      );
    }

    // Build combined transaction
    const combinedValue = actions.reduce(
      (sum, action) => sum + BigInt(action.value),
      0n
    );

    // Validate spending limit
    const sessionKeyManager = this.permissionManager.getSessionKeyManager();
    const status = sessionKeyManager.getSessionKeyStatus(sessionKey.signer);

    if (!status.isValid) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.PermissionExpired,
        status.message
      );
    }

    if (sessionKey.spendingLimit > 0n && combinedValue > status.remainingSpending) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.SpendingLimitExceeded,
        `Transaction value (${combinedValue}) exceeds remaining spending limit (${status.remainingSpending})`
      );
    }

    // Record spending
    sessionKeyManager.recordSpending(sessionKey.signer, combinedValue);

    // Return placeholder - actual execution would go through smart account
    return {
      transactionHash: '0x' + '0'.repeat(64) as HexString,
      success: true,
    };
  }

  /**
   * Validate actions against permission constraints
   */
  private validateActionsAgainstPermission(
    actions: readonly Action[],
    permission: PermissionResponse
  ): void {
    // Check for empty actions
    if (actions.length === 0) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.InvalidRequest,
        'At least one action is required'
      );
    }

    // Collect allowed targets and values from permissions
    const allowedTargets = new Set<string>();
    let totalAllowance = 0n;
    let hasNativeTransfer = false;

    for (const granted of permission.permissions) {
      switch (granted.type) {
        case 'native-token-transfer':
          hasNativeTransfer = true;
          totalAllowance += BigInt((granted.data as { allowance: HexString }).allowance);
          break;
        case 'erc20-token-transfer':
          allowedTargets.add((granted.data as { address: Address }).address.toLowerCase());
          break;
        case 'contract-call':
          allowedTargets.add((granted.data as { address: Address }).address.toLowerCase());
          break;
      }
    }

    // Validate each action
    let totalValue = 0n;
    for (const action of actions) {
      const targetLower = action.to.toLowerCase();

      // Check if action requires native transfer permission
      const actionValue = BigInt(action.value);
      if (actionValue > 0n) {
        if (!hasNativeTransfer) {
          throw new ERC7715RpcError(
            ERC7715ErrorCode.InsufficientPermission,
            'Native token transfer not permitted'
          );
        }
        totalValue += actionValue;
      }

      // Check contract call permission
      if (action.data && action.data !== '0x') {
        if (allowedTargets.size > 0 && !allowedTargets.has(targetLower)) {
          throw new ERC7715RpcError(
            ERC7715ErrorCode.InsufficientPermission,
            `Contract call to ${action.to} not permitted`
          );
        }
      }
    }

    // Validate total value against allowance
    if (hasNativeTransfer && totalValue > totalAllowance) {
      throw new ERC7715RpcError(
        ERC7715ErrorCode.SpendingLimitExceeded,
        `Total value (${totalValue}) exceeds permission allowance (${totalAllowance})`
      );
    }
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  /**
   * Get the current account address
   */
  getAccountAddress(): Address {
    return this.accountAddress;
  }

  /**
   * Get the current chain ID
   */
  getChainId(): ChainIdHex {
    return this.chainId;
  }

  /**
   * Get the permission manager
   */
  getPermissionManager(): PermissionManager {
    return this.permissionManager;
  }

  /**
   * Check if a permission is still valid
   */
  isPermissionValid(permissionId: PermissionId): boolean {
    const info = this.permissionManager.getPermissionInfo(permissionId);
    return info?.status === 'active';
  }

  /**
   * Get remaining time for a permission (in seconds)
   */
  getPermissionTimeRemaining(permissionId: PermissionId): number {
    const info = this.permissionManager.getPermissionInfo(permissionId);
    if (!info || info.status !== 'active') {
      return 0;
    }
    const now = Math.floor(Date.now() / 1000);
    return Math.max(0, info.expiry - now);
  }

  // ============================================================================
  // Factory Methods
  // ============================================================================

  /**
   * Create a permission request builder
   */
  createPermissionRequest(): PermissionRequestBuilder {
    return new PermissionRequestBuilder(this.chainId);
  }
}

// ============================================================================
// Permission Request Builder
// ============================================================================

/**
 * Builder for creating ERC-7715 permission requests
 *
 * @example
 * ```typescript
 * const request = provider.createPermissionRequest()
 *   .expireIn(86400) // 24 hours
 *   .withSigner({ type: 'account', data: { id: agentAddress } })
 *   .allowNativeTransfer('0xDE0B6B3A7640000') // 1 ETH
 *   .allowContractCall(uniswapRouter, ['0x38ed1739'])
 *   .withRateLimit(10, 3600) // 10 tx/hour
 *   .build();
 * ```
 */
export class PermissionRequestBuilder {
  private chainId: ChainIdHex;
  private expiry: number = 0;
  private signer: SignerInfo | null = null;
  private permissions: Permission[] = [];
  private policies: Policy[] = [];

  constructor(chainId: ChainIdHex) {
    this.chainId = chainId;
  }

  /**
   * Set chain ID
   */
  forChain(chainId: ChainIdHex): this {
    this.chainId = chainId;
    return this;
  }

  /**
   * Set expiry as Unix timestamp
   */
  expireAt(timestamp: number): this {
    this.expiry = timestamp;
    return this;
  }

  /**
   * Set expiry as duration from now (in seconds)
   */
  expireIn(seconds: number): this {
    this.expiry = Math.floor(Date.now() / 1000) + seconds;
    return this;
  }

  /**
   * Set the signer
   */
  withSigner(signer: SignerInfo): this {
    this.signer = signer;
    return this;
  }

  /**
   * Add native token transfer permission
   */
  allowNativeTransfer(allowance: HexString, required = true): this {
    this.permissions.push({
      type: 'native-token-transfer',
      data: { allowance },
      required,
    });
    return this;
  }

  /**
   * Add ERC-20 token transfer permission
   */
  allowErc20Transfer(tokenAddress: Address, allowance: HexString, required = true): this {
    this.permissions.push({
      type: 'erc20-token-transfer',
      data: { address: tokenAddress, allowance },
      required,
    });
    return this;
  }

  /**
   * Add contract call permission
   */
  allowContractCall(
    contractAddress: Address,
    selectors: HexString[] = [],
    maxValues: HexString[] = [],
    required = true
  ): this {
    const calls = selectors.map((selector, i) => ({
      selector,
      maxValue: maxValues[i],
    }));

    this.permissions.push({
      type: 'contract-call',
      data: { address: contractAddress, calls },
      required,
    });
    return this;
  }

  /**
   * Add rate limit permission
   */
  allowRateLimit(count: number, interval: number, required = true): this {
    this.permissions.push({
      type: 'rate-limit',
      data: { count, interval },
      required,
    });
    return this;
  }

  /**
   * Add gas limit policy
   */
  withGasLimit(limit: HexString): this {
    this.policies.push({
      type: 'gas-limit',
      data: { limit },
    });
    return this;
  }

  /**
   * Add call limit policy
   */
  withCallLimit(count: number): this {
    this.policies.push({
      type: 'call-limit',
      data: { count },
    });
    return this;
  }

  /**
   * Add rate limit policy
   */
  withRateLimit(count: number, interval: number): this {
    this.policies.push({
      type: 'rate-limit',
      data: { count, interval },
    });
    return this;
  }

  /**
   * Add spending limit policy
   */
  withSpendingLimit(allowance: HexString, period?: number): this {
    this.policies.push({
      type: 'spending-limit',
      data: { allowance, period },
    });
    return this;
  }

  /**
   * Build the permission request
   */
  build(): Omit<PermissionRequest, 'address'> {
    if (!this.signer) {
      throw new Error('Signer is required');
    }

    if (this.expiry === 0) {
      throw new Error('Expiry is required');
    }

    if (this.permissions.length === 0) {
      throw new Error('At least one permission is required');
    }

    return {
      chainId: this.chainId,
      expiry: this.expiry,
      signer: this.signer,
      permissions: this.permissions,
      policies: this.policies.length > 0 ? this.policies : undefined,
    };
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create an ERC-7715 provider
 */
export function createERC7715Provider(config: ERC7715ProviderConfig): ERC7715Provider {
  return new ERC7715Provider(config);
}
