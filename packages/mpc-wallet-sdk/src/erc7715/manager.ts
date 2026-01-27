/**
 * ERC-7715 Permission Manager
 *
 * Bridges ERC-7715 permissions with the existing SessionKeyManager and PolicyEngine.
 * Handles permission lifecycle including granting, revoking, and querying permissions.
 */

import type { Address } from '../types';
import { PolicyConfig } from '../policy';
import type { SessionKeyConfig, SessionKey } from '../session';
import { SessionKeyManager } from '../session';
import { bytesToHex, randomBytes } from '../utils';
import type {
  ChainIdHex,
  GrantedPermission,
  GrantedPermissionInfo,
  GrantedPermissionStatus,
  GrantedPermissionsQuery,
  GrantedPermissionsResponse,
  Permission,
  PermissionId,
  PermissionRequest,
  PermissionResponse,
  PermissionRevocationResponse,
  PermissionsContext,
  PermissionType,
  Policy,
  PolicyType,
  SignerInfo,
  SupportedPermission,
  SupportedPermissionsResponse,
} from './types';
import {
  isContractCallPermission,
  isErc20TokenTransferPermission,
  isNativeTokenTransferPermission,
} from './types';

// ============================================================================
// Internal Types
// ============================================================================

/**
 * Internal permission storage structure
 */
interface StoredPermission {
  permissionId: PermissionId;
  chainId: ChainIdHex;
  accountAddress: Address;
  expiry: number;
  signer: SignerInfo;
  permissions: readonly GrantedPermission[];
  permissionsContext: PermissionsContext;
  grantedAt: number;
  revokedAt?: number;
  status: GrantedPermissionStatus;
  /** Associated session key signer address */
  sessionKeySigner?: Address;
}

/**
 * Permission manager configuration
 */
export interface PermissionManagerConfig {
  /** Supported chain IDs */
  supportedChains: readonly ChainIdHex[];
  /** Session key manager instance */
  sessionKeyManager?: SessionKeyManager;
  /** Maximum permission duration in seconds (default: 30 days) */
  maxPermissionDuration?: number;
  /** Default supported permission types */
  supportedPermissionTypes?: readonly PermissionType[];
}

// ============================================================================
// Default Configuration
// ============================================================================

const DEFAULT_SUPPORTED_CHAINS: ChainIdHex[] = [
  '0x1' as ChainIdHex,   // Ethereum Mainnet
  '0x89' as ChainIdHex,  // Polygon
  '0xa' as ChainIdHex,   // Optimism
  '0xa4b1' as ChainIdHex, // Arbitrum One
  '0x2105' as ChainIdHex, // Base
];

const DEFAULT_SUPPORTED_PERMISSION_TYPES: PermissionType[] = [
  'native-token-transfer',
  'erc20-token-transfer',
  'contract-call',
  'rate-limit',
];

const DEFAULT_SUPPORTED_POLICY_TYPES: PolicyType[] = [
  'gas-limit',
  'call-limit',
  'rate-limit',
  'spending-limit',
];

const DEFAULT_MAX_PERMISSION_DURATION = 30 * 24 * 60 * 60; // 30 days

// ============================================================================
// Permission Manager
// ============================================================================

/**
 * Permission Manager for ERC-7715 permissions
 *
 * Manages the lifecycle of permissions including:
 * - Granting new permissions
 * - Revoking existing permissions
 * - Querying supported and granted permissions
 * - Mapping permissions to session keys
 *
 * @example
 * ```typescript
 * const manager = new PermissionManager({
 *   supportedChains: ['0x1', '0x89'],
 *   sessionKeyManager: wallet.getSessionKeyManager(),
 * });
 *
 * // Grant a permission
 * const response = await manager.grantPermission({
 *   chainId: '0x1',
 *   address: accountAddress,
 *   expiry: Math.floor(Date.now() / 1000) + 86400,
 *   signer: { type: 'account', data: { id: agentAddress } },
 *   permissions: [{ type: 'native-token-transfer', data: { allowance: '0xDE0B6B3A7640000' }, required: true }],
 * });
 * ```
 */
export class PermissionManager {
  private readonly permissions: Map<string, StoredPermission> = new Map();
  private readonly sessionKeyManager: SessionKeyManager;
  private readonly supportedChains: Set<string>;
  private readonly supportedPermissionTypes: Set<PermissionType>;
  private readonly maxPermissionDuration: number;

  constructor(config: PermissionManagerConfig = { supportedChains: DEFAULT_SUPPORTED_CHAINS }) {
    this.sessionKeyManager = config.sessionKeyManager ?? new SessionKeyManager();
    this.supportedChains = new Set(config.supportedChains ?? DEFAULT_SUPPORTED_CHAINS);
    this.supportedPermissionTypes = new Set(
      config.supportedPermissionTypes ?? DEFAULT_SUPPORTED_PERMISSION_TYPES
    );
    this.maxPermissionDuration = config.maxPermissionDuration ?? DEFAULT_MAX_PERMISSION_DURATION;
  }

  // ============================================================================
  // Chain Support
  // ============================================================================

  /**
   * Check if a chain is supported
   */
  isChainSupported(chainId: ChainIdHex): boolean {
    return this.supportedChains.has(chainId);
  }

  /**
   * Add support for a chain
   */
  addChainSupport(chainId: ChainIdHex): void {
    this.supportedChains.add(chainId);
  }

  /**
   * Remove support for a chain
   */
  removeChainSupport(chainId: ChainIdHex): void {
    this.supportedChains.delete(chainId);
  }

  /**
   * Get all supported chains
   */
  getSupportedChains(): ChainIdHex[] {
    return Array.from(this.supportedChains) as ChainIdHex[];
  }

  // ============================================================================
  // Supported Permissions Query
  // ============================================================================

  /**
   * Get supported permissions for a chain
   */
  getSupportedPermissions(chainId: ChainIdHex): SupportedPermissionsResponse {
    const permissions: SupportedPermission[] = Array.from(this.supportedPermissionTypes).map(
      (type) => ({
        type,
        supportedPolicies: this.getSupportedPoliciesForPermission(type),
        supportsRequired: true,
      })
    );

    return {
      chainId,
      permissions,
    };
  }

  /**
   * Get supported policies for a permission type
   */
  private getSupportedPoliciesForPermission(permissionType: PermissionType): readonly PolicyType[] {
    switch (permissionType) {
      case 'native-token-transfer':
        return ['spending-limit', 'rate-limit', 'gas-limit'];
      case 'erc20-token-transfer':
        return ['spending-limit', 'rate-limit', 'gas-limit'];
      case 'contract-call':
        return ['call-limit', 'rate-limit', 'gas-limit'];
      case 'rate-limit':
        return ['gas-limit'];
      default:
        return DEFAULT_SUPPORTED_POLICY_TYPES;
    }
  }

  // ============================================================================
  // Grant Permission
  // ============================================================================

  /**
   * Grant a new permission
   */
  async grantPermission(request: PermissionRequest & { address: Address }): Promise<PermissionResponse> {
    // Validate duration
    const now = Math.floor(Date.now() / 1000);
    const duration = request.expiry - now;
    if (duration > this.maxPermissionDuration) {
      throw new Error(
        `Permission duration (${duration}s) exceeds maximum allowed (${this.maxPermissionDuration}s)`
      );
    }

    // Generate permission ID
    const permissionId = this.generatePermissionId();

    // Create session key from permission request
    const sessionKeyConfig = this.permissionToSessionKeyConfig(request);
    const sessionKey = await this.sessionKeyManager.createSessionKey(sessionKeyConfig);

    // Generate permissions context
    const permissionsContext = this.generatePermissionsContext(
      permissionId,
      sessionKey,
      request
    );

    // Map permissions to granted format
    const grantedPermissions = this.mapToGrantedPermissions(request.permissions, request.policies);

    // Store the permission
    const storedPermission: StoredPermission = {
      permissionId,
      chainId: request.chainId,
      accountAddress: request.address,
      expiry: request.expiry,
      signer: request.signer,
      permissions: grantedPermissions,
      permissionsContext,
      grantedAt: now,
      status: 'active',
      sessionKeySigner: sessionKey.signer,
    };

    this.permissions.set(permissionId, storedPermission);

    return {
      permissionId,
      expiry: request.expiry,
      signer: request.signer,
      permissions: grantedPermissions,
      permissionsContext,
      grantedAt: now,
      chainId: request.chainId,
      accountAddress: request.address,
    };
  }

  /**
   * Convert ERC-7715 permission request to SessionKeyConfig
   */
  private permissionToSessionKeyConfig(request: PermissionRequest): SessionKeyConfig {
    const now = Math.floor(Date.now() / 1000);
    const duration = request.expiry - now;

    // Extract whitelist addresses from contract-call permissions
    const whitelist: string[] = [];
    const selectors: string[] = [];
    let spendingLimit: bigint | undefined;

    for (const permission of request.permissions) {
      if (isNativeTokenTransferPermission(permission)) {
        spendingLimit = BigInt(permission.data.allowance);
      } else if (isErc20TokenTransferPermission(permission)) {
        whitelist.push(permission.data.address);
      } else if (isContractCallPermission(permission)) {
        whitelist.push(permission.data.address);
        for (const call of permission.data.calls) {
          if (call.selector) {
            selectors.push(call.selector);
          }
        }
      }
    }

    // Apply policies to spending limit
    if (request.policies) {
      for (const policy of request.policies) {
        if (policy.type === 'spending-limit') {
          const policyLimit = BigInt(policy.data.allowance);
          if (spendingLimit === undefined || policyLimit < spendingLimit) {
            spendingLimit = policyLimit;
          }
        }
      }
    }

    return {
      validFor: duration,
      spendingLimit,
      whitelist: whitelist.length > 0 ? whitelist : undefined,
      selectors: selectors.length > 0 ? selectors : undefined,
    };
  }

  /**
   * Map permission request to granted permissions
   */
  private mapToGrantedPermissions(
    permissions: readonly Permission[],
    policies?: readonly Policy[]
  ): readonly GrantedPermission[] {
    return permissions.map((permission) => ({
      type: permission.type,
      data: permission.data,
      required: permission.required,
      policies: policies ?? [],
    }));
  }

  /**
   * Generate a unique permission ID
   */
  private generatePermissionId(): PermissionId {
    const randomData = randomBytes(32);
    return ('0x' + bytesToHex(randomData)) as PermissionId;
  }

  /**
   * Generate permissions context for redemption
   *
   * The permissions context encodes all information needed to validate
   * and execute actions using the granted permission.
   */
  private generatePermissionsContext(
    permissionId: PermissionId,
    sessionKey: SessionKey,
    request: PermissionRequest
  ): PermissionsContext {
    // Encode permission context as: [version (1 byte)][permissionId (32 bytes)][sessionKeySigner (20 bytes)][expiry (8 bytes)][chainId (8 bytes)]
    const version = new Uint8Array([0x01]);
    const permIdBytes = hexToBytes(permissionId);
    const signerBytes = hexToBytes(sessionKey.signer);
    const expiryBytes = bigintToBytes(BigInt(request.expiry), 8);
    const chainIdBytes = bigintToBytes(BigInt(request.chainId), 8);

    // Combine all parts
    const contextData = new Uint8Array(
      version.length + permIdBytes.length + signerBytes.length + expiryBytes.length + chainIdBytes.length
    );
    let offset = 0;
    contextData.set(version, offset);
    offset += version.length;
    contextData.set(permIdBytes, offset);
    offset += permIdBytes.length;
    contextData.set(signerBytes, offset);
    offset += signerBytes.length;
    contextData.set(expiryBytes, offset);
    offset += expiryBytes.length;
    contextData.set(chainIdBytes, offset);

    return ('0x' + bytesToHex(contextData)) as PermissionsContext;
  }

  // ============================================================================
  // Revoke Permission
  // ============================================================================

  /**
   * Revoke an existing permission
   */
  async revokePermission(permissionId: PermissionId): Promise<PermissionRevocationResponse> {
    const permission = this.permissions.get(permissionId);
    if (!permission) {
      throw new Error(`Permission not found: ${permissionId}`);
    }

    const now = Math.floor(Date.now() / 1000);

    // Revoke the associated session key
    if (permission.sessionKeySigner) {
      this.sessionKeyManager.revokeSessionKey(permission.sessionKeySigner);
    }

    // Update permission status
    permission.status = 'revoked';
    permission.revokedAt = now;

    return {
      success: true,
      permissionId,
      revokedAt: now,
    };
  }

  // ============================================================================
  // Query Permissions
  // ============================================================================

  /**
   * Get a permission by ID
   */
  getPermission(permissionId: PermissionId): PermissionResponse | null {
    const stored = this.permissions.get(permissionId);
    if (!stored) {
      return null;
    }

    return {
      permissionId: stored.permissionId,
      expiry: stored.expiry,
      signer: stored.signer,
      permissions: stored.permissions,
      permissionsContext: stored.permissionsContext,
      grantedAt: stored.grantedAt,
      chainId: stored.chainId,
      accountAddress: stored.accountAddress,
    };
  }

  /**
   * Get permission info including status
   */
  getPermissionInfo(permissionId: PermissionId): GrantedPermissionInfo | null {
    const stored = this.permissions.get(permissionId);
    if (!stored) {
      return null;
    }

    // Update status if expired
    const now = Math.floor(Date.now() / 1000);
    if (stored.status === 'active' && stored.expiry <= now) {
      stored.status = 'expired';
    }

    return {
      permissionId: stored.permissionId,
      expiry: stored.expiry,
      signer: stored.signer,
      permissions: stored.permissions,
      status: stored.status,
      grantedAt: stored.grantedAt,
      revokedAt: stored.revokedAt,
    };
  }

  /**
   * Get all granted permissions for an account
   */
  getGrantedPermissions(query: GrantedPermissionsQuery): GrantedPermissionsResponse {
    const now = Math.floor(Date.now() / 1000);
    const permissions: GrantedPermissionInfo[] = [];

    for (const stored of this.permissions.values()) {
      // Filter by chain ID
      if (stored.chainId !== query.chainId) {
        continue;
      }

      // Filter by address if specified
      if (query.address && stored.accountAddress.toLowerCase() !== query.address.toLowerCase()) {
        continue;
      }

      // Update status if expired
      if (stored.status === 'active' && stored.expiry <= now) {
        stored.status = 'expired';
      }

      permissions.push({
        permissionId: stored.permissionId,
        expiry: stored.expiry,
        signer: stored.signer,
        permissions: stored.permissions,
        status: stored.status,
        grantedAt: stored.grantedAt,
        revokedAt: stored.revokedAt,
      });
    }

    return {
      chainId: query.chainId,
      accountAddress: query.address ?? ('0x0000000000000000000000000000000000000000' as Address),
      permissions,
    };
  }

  /**
   * Get active permissions for an account
   */
  getActivePermissions(chainId: ChainIdHex, address: Address): GrantedPermissionInfo[] {
    const response = this.getGrantedPermissions({ chainId, address });
    return response.permissions.filter((p) => p.status === 'active');
  }

  // ============================================================================
  // Permission Context Operations
  // ============================================================================

  /**
   * Validate a permissions context
   */
  validatePermissionsContext(context: PermissionsContext): {
    valid: boolean;
    permissionId?: PermissionId;
    error?: string;
  } {
    try {
      const contextBytes = hexToBytes(context);

      // Check minimum length
      if (contextBytes.length < 69) {
        return { valid: false, error: 'Context too short' };
      }

      // Extract version
      const version = contextBytes[0];
      if (version !== 0x01) {
        return { valid: false, error: `Unsupported context version: ${version}` };
      }

      // Extract permission ID
      const permIdBytes = contextBytes.slice(1, 33);
      const permissionId = ('0x' + bytesToHex(permIdBytes)) as PermissionId;

      // Check if permission exists
      const permission = this.permissions.get(permissionId);
      if (!permission) {
        return { valid: false, permissionId, error: 'Permission not found' };
      }

      // Check status
      if (permission.status === 'revoked') {
        return { valid: false, permissionId, error: 'Permission has been revoked' };
      }

      // Check expiry
      const now = Math.floor(Date.now() / 1000);
      if (permission.expiry <= now) {
        permission.status = 'expired';
        return { valid: false, permissionId, error: 'Permission has expired' };
      }

      return { valid: true, permissionId };
    } catch (error) {
      return { valid: false, error: `Invalid context format: ${error}` };
    }
  }

  /**
   * Get the session key associated with a permission
   */
  getSessionKeyForPermission(permissionId: PermissionId): SessionKey | null {
    const stored = this.permissions.get(permissionId);
    if (!stored?.sessionKeySigner) {
      return null;
    }
    return this.sessionKeyManager.getSessionKey(stored.sessionKeySigner);
  }

  /**
   * Get the session key manager
   */
  getSessionKeyManager(): SessionKeyManager {
    return this.sessionKeyManager;
  }

  // ============================================================================
  // Policy Configuration
  // ============================================================================

  /**
   * Create a PolicyConfig from ERC-7715 policies
   */
  static createPolicyFromPermissions(
    permissions: readonly Permission[],
    policies?: readonly Policy[]
  ): PolicyConfig {
    const config = PolicyConfig.create();

    // Extract whitelist from permissions
    const whitelist: string[] = [];
    for (const permission of permissions) {
      if (isErc20TokenTransferPermission(permission)) {
        whitelist.push(permission.data.address);
      } else if (isContractCallPermission(permission)) {
        whitelist.push(permission.data.address);
      }
    }

    if (whitelist.length > 0) {
      config.withWhitelist(whitelist);
    }

    // Apply policies
    if (policies) {
      for (const policy of policies) {
        switch (policy.type) {
          case 'spending-limit':
            config.withPerTxLimit(BigInt(policy.data.allowance));
            break;
          case 'rate-limit':
            // Rate limit is handled at the session key level
            break;
          case 'gas-limit':
            // Gas limit is enforced during transaction execution
            break;
          case 'call-limit':
            // Call limit is handled at the session key level
            break;
        }
      }
    }

    return config;
  }

  // ============================================================================
  // Cleanup
  // ============================================================================

  /**
   * Remove expired and revoked permissions
   */
  cleanup(): number {
    const now = Math.floor(Date.now() / 1000);
    let removed = 0;

    for (const [id, permission] of this.permissions.entries()) {
      if (permission.status === 'revoked' || permission.expiry <= now) {
        this.permissions.delete(id);
        removed++;
      }
    }

    return removed;
  }

  /**
   * Clear all permissions
   */
  clear(): void {
    this.permissions.clear();
    this.sessionKeyManager.clear();
  }

  /**
   * Get statistics about stored permissions
   */
  getStats(): {
    total: number;
    active: number;
    expired: number;
    revoked: number;
  } {
    const now = Math.floor(Date.now() / 1000);
    let active = 0;
    let expired = 0;
    let revoked = 0;

    for (const permission of this.permissions.values()) {
      if (permission.status === 'revoked') {
        revoked++;
      } else if (permission.expiry <= now) {
        expired++;
      } else {
        active++;
      }
    }

    return {
      total: this.permissions.size,
      active,
      expired,
      revoked,
    };
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Convert hex string to bytes
 */
function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert bigint to fixed-length bytes
 */
function bigintToBytes(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}
