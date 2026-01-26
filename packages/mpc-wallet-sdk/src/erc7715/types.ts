/**
 * ERC-7715 type definitions for wallet execution permissions
 *
 * ERC-7715 defines a standard JSON-RPC interface for dapps and AI agents
 * to request fine-grained permissions from wallets to execute transactions
 * on the user's behalf.
 */

import type { Address, HexString } from '../types';

// ============================================================================
// Branded Types
// ============================================================================

declare const __erc7715Brand: unique symbol;
type Brand<T, B> = T & { [__erc7715Brand]: B };

export type ChainIdHex = Brand<`0x${string}`, 'ChainIdHex'>;
export type PermissionId = Brand<HexString, 'PermissionId'>;
export type PermissionsContext = Brand<HexString, 'PermissionsContext'>;

// ============================================================================
// Signer Types
// ============================================================================

export type SignerType = 'account' | 'key' | 'keys';

export interface AccountSignerData {
  readonly id: Address;
}

export interface KeySignerData {
  readonly publicKey: HexString;
}

export interface KeysSignerData {
  readonly publicKeys: readonly HexString[];
}

export interface AccountSigner {
  readonly type: 'account';
  readonly data: AccountSignerData;
}

export interface KeySigner {
  readonly type: 'key';
  readonly data: KeySignerData;
}

export interface KeysSigner {
  readonly type: 'keys';
  readonly data: KeysSignerData;
}

export type SignerInfo = AccountSigner | KeySigner | KeysSigner;

// ============================================================================
// Permission Types
// ============================================================================

export type PermissionType =
  | 'native-token-transfer'
  | 'erc20-token-transfer'
  | 'contract-call'
  | 'rate-limit';

export interface NativeTokenTransferData {
  readonly allowance: HexString;
}

export interface Erc20TokenTransferData {
  readonly address: Address;
  readonly allowance: HexString;
}

export interface ContractCallData {
  readonly address: Address;
  readonly calls: readonly ContractCallPermission[];
}

export interface ContractCallPermission {
  readonly selector?: HexString;
  readonly maxValue?: HexString;
}

export interface RateLimitData {
  readonly count: number;
  readonly interval: number;
}

export interface NativeTokenTransferPermission {
  readonly type: 'native-token-transfer';
  readonly data: NativeTokenTransferData;
  readonly required: boolean;
}

export interface Erc20TokenTransferPermission {
  readonly type: 'erc20-token-transfer';
  readonly data: Erc20TokenTransferData;
  readonly required: boolean;
}

export interface ContractCallPermissionEntry {
  readonly type: 'contract-call';
  readonly data: ContractCallData;
  readonly required: boolean;
}

export interface RateLimitPermission {
  readonly type: 'rate-limit';
  readonly data: RateLimitData;
  readonly required: boolean;
}

export type Permission =
  | NativeTokenTransferPermission
  | Erc20TokenTransferPermission
  | ContractCallPermissionEntry
  | RateLimitPermission;

// ============================================================================
// Policy Types
// ============================================================================

export type PolicyType =
  | 'gas-limit'
  | 'call-limit'
  | 'rate-limit'
  | 'spending-limit';

export interface GasLimitPolicyData {
  readonly limit: HexString;
}

export interface CallLimitPolicyData {
  readonly count: number;
}

export interface RateLimitPolicyData {
  readonly count: number;
  readonly interval: number;
}

export interface SpendingLimitPolicyData {
  readonly allowance: HexString;
  readonly period?: number;
}

export interface GasLimitPolicy {
  readonly type: 'gas-limit';
  readonly data: GasLimitPolicyData;
}

export interface CallLimitPolicy {
  readonly type: 'call-limit';
  readonly data: CallLimitPolicyData;
}

export interface RateLimitPolicy {
  readonly type: 'rate-limit';
  readonly data: RateLimitPolicyData;
}

export interface SpendingLimitPolicy {
  readonly type: 'spending-limit';
  readonly data: SpendingLimitPolicyData;
}

export type Policy =
  | GasLimitPolicy
  | CallLimitPolicy
  | RateLimitPolicy
  | SpendingLimitPolicy;

// ============================================================================
// Permission Request / Response
// ============================================================================

export interface PermissionRequest {
  readonly chainId: ChainIdHex;
  readonly address?: Address;
  readonly expiry: number;
  readonly signer: SignerInfo;
  readonly permissions: readonly Permission[];
  readonly policies?: readonly Policy[];
}

export type GrantedPermissionStatus = 'active' | 'expired' | 'revoked';

export interface GrantedPermission {
  readonly type: PermissionType;
  readonly data: Permission['data'];
  readonly required: boolean;
  readonly policies: readonly Policy[];
}

export interface PermissionResponse {
  readonly permissionId: PermissionId;
  readonly expiry: number;
  readonly signer: SignerInfo;
  readonly permissions: readonly GrantedPermission[];
  readonly permissionsContext: PermissionsContext;
  readonly grantedAt: number;
  readonly chainId: ChainIdHex;
  readonly accountAddress: Address;
}

export interface PermissionRevocationRequest {
  readonly permissionId: PermissionId;
  readonly chainId: ChainIdHex;
}

export interface PermissionRevocationResponse {
  readonly success: boolean;
  readonly permissionId: PermissionId;
  readonly revokedAt: number;
}

// ============================================================================
// Supported Permissions Query
// ============================================================================

export interface SupportedPermission {
  readonly type: PermissionType;
  readonly supportedPolicies: readonly PolicyType[];
  readonly supportsRequired: boolean;
}

export interface SupportedPermissionsResponse {
  readonly chainId: ChainIdHex;
  readonly permissions: readonly SupportedPermission[];
}

// ============================================================================
// Granted Permissions Query
// ============================================================================

export interface GrantedPermissionsQuery {
  readonly chainId: ChainIdHex;
  readonly address?: Address;
}

export interface GrantedPermissionInfo {
  readonly permissionId: PermissionId;
  readonly expiry: number;
  readonly signer: SignerInfo;
  readonly permissions: readonly GrantedPermission[];
  readonly status: GrantedPermissionStatus;
  readonly grantedAt: number;
  readonly revokedAt?: number;
}

export interface GrantedPermissionsResponse {
  readonly chainId: ChainIdHex;
  readonly accountAddress: Address;
  readonly permissions: readonly GrantedPermissionInfo[];
}

// ============================================================================
// Action Types (for execution)
// ============================================================================

export interface Action {
  readonly to: Address;
  readonly value: HexString;
  readonly data: HexString;
}

export interface ExecutionRequest {
  readonly permissionsContext: PermissionsContext;
  readonly chainId: ChainIdHex;
  readonly actions: readonly Action[];
}

export interface ExecutionResponse {
  readonly transactionHash: HexString;
  readonly success: boolean;
}

// ============================================================================
// JSON-RPC Types
// ============================================================================

export type ERC7715Method =
  | 'wallet_requestExecutionPermissions'
  | 'wallet_revokeExecutionPermission'
  | 'wallet_getSupportedExecutionPermissions'
  | 'wallet_getGrantedExecutionPermissions';

export interface ERC7715RpcRequest<T = unknown> {
  readonly method: ERC7715Method;
  readonly params: T;
}

export type RequestExecutionPermissionsParams = readonly [PermissionRequest];
export type RevokeExecutionPermissionParams = readonly [PermissionRevocationRequest];
export type GetSupportedExecutionPermissionsParams = readonly [{ chainId: ChainIdHex }];
export type GetGrantedExecutionPermissionsParams = readonly [GrantedPermissionsQuery];

// ============================================================================
// Error Types
// ============================================================================

export enum ERC7715ErrorCode {
  InvalidRequest = 4100,
  UnsupportedPermission = 4101,
  PermissionDenied = 4102,
  PermissionExpired = 4103,
  PermissionRevoked = 4104,
  InvalidSigner = 4105,
  ChainNotSupported = 4106,
  InsufficientPermission = 4107,
  RateLimitExceeded = 4108,
  SpendingLimitExceeded = 4109,
}

export interface ERC7715Error {
  readonly code: ERC7715ErrorCode;
  readonly message: string;
  readonly data?: unknown;
}

// ============================================================================
// Type Guards
// ============================================================================

export function isAccountSigner(signer: SignerInfo): signer is AccountSigner {
  return signer.type === 'account';
}

export function isKeySigner(signer: SignerInfo): signer is KeySigner {
  return signer.type === 'key';
}

export function isKeysSigner(signer: SignerInfo): signer is KeysSigner {
  return signer.type === 'keys';
}

export function isNativeTokenTransferPermission(
  permission: Permission
): permission is NativeTokenTransferPermission {
  return permission.type === 'native-token-transfer';
}

export function isErc20TokenTransferPermission(
  permission: Permission
): permission is Erc20TokenTransferPermission {
  return permission.type === 'erc20-token-transfer';
}

export function isContractCallPermission(
  permission: Permission
): permission is ContractCallPermissionEntry {
  return permission.type === 'contract-call';
}

export function isRateLimitPermission(
  permission: Permission
): permission is RateLimitPermission {
  return permission.type === 'rate-limit';
}

export function isValidChainIdHex(value: string): value is ChainIdHex {
  return /^0x[0-9a-fA-F]+$/.test(value);
}

export function isValidPermissionId(value: string): value is PermissionId {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

// ============================================================================
// Factory Functions
// ============================================================================

export function createAccountSigner(id: Address): AccountSigner {
  return {
    type: 'account',
    data: { id },
  };
}

export function createKeySigner(publicKey: HexString): KeySigner {
  return {
    type: 'key',
    data: { publicKey },
  };
}

export function createKeysSigner(publicKeys: readonly HexString[]): KeysSigner {
  return {
    type: 'keys',
    data: { publicKeys },
  };
}

export function createNativeTokenTransferPermission(
  allowance: HexString,
  required = true
): NativeTokenTransferPermission {
  return {
    type: 'native-token-transfer',
    data: { allowance },
    required,
  };
}

export function createErc20TokenTransferPermission(
  tokenAddress: Address,
  allowance: HexString,
  required = true
): Erc20TokenTransferPermission {
  return {
    type: 'erc20-token-transfer',
    data: { address: tokenAddress, allowance },
    required,
  };
}

export function createContractCallPermission(
  contractAddress: Address,
  calls: readonly ContractCallPermission[],
  required = true
): ContractCallPermissionEntry {
  return {
    type: 'contract-call',
    data: { address: contractAddress, calls },
    required,
  };
}

export function createRateLimitPermission(
  count: number,
  interval: number,
  required = true
): RateLimitPermission {
  return {
    type: 'rate-limit',
    data: { count, interval },
    required,
  };
}

export function createGasLimitPolicy(limit: HexString): GasLimitPolicy {
  return {
    type: 'gas-limit',
    data: { limit },
  };
}

export function createCallLimitPolicy(count: number): CallLimitPolicy {
  return {
    type: 'call-limit',
    data: { count },
  };
}

export function createRateLimitPolicy(count: number, interval: number): RateLimitPolicy {
  return {
    type: 'rate-limit',
    data: { count, interval },
  };
}

export function createSpendingLimitPolicy(
  allowance: HexString,
  period?: number
): SpendingLimitPolicy {
  return {
    type: 'spending-limit',
    data: { allowance, period },
  };
}
