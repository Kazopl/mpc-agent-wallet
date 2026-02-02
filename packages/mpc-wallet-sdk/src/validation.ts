/**
 * Validation API for ERC-8004 Integration
 *
 * Provides validation request management and attestation status querying
 * for the ERC-8004 Validation Registry.
 *
 * @example
 * ```typescript
 * const validationApi = new ValidationAPI();
 *
 * // Request TEE validation
 * const calldata = validationApi.encodeValidationRequestCalldata({
 *   validator: '0x...',
 *   agentId: 1n,
 *   requestURI: 'ipfs://Qm...',
 *   contentHash: '0x...',
 * });
 *
 * // Check validation status
 * const status = await validationApi.getValidationStatus(requestHash);
 * ```
 */

import type { Address, Hash, HexString } from './types';
import { MpcWalletError, ErrorCode, isAddress } from './types';
import { bytesToHex, hexToBytes } from './utils';
import { TrustModel } from './agent-identity';

export const VALIDATION_REGISTRY_ADDRESS: Address =
  '0x662b40A526cb4017d947e71eAF6753BF3eeE66d8';

export enum ValidationResponse {
  Pending = 0,
  Approved = 1,
  Rejected = 2,
  Expired = 3,
}

export interface ValidationRequest {
  readonly requester: Address;
  readonly validator: Address;
  readonly agentId: bigint;
  readonly requestURI: string;
  readonly contentHash: Hash;
  readonly timestamp: bigint;
  readonly expiresAt: bigint;
  readonly response: ValidationResponse;
  readonly responseData: HexString;
  readonly trustModel: TrustModel;
}

export interface ValidationRequestParams {
  readonly validator: Address;
  readonly agentId: bigint;
  readonly requestURI: string;
  readonly contentHash: Hash;
}

export interface ValidationResponseParams {
  readonly requestHash: Hash;
  readonly response: ValidationResponse;
  readonly responseData: HexString;
}

export interface TeeAttestationData {
  readonly quote: HexString;
  readonly reportData: HexString;
  readonly mrEnclave: Hash;
  readonly mrSigner: Hash;
  readonly timestamp: bigint;
}

export interface ZkProofData {
  readonly proof: HexString;
  readonly publicInputs: readonly HexString[];
  readonly verifierAddress: Address;
}

export interface ValidationAPIConfig {
  readonly registryAddress?: Address;
}

export interface ValidationStatus {
  readonly requestHash: Hash;
  readonly isPending: boolean;
  readonly isApproved: boolean;
  readonly isRejected: boolean;
  readonly isExpired: boolean;
  readonly response: ValidationResponse;
  readonly responseData: HexString | null;
}

const VALIDATION_REGISTRY_ABI = [
  {
    name: 'validationRequest',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'validator', type: 'address' },
      { name: 'agentId', type: 'uint256' },
      { name: 'requestURI', type: 'string' },
      { name: 'contentHash', type: 'bytes32' },
    ],
    outputs: [{ name: 'requestHash', type: 'bytes32' }],
  },
  {
    name: 'validationResponse',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'requestHash', type: 'bytes32' },
      { name: 'response', type: 'uint8' },
      { name: 'responseData', type: 'bytes' },
    ],
    outputs: [],
  },
  {
    name: 'getValidationStatus',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'requestHash', type: 'bytes32' }],
    outputs: [
      {
        name: 'request',
        type: 'tuple',
        components: [
          { name: 'requester', type: 'address' },
          { name: 'validator', type: 'address' },
          { name: 'agentId', type: 'uint256' },
          { name: 'requestURI', type: 'string' },
          { name: 'contentHash', type: 'bytes32' },
          { name: 'timestamp', type: 'uint64' },
          { name: 'expiresAt', type: 'uint64' },
          { name: 'response', type: 'uint8' },
          { name: 'responseData', type: 'bytes' },
          { name: 'trustModel', type: 'uint8' },
        ],
      },
    ],
  },
  {
    name: 'getAgentValidations',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'agentId', type: 'uint256' }],
    outputs: [{ name: 'requestHashes', type: 'bytes32[]' }],
  },
  {
    name: 'getValidatorRequests',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'validator', type: 'address' }],
    outputs: [{ name: 'requestHashes', type: 'bytes32[]' }],
  },
  {
    name: 'isExpired',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'requestHash', type: 'bytes32' }],
    outputs: [{ name: '', type: 'bool' }],
  },
] as const;

export class ValidationAPI {
  private readonly registryAddress: Address;

  constructor(config: ValidationAPIConfig = {}) {
    this.registryAddress = config.registryAddress ?? VALIDATION_REGISTRY_ADDRESS;
  }

  getRegistryAddress(): Address {
    return this.registryAddress;
  }

  getAbi(): typeof VALIDATION_REGISTRY_ABI {
    return VALIDATION_REGISTRY_ABI;
  }

  encodeValidationRequestCalldata(params: ValidationRequestParams): HexString {
    this.validateRequestParams(params);

    const functionSelector = '0x8f7dcfa3';
    const validatorEncoded = this.encodeAddress(params.validator);
    const agentIdEncoded = this.encodeUint256(params.agentId);
    const contentHashEncoded = params.contentHash.slice(2).padStart(64, '0');

    const uriBytes = new TextEncoder().encode(params.requestURI);
    const uriOffset = 128n;
    const uriOffsetEncoded = this.encodeUint256(uriOffset);
    const uriLenEncoded = this.encodeUint256(BigInt(uriBytes.length));
    const uriPaddedLen = Math.ceil(uriBytes.length / 32) * 32 || 32;
    const uriPadded = this.padBytes(uriBytes, uriPaddedLen);

    return `${functionSelector}${validatorEncoded}${agentIdEncoded}${uriOffsetEncoded}${contentHashEncoded}${uriLenEncoded}${uriPadded}` as HexString;
  }

  encodeValidationResponseCalldata(params: ValidationResponseParams): HexString {
    if (
      params.response !== ValidationResponse.Approved &&
      params.response !== ValidationResponse.Rejected
    ) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Response must be Approved or Rejected'
      );
    }

    const functionSelector = '0xa4c0ed36';
    const requestHashEncoded = params.requestHash.slice(2).padStart(64, '0');
    const responseEncoded = this.encodeUint256(BigInt(params.response));

    const responseDataBytes = hexToBytes(params.responseData);
    const dataOffset = 96n;
    const dataOffsetEncoded = this.encodeUint256(dataOffset);
    const dataLenEncoded = this.encodeUint256(BigInt(responseDataBytes.length));
    const dataPaddedLen = Math.ceil(responseDataBytes.length / 32) * 32 || 0;
    const dataPadded =
      dataPaddedLen > 0 ? this.padBytes(responseDataBytes, dataPaddedLen) : '';

    return `${functionSelector}${requestHashEncoded}${responseEncoded}${dataOffsetEncoded}${dataLenEncoded}${dataPadded}` as HexString;
  }

  encodeGetValidationStatusCalldata(requestHash: Hash): HexString {
    const functionSelector = '0xe7f43c68';
    const hashEncoded = requestHash.slice(2).padStart(64, '0');

    return `${functionSelector}${hashEncoded}` as HexString;
  }

  encodeGetAgentValidationsCalldata(agentId: bigint): HexString {
    const functionSelector = '0x3c6568ce';
    const agentIdEncoded = this.encodeUint256(agentId);

    return `${functionSelector}${agentIdEncoded}` as HexString;
  }

  encodeGetValidatorRequestsCalldata(validator: Address): HexString {
    if (!isAddress(validator)) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Invalid validator address: ${validator}`
      );
    }

    const functionSelector = '0x8da5cb5b';
    const validatorEncoded = this.encodeAddress(validator);

    return `${functionSelector}${validatorEncoded}` as HexString;
  }

  encodeIsExpiredCalldata(requestHash: Hash): HexString {
    const functionSelector = '0xd9548e53';
    const hashEncoded = requestHash.slice(2).padStart(64, '0');

    return `${functionSelector}${hashEncoded}` as HexString;
  }

  parseValidationRequestFromContractData(data: {
    requester: Address;
    validator: Address;
    agentId: bigint;
    requestURI: string;
    contentHash: Hash;
    timestamp: bigint;
    expiresAt: bigint;
    response: number;
    responseData: HexString;
    trustModel: number;
  }): ValidationRequest {
    return {
      requester: data.requester,
      validator: data.validator,
      agentId: data.agentId,
      requestURI: data.requestURI,
      contentHash: data.contentHash,
      timestamp: data.timestamp,
      expiresAt: data.expiresAt,
      response: data.response as ValidationResponse,
      responseData: data.responseData,
      trustModel: data.trustModel as TrustModel,
    };
  }

  getValidationStatus(request: ValidationRequest): ValidationStatus {
    const now = BigInt(Math.floor(Date.now() / 1000));
    const isExpired = request.expiresAt > 0n && now > request.expiresAt;

    return {
      requestHash: request.contentHash,
      isPending: request.response === ValidationResponse.Pending && !isExpired,
      isApproved: request.response === ValidationResponse.Approved,
      isRejected: request.response === ValidationResponse.Rejected,
      isExpired: isExpired || request.response === ValidationResponse.Expired,
      response: isExpired ? ValidationResponse.Expired : request.response,
      responseData:
        request.responseData === '0x' ? null : request.responseData,
    };
  }

  encodeTeeAttestationData(attestation: TeeAttestationData): HexString {
    const quoteBytes = hexToBytes(attestation.quote);
    const reportDataBytes = hexToBytes(attestation.reportData);
    const mrEnclaveBytes = hexToBytes(attestation.mrEnclave);
    const mrSignerBytes = hexToBytes(attestation.mrSigner);

    const timestampEncoded = this.encodeUint256(attestation.timestamp);
    const mrEnclaveEncoded = bytesToHex(mrEnclaveBytes).padStart(64, '0');
    const mrSignerEncoded = bytesToHex(mrSignerBytes).padStart(64, '0');

    const quoteOffset = 160n;
    const reportDataOffset = quoteOffset + 32n + BigInt(Math.ceil(quoteBytes.length / 32) * 32);

    const quoteOffsetEncoded = this.encodeUint256(quoteOffset);
    const reportDataOffsetEncoded = this.encodeUint256(reportDataOffset);

    const quoteLenEncoded = this.encodeUint256(BigInt(quoteBytes.length));
    const quotePaddedLen = Math.ceil(quoteBytes.length / 32) * 32 || 32;
    const quotePadded = this.padBytes(quoteBytes, quotePaddedLen);

    const reportDataLenEncoded = this.encodeUint256(BigInt(reportDataBytes.length));
    const reportDataPaddedLen = Math.ceil(reportDataBytes.length / 32) * 32 || 32;
    const reportDataPadded = this.padBytes(reportDataBytes, reportDataPaddedLen);

    return `0x${timestampEncoded}${mrEnclaveEncoded}${mrSignerEncoded}${quoteOffsetEncoded}${reportDataOffsetEncoded}${quoteLenEncoded}${quotePadded}${reportDataLenEncoded}${reportDataPadded}` as HexString;
  }

  encodeZkProofData(proof: ZkProofData): HexString {
    if (!isAddress(proof.verifierAddress)) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Invalid verifier address: ${proof.verifierAddress}`
      );
    }

    const proofBytes = hexToBytes(proof.proof);
    const verifierEncoded = this.encodeAddress(proof.verifierAddress);

    const proofOffset = 96n;
    const inputsOffset = proofOffset + 32n + BigInt(Math.ceil(proofBytes.length / 32) * 32);

    const proofOffsetEncoded = this.encodeUint256(proofOffset);
    const inputsOffsetEncoded = this.encodeUint256(inputsOffset);

    const proofLenEncoded = this.encodeUint256(BigInt(proofBytes.length));
    const proofPaddedLen = Math.ceil(proofBytes.length / 32) * 32 || 32;
    const proofPadded = this.padBytes(proofBytes, proofPaddedLen);

    const inputsLenEncoded = this.encodeUint256(BigInt(proof.publicInputs.length));
    let inputsEncoded = '';
    for (const input of proof.publicInputs) {
      inputsEncoded += input.slice(2).padStart(64, '0');
    }

    return `0x${verifierEncoded}${proofOffsetEncoded}${inputsOffsetEncoded}${proofLenEncoded}${proofPadded}${inputsLenEncoded}${inputsEncoded}` as HexString;
  }

  createTeeValidationRequest(
    validator: Address,
    agentId: bigint,
    attestation: TeeAttestationData
  ): ValidationRequestParams {
    const responseData = this.encodeTeeAttestationData(attestation);
    const contentHash = this.hashData(responseData);

    return {
      validator,
      agentId,
      requestURI: `tee://attestation/${attestation.mrEnclave.slice(2, 18)}`,
      contentHash,
    };
  }

  createZkValidationRequest(
    validator: Address,
    agentId: bigint,
    proof: ZkProofData
  ): ValidationRequestParams {
    const responseData = this.encodeZkProofData(proof);
    const contentHash = this.hashData(responseData);

    return {
      validator,
      agentId,
      requestURI: `zkml://proof/${proof.verifierAddress.slice(2, 10)}`,
      contentHash,
    };
  }

  private validateRequestParams(params: ValidationRequestParams): void {
    if (!isAddress(params.validator)) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Invalid validator address: ${params.validator}`
      );
    }

    if (!params.requestURI || params.requestURI.trim().length === 0) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Request URI cannot be empty'
      );
    }
  }

  private encodeUint256(value: bigint): string {
    return value.toString(16).padStart(64, '0');
  }

  private encodeAddress(address: Address): string {
    return address.slice(2).toLowerCase().padStart(64, '0');
  }

  private padBytes(bytes: Uint8Array, targetLength: number): string {
    const padded = new Uint8Array(targetLength);
    padded.set(bytes);
    return bytesToHex(padded);
  }

  private hashData(data: HexString): Hash {
    const bytes = hexToBytes(data);
    const result = new Uint8Array(32);
    for (let i = 0; i < bytes.length; i++) {
      result[i % 32] ^= bytes[i];
    }
    return `0x${bytesToHex(result)}` as Hash;
  }
}

export class ValidationRequestBuilder {
  private validator: Address | null = null;
  private agentId: bigint = 0n;
  private requestURI: string = '';
  private contentHash: Hash | null = null;

  forAgent(agentId: bigint): this {
    this.agentId = agentId;
    return this;
  }

  withValidator(validator: Address): this {
    if (!isAddress(validator)) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Invalid validator address: ${validator}`
      );
    }
    this.validator = validator;
    return this;
  }

  withRequestURI(uri: string): this {
    this.requestURI = uri;
    return this;
  }

  withContentHash(hash: Hash): this {
    this.contentHash = hash;
    return this;
  }

  withContentFromString(content: string): this {
    const bytes = new TextEncoder().encode(content);
    const result = new Uint8Array(32);
    for (let i = 0; i < bytes.length; i++) {
      result[i % 32] ^= bytes[i];
    }
    this.contentHash = `0x${bytesToHex(result)}` as Hash;
    return this;
  }

  build(): ValidationRequestParams {
    if (!this.validator) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Validator address is required'
      );
    }

    if (this.agentId === 0n) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Agent ID is required'
      );
    }

    if (!this.requestURI) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Request URI is required'
      );
    }

    if (!this.contentHash) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Content hash is required'
      );
    }

    return {
      validator: this.validator,
      agentId: this.agentId,
      requestURI: this.requestURI,
      contentHash: this.contentHash,
    };
  }
}

export function validationResponseToString(response: ValidationResponse): string {
  switch (response) {
    case ValidationResponse.Pending:
      return 'pending';
    case ValidationResponse.Approved:
      return 'approved';
    case ValidationResponse.Rejected:
      return 'rejected';
    case ValidationResponse.Expired:
      return 'expired';
    default:
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Invalid validation response: ${response}`
      );
  }
}

export function validationResponseFromString(value: string): ValidationResponse {
  switch (value.toLowerCase()) {
    case 'pending':
      return ValidationResponse.Pending;
    case 'approved':
      return ValidationResponse.Approved;
    case 'rejected':
      return ValidationResponse.Rejected;
    case 'expired':
      return ValidationResponse.Expired;
    default:
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Invalid validation response string: ${value}`
      );
  }
}
