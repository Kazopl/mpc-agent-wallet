/**
 * Reputation API for ERC-8004 Integration
 *
 * Provides feedback signal management and reputation querying for the
 * ERC-8004 Reputation Registry.
 *
 * @example
 * ```typescript
 * const reputationApi = new ReputationAPI();
 *
 * // Submit feedback for an agent
 * const calldata = reputationApi.encodeGiveFeedbackCalldata({
 *   agentId: 1n,
 *   value: 100n,
 *   decimals: 2,
 *   tag1: 'quality',
 *   tag2: 'speed',
 * });
 *
 * // Get reputation summary
 * const summary = await reputationApi.getSummary(agentId);
 * ```
 */

import type { Address, Hash, HexString } from './types';
import { MpcWalletError, ErrorCode, isAddress } from './types';
import { bytesToHex } from './utils';

export const REPUTATION_REGISTRY_ADDRESS: Address =
  '0xB5048e3ef1DA4E04deB6f7d0423D06F63869e322';

export interface FeedbackSignal {
  readonly agentId: bigint;
  readonly reviewer: Address;
  readonly value: bigint;
  readonly decimals: number;
  readonly tag1: string;
  readonly tag2: string;
  readonly proofOfPayment: Hash | null;
  readonly timestamp: bigint;
  readonly feedbackIndex: bigint;
  readonly revoked: boolean;
}

export interface ReputationSummary {
  readonly agentId: bigint;
  readonly feedbackCount: bigint;
  readonly aggregateValue: bigint;
  readonly decimals: number;
  readonly filtersApplied: SummaryFilters;
}

export interface SummaryFilters {
  readonly reviewers: readonly Address[];
  readonly tag1: string | null;
  readonly tag2: string | null;
}

export interface FeedbackParams {
  readonly agentId: bigint;
  readonly value: bigint;
  readonly decimals: number;
  readonly tag1?: string;
  readonly tag2?: string;
  readonly proofOfPayment?: Hash;
}

export interface SummaryQueryParams {
  readonly agentId: bigint;
  readonly reviewers?: readonly Address[];
  readonly tag1?: string;
  readonly tag2?: string;
}

export interface ReputationAPIConfig {
  readonly registryAddress?: Address;
}

const REPUTATION_REGISTRY_ABI = [
  {
    name: 'giveFeedback',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'value', type: 'int128' },
      { name: 'decimals', type: 'uint8' },
      { name: 'tag1', type: 'string' },
      { name: 'tag2', type: 'string' },
      { name: 'proofOfPayment', type: 'bytes32' },
    ],
    outputs: [{ name: 'feedbackIndex', type: 'uint64' }],
  },
  {
    name: 'revokeFeedback',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'feedbackIndex', type: 'uint64' },
    ],
    outputs: [],
  },
  {
    name: 'getSummary',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'clients', type: 'address[]' },
      { name: 'tag1', type: 'string' },
      { name: 'tag2', type: 'string' },
    ],
    outputs: [
      {
        name: 'summary',
        type: 'tuple',
        components: [
          { name: 'feedbackCount', type: 'uint64' },
          { name: 'aggregateValue', type: 'int128' },
          { name: 'decimals', type: 'uint8' },
        ],
      },
    ],
  },
  {
    name: 'getFeedback',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'feedbackIndex', type: 'uint64' },
    ],
    outputs: [
      {
        name: 'feedback',
        type: 'tuple',
        components: [
          { name: 'reviewer', type: 'address' },
          { name: 'value', type: 'int128' },
          { name: 'decimals', type: 'uint8' },
          { name: 'tag1', type: 'string' },
          { name: 'tag2', type: 'string' },
          { name: 'proofOfPayment', type: 'bytes32' },
          { name: 'timestamp', type: 'uint64' },
          { name: 'revoked', type: 'bool' },
        ],
      },
    ],
  },
  {
    name: 'getFeedbackCount',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'agentId', type: 'uint256' }],
    outputs: [{ name: '', type: 'uint64' }],
  },
] as const;

export class ReputationAPI {
  private readonly registryAddress: Address;

  constructor(config: ReputationAPIConfig = {}) {
    this.registryAddress = config.registryAddress ?? REPUTATION_REGISTRY_ADDRESS;
  }

  getRegistryAddress(): Address {
    return this.registryAddress;
  }

  getAbi(): typeof REPUTATION_REGISTRY_ABI {
    return REPUTATION_REGISTRY_ABI;
  }

  encodeGiveFeedbackCalldata(params: FeedbackParams): HexString {
    this.validateFeedbackParams(params);

    const functionSelector = '0x623c4871';
    const agentIdEncoded = this.encodeUint256(params.agentId);
    const valueEncoded = this.encodeInt128(params.value);
    const decimalsEncoded = this.encodeUint256(BigInt(params.decimals));

    const tag1 = params.tag1 ?? '';
    const tag2 = params.tag2 ?? '';
    const tag1Bytes = new TextEncoder().encode(tag1);
    const tag2Bytes = new TextEncoder().encode(tag2);

    const proofOfPayment = params.proofOfPayment ?? ('0x' + '0'.repeat(64)) as Hash;
    const proofEncoded = proofOfPayment.slice(2).padStart(64, '0');

    const tag1Offset = 192n;
    const tag1PaddedLen = Math.ceil(tag1Bytes.length / 32) * 32 || 32;
    const tag2Offset = tag1Offset + 32n + BigInt(tag1PaddedLen);

    const tag1OffsetEncoded = this.encodeUint256(tag1Offset);
    const tag2OffsetEncoded = this.encodeUint256(tag2Offset);

    const tag1LenEncoded = this.encodeUint256(BigInt(tag1Bytes.length));
    const tag1Padded = this.padBytes(tag1Bytes, tag1PaddedLen);

    const tag2LenEncoded = this.encodeUint256(BigInt(tag2Bytes.length));
    const tag2PaddedLen = Math.ceil(tag2Bytes.length / 32) * 32 || 0;
    const tag2Padded = tag2PaddedLen > 0 ? this.padBytes(tag2Bytes, tag2PaddedLen) : '';

    return `${functionSelector}${agentIdEncoded}${valueEncoded}${decimalsEncoded}${tag1OffsetEncoded}${tag2OffsetEncoded}${proofEncoded}${tag1LenEncoded}${tag1Padded}${tag2LenEncoded}${tag2Padded}` as HexString;
  }

  encodeRevokeFeedbackCalldata(agentId: bigint, feedbackIndex: bigint): HexString {
    const functionSelector = '0x87235a4b';
    const agentIdEncoded = this.encodeUint256(agentId);
    const indexEncoded = this.encodeUint256(feedbackIndex);

    return `${functionSelector}${agentIdEncoded}${indexEncoded}` as HexString;
  }

  encodeGetSummaryCalldata(params: SummaryQueryParams): HexString {
    const functionSelector = '0x5b5e139f';
    const agentIdEncoded = this.encodeUint256(params.agentId);

    const reviewers = params.reviewers ?? [];
    const tag1 = params.tag1 ?? '';
    const tag2 = params.tag2 ?? '';

    const tag1Bytes = new TextEncoder().encode(tag1);
    const tag2Bytes = new TextEncoder().encode(tag2);
    const tag1PaddedLen = Math.ceil(tag1Bytes.length / 32) * 32 || 0;
    const tag2PaddedLen = Math.ceil(tag2Bytes.length / 32) * 32 || 0;

    const reviewersOffset = 128n;
    const tag1Offset = reviewersOffset + 32n + BigInt(reviewers.length * 32);
    const tag2Offset = tag1Offset + 32n + BigInt(tag1PaddedLen);

    const reviewersOffsetEncoded = this.encodeUint256(reviewersOffset);
    const tag1OffsetEncoded = this.encodeUint256(tag1Offset);
    const tag2OffsetEncoded = this.encodeUint256(tag2Offset);

    const reviewersLenEncoded = this.encodeUint256(BigInt(reviewers.length));
    let reviewersEncoded = '';
    for (const reviewer of reviewers) {
      if (!isAddress(reviewer)) {
        throw new MpcWalletError(
          ErrorCode.InvalidConfig,
          `Invalid reviewer address: ${reviewer}`
        );
      }
      reviewersEncoded += this.encodeAddress(reviewer);
    }

    const tag1LenEncoded = this.encodeUint256(BigInt(tag1Bytes.length));
    const tag1Padded = tag1PaddedLen > 0 ? this.padBytes(tag1Bytes, tag1PaddedLen) : '';

    const tag2LenEncoded = this.encodeUint256(BigInt(tag2Bytes.length));
    const tag2Padded = tag2PaddedLen > 0 ? this.padBytes(tag2Bytes, tag2PaddedLen) : '';

    return `${functionSelector}${agentIdEncoded}${reviewersOffsetEncoded}${tag1OffsetEncoded}${tag2OffsetEncoded}${reviewersLenEncoded}${reviewersEncoded}${tag1LenEncoded}${tag1Padded}${tag2LenEncoded}${tag2Padded}` as HexString;
  }

  encodeGetFeedbackCalldata(agentId: bigint, feedbackIndex: bigint): HexString {
    const functionSelector = '0x7a8a8152';
    const agentIdEncoded = this.encodeUint256(agentId);
    const indexEncoded = this.encodeUint256(feedbackIndex);

    return `${functionSelector}${agentIdEncoded}${indexEncoded}` as HexString;
  }

  encodeGetFeedbackCountCalldata(agentId: bigint): HexString {
    const functionSelector = '0x9c1a2a50';
    const agentIdEncoded = this.encodeUint256(agentId);

    return `${functionSelector}${agentIdEncoded}` as HexString;
  }

  parseFeedbackFromContractData(data: {
    reviewer: Address;
    value: bigint;
    decimals: number;
    tag1: string;
    tag2: string;
    proofOfPayment: Hash;
    timestamp: bigint;
    revoked: boolean;
  }, agentId: bigint, feedbackIndex: bigint): FeedbackSignal {
    const isZeroProof = data.proofOfPayment === ('0x' + '0'.repeat(64)) as Hash;

    return {
      agentId,
      reviewer: data.reviewer,
      value: data.value,
      decimals: data.decimals,
      tag1: data.tag1,
      tag2: data.tag2,
      proofOfPayment: isZeroProof ? null : data.proofOfPayment,
      timestamp: data.timestamp,
      feedbackIndex,
      revoked: data.revoked,
    };
  }

  parseSummaryFromContractData(data: {
    feedbackCount: bigint;
    aggregateValue: bigint;
    decimals: number;
  }, params: SummaryQueryParams): ReputationSummary {
    return {
      agentId: params.agentId,
      feedbackCount: data.feedbackCount,
      aggregateValue: data.aggregateValue,
      decimals: data.decimals,
      filtersApplied: {
        reviewers: params.reviewers ?? [],
        tag1: params.tag1 ?? null,
        tag2: params.tag2 ?? null,
      },
    };
  }

  calculateReputationScore(summary: ReputationSummary): number {
    if (summary.feedbackCount === 0n) {
      return 0;
    }

    const normalizedAggregate =
      Number(summary.aggregateValue) / Math.pow(10, summary.decimals);
    const count = Number(summary.feedbackCount);

    return normalizedAggregate / count;
  }

  normalizeValue(value: bigint, decimals: number): number {
    return Number(value) / Math.pow(10, decimals);
  }

  isPositiveFeedback(signal: FeedbackSignal): boolean {
    return signal.value > 0n;
  }

  isNegativeFeedback(signal: FeedbackSignal): boolean {
    return signal.value < 0n;
  }

  hasProofOfPayment(signal: FeedbackSignal): boolean {
    return signal.proofOfPayment !== null;
  }

  private validateFeedbackParams(params: FeedbackParams): void {
    if (params.decimals < 0 || params.decimals > 18) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Decimals must be between 0 and 18, got ${params.decimals}`
      );
    }
  }

  private encodeUint256(value: bigint): string {
    return value.toString(16).padStart(64, '0');
  }

  private encodeInt128(value: bigint): string {
    if (value >= 0n) {
      return value.toString(16).padStart(64, '0');
    }
    const twosComplement = (1n << 128n) + value;
    return twosComplement.toString(16).padStart(64, '0');
  }

  private encodeAddress(address: Address): string {
    return address.slice(2).toLowerCase().padStart(64, '0');
  }

  private padBytes(bytes: Uint8Array, targetLength: number): string {
    const padded = new Uint8Array(targetLength);
    padded.set(bytes);
    return bytesToHex(padded);
  }
}

export class FeedbackBuilder {
  private params: FeedbackParams;

  constructor(agentId: bigint) {
    this.params = {
      agentId,
      value: 0n,
      decimals: 2,
    };
  }

  positive(value: bigint, decimals: number): this {
    this.params = {
      ...this.params,
      value,
      decimals,
    };
    return this;
  }

  negative(value: bigint, decimals: number): this {
    this.params = {
      ...this.params,
      value: -value,
      decimals,
    };
    return this;
  }

  tag1(tag: string): this {
    this.params = { ...this.params, tag1: tag };
    return this;
  }

  tag2(tag: string): this {
    this.params = { ...this.params, tag2: tag };
    return this;
  }

  tags(tag1: string, tag2: string): this {
    this.params = { ...this.params, tag1, tag2 };
    return this;
  }

  proofOfPayment(proof: Hash): this {
    this.params = { ...this.params, proofOfPayment: proof };
    return this;
  }

  proofOfPaymentFromHex(hex: string): this {
    const cleanHex = hex.startsWith('0x') ? hex : `0x${hex}`;
    if (cleanHex.length !== 66) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Invalid proof of payment length: expected 66 chars (0x + 64), got ${cleanHex.length}`
      );
    }
    return this.proofOfPayment(cleanHex as Hash);
  }

  build(): FeedbackParams {
    return { ...this.params };
  }
}

export class SummaryQueryBuilder {
  private params: SummaryQueryParams;

  constructor(agentId: bigint) {
    this.params = { agentId };
  }

  reviewer(address: Address): this {
    const reviewers = this.params.reviewers ? [...this.params.reviewers] : [];
    if (!isAddress(address)) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Invalid reviewer address: ${address}`
      );
    }
    reviewers.push(address);
    this.params = { ...this.params, reviewers };
    return this;
  }

  reviewers(addresses: readonly Address[]): this {
    for (const address of addresses) {
      if (!isAddress(address)) {
        throw new MpcWalletError(
          ErrorCode.InvalidConfig,
          `Invalid reviewer address: ${address}`
        );
      }
    }
    this.params = { ...this.params, reviewers: addresses };
    return this;
  }

  tag1(tag: string): this {
    this.params = { ...this.params, tag1: tag };
    return this;
  }

  tag2(tag: string): this {
    this.params = { ...this.params, tag2: tag };
    return this;
  }

  build(): SummaryQueryParams {
    return { ...this.params };
  }
}

export function calculateWeightedReputationScore(
  positiveCount: bigint,
  negativeCount: bigint,
  aggregateValue: bigint,
  decimals: number
): number {
  const total = positiveCount + negativeCount;
  if (total === 0n) {
    return 0;
  }

  const normalized = Number(aggregateValue) / Math.pow(10, decimals);
  const ratio = Number(positiveCount) / Number(total);

  return normalized * ratio;
}
