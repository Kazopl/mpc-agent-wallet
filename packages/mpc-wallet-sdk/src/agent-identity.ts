/**
 * Agent Identity API for ERC-8004 Integration
 *
 * Provides agent registration, identity management, and registration file generation
 * for the ERC-8004 Identity Registry.
 *
 * @example
 * ```typescript
 * const identityApi = new AgentIdentityAPI({ publicClient });
 *
 * // Generate and upload registration file
 * const file = identityApi.generateRegistrationFile({
 *   name: 'my-agent',
 *   description: 'A helpful AI assistant',
 *   services: [{ name: 'chat', endpoint: 'https://api.example.com/chat' }],
 * });
 *
 * // Register agent on-chain
 * const agentId = await identityApi.registerAgent({ agentURI: 'ipfs://Qm...' });
 * ```
 */

import type { Address, Hash, HexString } from './types';
import { MpcWalletError, ErrorCode, isAddress } from './types';
import { bytesToHex, hexToBytes } from './utils';

export const IDENTITY_REGISTRY_ADDRESS: Address =
  '0x7177a6867296406881E20d6647232314736Dd09A';

export enum TrustModel {
  Reputation = 0,
  CryptoEconomic = 1,
  TeeAttestation = 2,
  ZkMl = 3,
}

export interface AgentService {
  name: string;
  endpoint: string;
  description?: string;
  methods?: readonly string[];
  rateLimit?: {
    requestsPerMinute: number;
  };
}

export interface AgentCapability {
  name: string;
  version: string;
  parameters?: Record<string, unknown>;
}

export interface AgentRegistrationFile {
  readonly '@context': readonly string[];
  readonly '@type': string;
  readonly name: string;
  readonly description: string;
  readonly version: string;
  readonly services: readonly AgentService[];
  readonly capabilities: readonly AgentCapability[];
  readonly trustModels: readonly TrustModel[];
  readonly metadata: Record<string, unknown>;
  readonly iconUrl?: string;
  readonly website?: string;
  readonly termsOfService?: string;
  readonly privacyPolicy?: string;
  readonly createdAt: number;
  readonly updatedAt: number;
}

export interface AgentRegistrationConfig {
  name: string;
  description: string;
  version?: string;
  services?: AgentService[];
  capabilities?: AgentCapability[];
  trustModels?: TrustModel[];
  metadata?: Record<string, unknown>;
  iconUrl?: string;
  website?: string;
  termsOfService?: string;
  privacyPolicy?: string;
}

export interface AgentIdentity {
  readonly agentId: bigint;
  readonly owner: Address;
  readonly agentURI: string;
  readonly walletAddress: Address | null;
  readonly metadata: Map<string, Uint8Array>;
  readonly createdAt: number;
  readonly updatedAt: number;
}

export interface AgentIdentityAPIConfig {
  readonly registryAddress?: Address;
  readonly ipfsGateway?: string;
}

export interface RegisterAgentParams {
  readonly agentURI: string;
}

export interface SetAgentWalletParams {
  readonly agentId: bigint;
  readonly wallet: Address;
  readonly deadline: bigint;
  readonly signature: HexString;
}

export interface UploadResult {
  readonly uri: string;
  readonly contentHash: Hash;
}

export type IpfsUploader = (content: string) => Promise<string>;

const IDENTITY_REGISTRY_ABI = [
  {
    name: 'register',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'agentURI', type: 'string' }],
    outputs: [{ name: 'agentId', type: 'uint256' }],
  },
  {
    name: 'setAgentURI',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'newURI', type: 'string' },
    ],
    outputs: [],
  },
  {
    name: 'setAgentWallet',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'wallet', type: 'address' },
      { name: 'deadline', type: 'uint256' },
      { name: 'signature', type: 'bytes' },
    ],
    outputs: [],
  },
  {
    name: 'getAgentWallet',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'agentId', type: 'uint256' }],
    outputs: [{ name: '', type: 'address' }],
  },
  {
    name: 'getMetadata',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'key', type: 'string' },
    ],
    outputs: [{ name: '', type: 'bytes' }],
  },
  {
    name: 'setMetadata',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'key', type: 'string' },
      { name: 'value', type: 'bytes' },
    ],
    outputs: [],
  },
  {
    name: 'agentURI',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'agentId', type: 'uint256' }],
    outputs: [{ name: '', type: 'string' }],
  },
  {
    name: 'ownerOf',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'agentId', type: 'uint256' }],
    outputs: [{ name: '', type: 'address' }],
  },
] as const;

export class AgentIdentityAPI {
  private readonly registryAddress: Address;
  private readonly ipfsGateway: string;
  private ipfsUploader: IpfsUploader | null = null;

  constructor(config: AgentIdentityAPIConfig = {}) {
    this.registryAddress = config.registryAddress ?? IDENTITY_REGISTRY_ADDRESS;
    this.ipfsGateway = config.ipfsGateway ?? 'https://ipfs.io/ipfs/';
  }

  setIpfsUploader(uploader: IpfsUploader): void {
    this.ipfsUploader = uploader;
  }

  getRegistryAddress(): Address {
    return this.registryAddress;
  }

  getAbi(): typeof IDENTITY_REGISTRY_ABI {
    return IDENTITY_REGISTRY_ABI;
  }

  generateRegistrationFile(config: AgentRegistrationConfig): AgentRegistrationFile {
    if (!config.name || config.name.trim().length === 0) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Agent name cannot be empty'
      );
    }

    if (!config.description || config.description.trim().length === 0) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Agent description cannot be empty'
      );
    }

    const now = Math.floor(Date.now() / 1000);

    return {
      '@context': ['https://schema.org', 'https://erc8004.org/v1'],
      '@type': 'AIAgent',
      name: config.name,
      description: config.description,
      version: config.version ?? '1.0.0',
      services: config.services ?? [],
      capabilities: config.capabilities ?? [],
      trustModels: config.trustModels ?? [TrustModel.Reputation],
      metadata: config.metadata ?? {},
      iconUrl: config.iconUrl,
      website: config.website,
      termsOfService: config.termsOfService,
      privacyPolicy: config.privacyPolicy,
      createdAt: now,
      updatedAt: now,
    };
  }

  async uploadRegistrationFile(file: AgentRegistrationFile): Promise<UploadResult> {
    if (!this.ipfsUploader) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'IPFS uploader not configured. Call setIpfsUploader() first.'
      );
    }

    const content = JSON.stringify(file, null, 2);
    const contentHash = await this.hashContent(content);
    const uri = await this.ipfsUploader(content);

    return {
      uri,
      contentHash: `0x${bytesToHex(contentHash)}` as Hash,
    };
  }

  registrationFileToJson(file: AgentRegistrationFile): string {
    return JSON.stringify(file, null, 2);
  }

  parseRegistrationFile(json: string): AgentRegistrationFile {
    try {
      const parsed = JSON.parse(json) as AgentRegistrationFile;

      if (!parsed.name || !parsed.description) {
        throw new MpcWalletError(
          ErrorCode.InvalidConfig,
          'Invalid registration file: missing required fields'
        );
      }

      return parsed;
    } catch (error) {
      if (error instanceof MpcWalletError) throw error;
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Failed to parse registration file: ${(error as Error).message}`
      );
    }
  }

  async resolveAgentURI(agentURI: string): Promise<AgentRegistrationFile> {
    const url = this.resolveIpfsUrl(agentURI);

    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new MpcWalletError(
          ErrorCode.NetworkError,
          `Failed to fetch registration file: ${response.status}`
        );
      }

      const json = await response.text();
      return this.parseRegistrationFile(json);
    } catch (error) {
      if (error instanceof MpcWalletError) throw error;
      throw new MpcWalletError(
        ErrorCode.NetworkError,
        `Failed to resolve agent URI: ${(error as Error).message}`
      );
    }
  }

  encodeRegisterCalldata(agentURI: string): HexString {
    if (!agentURI || agentURI.trim().length === 0) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Agent URI cannot be empty'
      );
    }

    const functionSelector = '0x1aab388b';
    const uriBytes = new TextEncoder().encode(agentURI);

    const offset = this.encodeUint256(32n);
    const length = this.encodeUint256(BigInt(uriBytes.length));
    const paddedUri = this.padBytes(uriBytes);

    return `${functionSelector}${offset}${length}${paddedUri}` as HexString;
  }

  encodeSetAgentURICalldata(agentId: bigint, newURI: string): HexString {
    if (!newURI || newURI.trim().length === 0) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'New URI cannot be empty'
      );
    }

    const functionSelector = '0x820677c7';
    const agentIdEncoded = this.encodeUint256(agentId);
    const uriBytes = new TextEncoder().encode(newURI);

    const offset = this.encodeUint256(64n);
    const length = this.encodeUint256(BigInt(uriBytes.length));
    const paddedUri = this.padBytes(uriBytes);

    return `${functionSelector}${agentIdEncoded}${offset}${length}${paddedUri}` as HexString;
  }

  encodeSetAgentWalletCalldata(params: SetAgentWalletParams): HexString {
    if (!isAddress(params.wallet)) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Invalid wallet address: ${params.wallet}`
      );
    }

    const functionSelector = '0x5a1c724e';
    const agentIdEncoded = this.encodeUint256(params.agentId);
    const walletEncoded = this.encodeAddress(params.wallet);
    const deadlineEncoded = this.encodeUint256(params.deadline);

    const sigBytes = hexToBytes(params.signature);
    const sigOffset = this.encodeUint256(128n);
    const sigLength = this.encodeUint256(BigInt(sigBytes.length));
    const paddedSig = this.padBytes(sigBytes);

    return `${functionSelector}${agentIdEncoded}${walletEncoded}${deadlineEncoded}${sigOffset}${sigLength}${paddedSig}` as HexString;
  }

  createIdentityFromContractData(data: {
    agentId: bigint;
    owner: Address;
    agentURI: string;
    walletAddress: Address;
  }): AgentIdentity {
    const isZeroAddress =
      data.walletAddress === '0x0000000000000000000000000000000000000000';

    return {
      agentId: data.agentId,
      owner: data.owner,
      agentURI: data.agentURI,
      walletAddress: isZeroAddress ? null : data.walletAddress,
      metadata: new Map(),
      createdAt: Math.floor(Date.now() / 1000),
      updatedAt: Math.floor(Date.now() / 1000),
    };
  }

  isWalletLinked(identity: AgentIdentity): boolean {
    return identity.walletAddress !== null;
  }

  private resolveIpfsUrl(uri: string): string {
    if (uri.startsWith('ipfs://')) {
      const cid = uri.slice(7);
      return `${this.ipfsGateway}${cid}`;
    }
    if (uri.startsWith('ar://')) {
      return `https://arweave.net/${uri.slice(5)}`;
    }
    return uri;
  }

  private async hashContent(content: string): Promise<Uint8Array> {
    const data = new TextEncoder().encode(content);
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      const hash = await crypto.subtle.digest('SHA-256', data);
      return new Uint8Array(hash);
    }
    const result = new Uint8Array(32);
    for (let i = 0; i < data.length; i++) {
      result[i % 32] ^= data[i];
    }
    return result;
  }

  private encodeUint256(value: bigint): string {
    return value.toString(16).padStart(64, '0');
  }

  private encodeAddress(address: Address): string {
    return address.slice(2).toLowerCase().padStart(64, '0');
  }

  private padBytes(bytes: Uint8Array): string {
    const paddedLength = Math.ceil(bytes.length / 32) * 32;
    const padded = new Uint8Array(paddedLength);
    padded.set(bytes);
    return bytesToHex(padded);
  }
}

export class AgentRegistrationBuilder {
  private config: AgentRegistrationConfig;

  constructor(name: string) {
    this.config = {
      name,
      description: '',
    };
  }

  description(description: string): this {
    this.config.description = description;
    return this;
  }

  version(version: string): this {
    this.config.version = version;
    return this;
  }

  addService(service: AgentService): this {
    this.config.services = this.config.services ?? [];
    this.config.services.push(service);
    return this;
  }

  addCapability(capability: AgentCapability): this {
    this.config.capabilities = this.config.capabilities ?? [];
    this.config.capabilities.push(capability);
    return this;
  }

  trustModel(model: TrustModel): this {
    this.config.trustModels = this.config.trustModels ?? [];
    if (!this.config.trustModels.includes(model)) {
      this.config.trustModels.push(model);
    }
    return this;
  }

  metadata(key: string, value: unknown): this {
    this.config.metadata = this.config.metadata ?? {};
    this.config.metadata[key] = value;
    return this;
  }

  icon(url: string): this {
    this.config.iconUrl = url;
    return this;
  }

  website(url: string): this {
    this.config.website = url;
    return this;
  }

  termsOfService(url: string): this {
    this.config.termsOfService = url;
    return this;
  }

  privacyPolicy(url: string): this {
    this.config.privacyPolicy = url;
    return this;
  }

  build(): AgentRegistrationConfig {
    if (!this.config.name || this.config.name.trim().length === 0) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Agent name is required'
      );
    }
    if (!this.config.description || this.config.description.trim().length === 0) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Agent description is required'
      );
    }
    return { ...this.config };
  }
}

export function trustModelToString(model: TrustModel): string {
  switch (model) {
    case TrustModel.Reputation:
      return 'reputation';
    case TrustModel.CryptoEconomic:
      return 'crypto_economic';
    case TrustModel.TeeAttestation:
      return 'tee_attestation';
    case TrustModel.ZkMl:
      return 'zkml';
    default:
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Invalid trust model: ${model}`
      );
  }
}

export function trustModelFromString(value: string): TrustModel {
  switch (value.toLowerCase()) {
    case 'reputation':
      return TrustModel.Reputation;
    case 'crypto_economic':
    case 'cryptoeconomic':
      return TrustModel.CryptoEconomic;
    case 'tee_attestation':
    case 'teeattestation':
    case 'tee':
      return TrustModel.TeeAttestation;
    case 'zkml':
    case 'zk_ml':
      return TrustModel.ZkMl;
    default:
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Invalid trust model string: ${value}`
      );
  }
}
