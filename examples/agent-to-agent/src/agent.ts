import {
  AgentIdentityAPI,
  AgentRegistrationBuilder,
  TrustModel,
  type AgentRegistrationFile,
  type AgentService,
  type Address,
} from '@mpc-wallet/sdk';

export interface AgentConfig {
  name: string;
  description: string;
  version?: string;
  services?: AgentService[];
  trustModels?: TrustModel[];
  website?: string;
}

export interface SimulatedKeyShare {
  publicKey: string;
  privateKeyFragment: Uint8Array;
}

export class AgentClient {
  private readonly id: string;
  private readonly config: AgentConfig;
  private readonly identityApi: AgentIdentityAPI;
  private agentId: bigint | null = null;
  private registrationFile: AgentRegistrationFile | null = null;
  private walletAddress: Address | null = null;
  private keyShare: SimulatedKeyShare | null = null;

  constructor(id: string, config: AgentConfig) {
    this.id = id;
    this.config = config;
    this.identityApi = new AgentIdentityAPI();
  }

  async initialize(): Promise<void> {
    console.log(`[${this.id}] Initializing agent...`);

    this.keyShare = this.generateSimulatedKeyShare();
    this.walletAddress = this.deriveAddressFromKeyShare(this.keyShare);

    console.log(`[${this.id}] Wallet address: ${this.walletAddress}`);
  }

  async register(): Promise<bigint> {
    if (!this.walletAddress) {
      throw new Error('Agent not initialized. Call initialize() first.');
    }

    console.log(`[${this.id}] Registering agent on-chain...`);

    const builder = new AgentRegistrationBuilder(this.config.name)
      .description(this.config.description)
      .version(this.config.version ?? '1.0.0')
      .trustModel(TrustModel.Reputation);

    if (this.config.services) {
      for (const service of this.config.services) {
        builder.addService(service);
      }
    }

    if (this.config.trustModels) {
      for (const model of this.config.trustModels) {
        builder.trustModel(model);
      }
    }

    if (this.config.website) {
      builder.website(this.config.website);
    }

    const registrationConfig = builder.build();
    this.registrationFile = this.identityApi.generateRegistrationFile(registrationConfig);

    this.agentId = this.generateSimulatedAgentId();

    console.log(`[${this.id}] Registered with agent ID: ${this.agentId}`);
    console.log(`[${this.id}] Registration file created`);

    return this.agentId;
  }

  getAgentId(): bigint {
    if (!this.agentId) {
      throw new Error('Agent not registered. Call register() first.');
    }
    return this.agentId;
  }

  getWalletAddress(): Address {
    if (!this.walletAddress) {
      throw new Error('Agent not initialized. Call initialize() first.');
    }
    return this.walletAddress;
  }

  getRegistrationFile(): AgentRegistrationFile {
    if (!this.registrationFile) {
      throw new Error('Agent not registered. Call register() first.');
    }
    return this.registrationFile;
  }

  getName(): string {
    return this.config.name;
  }

  getId(): string {
    return this.id;
  }

  getServices(): AgentService[] {
    return this.config.services ?? [];
  }

  async sendTo(to: Address, value: bigint): Promise<string> {
    if (!this.walletAddress) {
      throw new Error('Agent not initialized. Call initialize() first.');
    }

    console.log(`[${this.id}] Sending ${this.formatEther(value)} ETH to ${to.slice(0, 10)}...`);

    const txHash = this.generateSimulatedTxHash();

    console.log(`[${this.id}] Transaction hash: ${txHash}`);

    return txHash;
  }

  async evaluatePolicy(_to: Address, value: bigint): Promise<{ approved: boolean; reason?: string }> {
    const maxPerTx = this.parseEther('1');

    if (value > maxPerTx) {
      return {
        approved: false,
        reason: `Transaction value ${this.formatEther(value)} ETH exceeds limit of 1 ETH`,
      };
    }

    return { approved: true };
  }

  private generateSimulatedKeyShare(): SimulatedKeyShare {
    const randomBytes = new Uint8Array(32);
    crypto.getRandomValues(randomBytes);

    const publicKeyBytes = new Uint8Array(33);
    publicKeyBytes[0] = 0x02;
    crypto.getRandomValues(publicKeyBytes.subarray(1));

    return {
      publicKey: '0x' + Array.from(publicKeyBytes).map(b => b.toString(16).padStart(2, '0')).join(''),
      privateKeyFragment: randomBytes,
    };
  }

  private deriveAddressFromKeyShare(keyShare: SimulatedKeyShare): Address {
    const hashBytes = new Uint8Array(20);
    const pubKeyBytes = this.hexToBytes(keyShare.publicKey);
    for (let i = 0; i < pubKeyBytes.length; i++) {
      hashBytes[i % 20] ^= pubKeyBytes[i];
    }

    return ('0x' + Array.from(hashBytes).map(b => b.toString(16).padStart(2, '0')).join('')) as Address;
  }

  private generateSimulatedAgentId(): bigint {
    const bytes = new Uint8Array(8);
    crypto.getRandomValues(bytes);
    let value = 0n;
    for (const byte of bytes) {
      value = (value << 8n) | BigInt(byte);
    }
    return value % 1000000n + 1n;
  }

  private generateSimulatedTxHash(): string {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  private hexToBytes(hex: string): Uint8Array {
    const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  private parseEther(eth: string): bigint {
    return BigInt(Math.floor(parseFloat(eth) * 1e18));
  }

  private formatEther(wei: bigint): string {
    const weiStr = wei.toString();
    if (weiStr.length <= 18) {
      return '0.' + weiStr.padStart(18, '0').replace(/0+$/, '') || '0';
    }
    const intPart = weiStr.slice(0, -18);
    const decPart = weiStr.slice(-18).replace(/0+$/, '');
    return decPart ? `${intPart}.${decPart}` : intPart;
  }
}

export function parseEther(eth: string): bigint {
  return BigInt(Math.floor(parseFloat(eth) * 1e18));
}

export function formatEther(wei: bigint): string {
  const weiStr = wei.toString();
  if (weiStr.length <= 18) {
    const decPart = weiStr.padStart(18, '0').replace(/0+$/, '');
    return decPart ? `0.${decPart}` : '0';
  }
  const intPart = weiStr.slice(0, -18);
  const decPart = weiStr.slice(-18).replace(/0+$/, '');
  return decPart ? `${intPart}.${decPart}` : intPart;
}
