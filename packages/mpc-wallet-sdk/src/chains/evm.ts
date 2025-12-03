/**
 * EVM chain adapter
 */

import type { Balance, Signature, TxHash, TxReceipt } from '../types';

/**
 * EVM chain configuration
 */
export interface EvmChainConfig {
  /** Chain ID */
  chainId: number;
  /** Chain name */
  name: string;
  /** RPC URLs (with failover) */
  rpcUrls: string[];
  /** Native currency symbol */
  symbol: string;
  /** Native currency decimals */
  decimals: number;
  /** Block explorer URL */
  explorerUrl?: string;
}

/**
 * Pre-configured chain configs
 */
export const EVMChains = {
  ETHEREUM_MAINNET: {
    chainId: 1,
    name: 'Ethereum Mainnet',
    rpcUrls: ['https://eth.llamarpc.com', 'https://rpc.ankr.com/eth'],
    symbol: 'ETH',
    decimals: 18,
    explorerUrl: 'https://etherscan.io',
  },
  ETHEREUM_SEPOLIA: {
    chainId: 11155111,
    name: 'Ethereum Sepolia',
    rpcUrls: ['https://sepolia.drpc.org', 'https://rpc.ankr.com/eth_sepolia'],
    symbol: 'ETH',
    decimals: 18,
    explorerUrl: 'https://sepolia.etherscan.io',
  },
  ARBITRUM_ONE: {
    chainId: 42161,
    name: 'Arbitrum One',
    rpcUrls: ['https://arb1.arbitrum.io/rpc', 'https://rpc.ankr.com/arbitrum'],
    symbol: 'ETH',
    decimals: 18,
    explorerUrl: 'https://arbiscan.io',
  },
  OPTIMISM: {
    chainId: 10,
    name: 'Optimism',
    rpcUrls: ['https://mainnet.optimism.io', 'https://rpc.ankr.com/optimism'],
    symbol: 'ETH',
    decimals: 18,
    explorerUrl: 'https://optimistic.etherscan.io',
  },
  BASE: {
    chainId: 8453,
    name: 'Base',
    rpcUrls: ['https://mainnet.base.org', 'https://base.llamarpc.com'],
    symbol: 'ETH',
    decimals: 18,
    explorerUrl: 'https://basescan.org',
  },
  POLYGON: {
    chainId: 137,
    name: 'Polygon',
    rpcUrls: [
      'https://polygon-rpc.com',
      'https://rpc.ankr.com/polygon',
    ],
    symbol: 'MATIC',
    decimals: 18,
    explorerUrl: 'https://polygonscan.com',
  },
} as const;

/**
 * Transaction parameters for EVM
 */
export interface EvmTxParams {
  /** Sender address */
  from: string;
  /** Recipient address */
  to: string;
  /** Value in wei (as string) */
  value: string;
  /** Transaction data (hex) */
  data?: string;
  /** Gas limit */
  gasLimit?: bigint;
  /** Max fee per gas (EIP-1559) */
  maxFeePerGas?: bigint;
  /** Max priority fee per gas (EIP-1559) */
  maxPriorityFeePerGas?: bigint;
  /** Nonce override */
  nonce?: number;
}

/**
 * Unsigned EVM transaction
 */
export interface UnsignedEvmTx {
  /** Chain ID */
  chainId: number;
  /** Serialized transaction for signing */
  serialized: Uint8Array;
  /** Transaction hash for signing */
  signingHash: Uint8Array;
  /** Human-readable summary */
  summary: {
    from: string;
    to: string;
    value: string;
    estimatedFee: string;
  };
}

/**
 * EVM chain adapter
 *
 * @example
 * ```typescript
 * const adapter = new EvmAdapter(EVMChains.ETHEREUM_MAINNET);
 *
 * // Get balance
 * const balance = await adapter.getBalance('0x...');
 *
 * // Build transaction
 * const unsignedTx = await adapter.buildTransaction({
 *   from: '0x...',
 *   to: '0x...',
 *   value: '1000000000000000000', // 1 ETH
 * });
 *
 * // After MPC signing, broadcast
 * const txHash = await adapter.broadcast(signedTx);
 * ```
 */
export class EvmAdapter {
  private config: EvmChainConfig;
  private currentRpcIndex = 0;

  constructor(config: EvmChainConfig) {
    this.config = config;
  }

  /** Get chain ID */
  get chainId(): number {
    return this.config.chainId;
  }

  /** Get native currency symbol */
  get symbol(): string {
    return this.config.symbol;
  }

  /** Get native currency decimals */
  get decimals(): number {
    return this.config.decimals;
  }

  /**
   * Get balance for an address
   */
  async getBalance(address: string): Promise<Balance> {
    const result = await this.rpcCall<string>('eth_getBalance', [
      address,
      'latest',
    ]);

    const rawValue = BigInt(result);
    const formatted = this.formatValue(rawValue);

    return {
      raw: rawValue.toString(),
      formatted,
      symbol: this.config.symbol,
      decimals: this.config.decimals,
    };
  }

  /**
   * Get nonce for an address
   */
  async getNonce(address: string): Promise<number> {
    const result = await this.rpcCall<string>('eth_getTransactionCount', [
      address,
      'latest',
    ]);
    return parseInt(result, 16);
  }

  /**
   * Get current gas prices (EIP-1559)
   */
  async getGasPrices(): Promise<{
    baseFee: bigint;
    maxFeePerGas: bigint;
    maxPriorityFeePerGas: bigint;
  }> {
    // Get latest block for base fee
    const block = await this.rpcCall<{ baseFeePerGas: string }>(
      'eth_getBlockByNumber',
      ['latest', false]
    );

    const baseFee = BigInt(block.baseFeePerGas || '0');

    // Get priority fee suggestion
    const priorityFee = await this.rpcCall<string>(
      'eth_maxPriorityFeePerGas',
      []
    ).catch(() => '0x3b9aca00'); // Default to 1 gwei

    const maxPriorityFeePerGas = BigInt(priorityFee);
    const maxFeePerGas = baseFee * 2n + maxPriorityFeePerGas;

    return {
      baseFee,
      maxFeePerGas,
      maxPriorityFeePerGas,
    };
  }

  /**
   * Estimate gas for a transaction
   */
  async estimateGas(params: EvmTxParams): Promise<bigint> {
    const result = await this.rpcCall<string>('eth_estimateGas', [
      {
        from: params.from,
        to: params.to,
        value: '0x' + BigInt(params.value).toString(16),
        data: params.data || '0x',
      },
    ]);
    return BigInt(result);
  }

  /**
   * Build an unsigned transaction
   */
  async buildTransaction(params: EvmTxParams): Promise<UnsignedEvmTx> {
    // Get nonce if not provided
    const nonce = params.nonce ?? (await this.getNonce(params.from));

    // Get gas prices
    const gasPrices = await this.getGasPrices();
    const maxFeePerGas = params.maxFeePerGas ?? gasPrices.maxFeePerGas;
    const maxPriorityFeePerGas =
      params.maxPriorityFeePerGas ?? gasPrices.maxPriorityFeePerGas;

    // Estimate gas if not provided
    const gasLimit =
      params.gasLimit ?? ((await this.estimateGas(params)) * 120n) / 100n; // 20% buffer

    // Build EIP-1559 transaction
    const tx = {
      chainId: this.config.chainId,
      nonce,
      maxFeePerGas,
      maxPriorityFeePerGas,
      gasLimit,
      to: params.to,
      value: BigInt(params.value),
      data: params.data ? hexToBytes(params.data) : new Uint8Array(0),
    };

    // Serialize transaction (simplified - in production use RLP encoding)
    const serialized = new TextEncoder().encode(JSON.stringify(tx));

    // Compute signing hash (simplified - in production use proper EIP-1559 hash)
    const signingHash = await sha256(serialized);

    // Estimate fee
    const estimatedFee = gasLimit * maxFeePerGas;

    return {
      chainId: this.config.chainId,
      serialized,
      signingHash,
      summary: {
        from: params.from,
        to: params.to,
        value: this.formatValue(BigInt(params.value)),
        estimatedFee: this.formatValue(estimatedFee),
      },
    };
  }

  /**
   * Finalize a transaction with signature
   */
  finalizeTransaction(
    unsignedTx: UnsignedEvmTx,
    signature: Signature
  ): Uint8Array {
    // Combine transaction with signature
    // In production, this would use proper RLP encoding
    const r = hexToBytes(signature.r);
    const s = hexToBytes(signature.s);

    // EIP-1559: v = yParity (0 or 1)
    const v = signature.recoveryId;

    const signed = new Uint8Array(unsignedTx.serialized.length + 65);
    signed.set(unsignedTx.serialized);
    signed.set(r, unsignedTx.serialized.length);
    signed.set(s, unsignedTx.serialized.length + 32);
    signed[unsignedTx.serialized.length + 64] = v;

    return signed;
  }

  /**
   * Broadcast a signed transaction
   */
  async broadcast(signedTx: Uint8Array): Promise<TxHash> {
    const txHex = '0x' + bytesToHex(signedTx);
    const result = await this.rpcCall<string>('eth_sendRawTransaction', [txHex]);

    return {
      hash: result,
      explorerUrl: this.config.explorerUrl
        ? `${this.config.explorerUrl}/tx/${result}`
        : undefined,
    };
  }

  /**
   * Wait for transaction confirmation
   */
  async waitForConfirmation(
    txHash: string,
    timeoutMs = 60000
  ): Promise<TxReceipt> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeoutMs) {
      try {
        const receipt = await this.rpcCall<{
          blockNumber: string;
          status: string;
          gasUsed: string;
          effectiveGasPrice: string;
        } | null>('eth_getTransactionReceipt', [txHash]);

        if (receipt) {
          return {
            txHash,
            blockNumber: parseInt(receipt.blockNumber, 16),
            status: receipt.status === '0x1' ? 'success' : 'failed',
            gasUsed: BigInt(receipt.gasUsed),
            effectiveGasPrice: BigInt(receipt.effectiveGasPrice),
          };
        }
      } catch {
        // Transaction not found yet
      }

      await sleep(2000);
    }

    throw new Error(`Transaction ${txHash} not confirmed within timeout`);
  }

  /**
   * Derive address from public key
   */
  deriveAddress(publicKey: Uint8Array): string {
    // Keccak256 of uncompressed public key (skip first byte if compressed)
    const pk = publicKey[0] === 0x04 ? publicKey.slice(1) : publicKey;
    // In production, use proper keccak256
    const hash = new Uint8Array(32);
    for (let i = 0; i < pk.length; i++) {
      hash[i % 32] ^= pk[i];
    }
    return '0x' + bytesToHex(hash.slice(12));
  }

  /**
   * Check if an address is valid
   */
  isValidAddress(address: string): boolean {
    return /^0x[0-9a-fA-F]{40}$/.test(address);
  }

  /**
   * Get explorer URL for a transaction
   */
  getExplorerTxUrl(txHash: string): string | undefined {
    if (!this.config.explorerUrl) return undefined;
    return `${this.config.explorerUrl}/tx/${txHash}`;
  }

  /**
   * Get explorer URL for an address
   */
  getExplorerAddressUrl(address: string): string | undefined {
    if (!this.config.explorerUrl) return undefined;
    return `${this.config.explorerUrl}/address/${address}`;
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private async rpcCall<T>(method: string, params: unknown[]): Promise<T> {
    const errors: Error[] = [];

    for (let i = 0; i < this.config.rpcUrls.length; i++) {
      const rpcUrl = this.config.rpcUrls[this.currentRpcIndex];

      try {
        const response = await fetch(rpcUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            method,
            params,
            id: Date.now(),
          }),
        });

        const data = await response.json();

        if (data.error) {
          throw new Error(data.error.message || 'RPC error');
        }

        return data.result;
      } catch (error) {
        errors.push(error as Error);
        this.currentRpcIndex =
          (this.currentRpcIndex + 1) % this.config.rpcUrls.length;
      }
    }

    throw new Error(
      `All RPC endpoints failed: ${errors.map((e) => e.message).join(', ')}`
    );
  }

  private formatValue(value: bigint): string {
    const divisor = 10n ** BigInt(this.config.decimals);
    const whole = value / divisor;
    const fraction = value % divisor;

    if (fraction === 0n) {
      return `${whole} ${this.config.symbol}`;
    }

    const fractionStr = fraction.toString().padStart(this.config.decimals, '0');
    const trimmed = fractionStr.replace(/0+$/, '');
    return `${whole}.${trimmed} ${this.config.symbol}`;
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const hash = await crypto.subtle.digest('SHA-256', data.buffer as ArrayBuffer);
    return new Uint8Array(hash);
  }
  // Fallback simple hash
  const result = new Uint8Array(32);
  for (let i = 0; i < data.length; i++) {
    result[i % 32] ^= data[i];
  }
  return result;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
