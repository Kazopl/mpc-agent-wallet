/**
 * Solana chain adapter
 */

import type { Balance, TxHash } from '../types';

/**
 * Solana chain configuration
 */
export interface SolanaChainConfig {
  /** Chain name */
  name: string;
  /** RPC URLs (with failover) */
  rpcUrls: string[];
  /** Commitment level */
  commitment: 'processed' | 'confirmed' | 'finalized';
  /** Explorer URL */
  explorerUrl?: string;
}

/**
 * Pre-configured Solana networks
 */
export const SolanaNetworks = {
  MAINNET: {
    name: 'Solana Mainnet',
    rpcUrls: ['https://api.mainnet-beta.solana.com'],
    commitment: 'confirmed' as const,
    explorerUrl: 'https://explorer.solana.com',
  },
  DEVNET: {
    name: 'Solana Devnet',
    rpcUrls: ['https://api.devnet.solana.com'],
    commitment: 'confirmed' as const,
    explorerUrl: 'https://explorer.solana.com?cluster=devnet',
  },
  TESTNET: {
    name: 'Solana Testnet',
    rpcUrls: ['https://api.testnet.solana.com'],
    commitment: 'confirmed' as const,
    explorerUrl: 'https://explorer.solana.com?cluster=testnet',
  },
} as const;

/**
 * Transaction parameters for Solana
 */
export interface SolanaTxParams {
  /** Sender public key (base58) */
  from: string;
  /** Recipient public key (base58) */
  to: string;
  /** Amount in lamports */
  amount: bigint;
  /** Recent blockhash (will be fetched if not provided) */
  recentBlockhash?: string;
  /** Priority fee in microlamports per compute unit */
  priorityFee?: number;
}

/**
 * Unsigned Solana transaction
 */
export interface UnsignedSolanaTx {
  /** Serialized message for signing */
  message: Uint8Array;
  /** Recent blockhash used */
  recentBlockhash: string;
  /** Human-readable summary */
  summary: {
    from: string;
    to: string;
    amount: string;
    estimatedFee: string;
  };
}

/**
 * Solana chain adapter
 *
 * @example
 * ```typescript
 * const adapter = new SolanaAdapter(SolanaNetworks.MAINNET);
 *
 * // Get balance
 * const balance = await adapter.getBalance('...');
 *
 * // Build transaction
 * const unsignedTx = await adapter.buildTransaction({
 *   from: '...',
 *   to: '...',
 *   amount: 1000000000n, // 1 SOL
 * });
 * ```
 */
export class SolanaAdapter {
  private config: SolanaChainConfig;
  private currentRpcIndex = 0;

  constructor(config: SolanaChainConfig) {
    this.config = config;
  }

  /** Get network name */
  get name(): string {
    return this.config.name;
  }

  /** Native currency symbol */
  get symbol(): string {
    return 'SOL';
  }

  /** Native currency decimals */
  get decimals(): number {
    return 9;
  }

  /**
   * Get SOL balance for an address
   */
  async getBalance(address: string): Promise<Balance> {
    const result = await this.rpcCall<{ value: number }>('getBalance', [
      address,
      { commitment: this.config.commitment },
    ]);

    const rawValue = BigInt(result.value);
    const formatted = this.formatLamports(rawValue);

    return {
      raw: rawValue.toString(),
      formatted,
      symbol: 'SOL',
      decimals: 9,
    };
  }

  /**
   * Get recent blockhash
   */
  async getRecentBlockhash(): Promise<string> {
    const result = await this.rpcCall<{
      value: { blockhash: string; lastValidBlockHeight: number };
    }>('getLatestBlockhash', [{ commitment: this.config.commitment }]);

    return result.value.blockhash;
  }

  /**
   * Get priority fee estimate
   */
  async getPriorityFee(): Promise<number> {
    try {
      const result = await this.rpcCall<{
        prioritizationFeeEstimate: { priorityFeeEstimate: number };
      }>('getRecentPrioritizationFees', []);

      return result.prioritizationFeeEstimate?.priorityFeeEstimate ?? 1000;
    } catch {
      return 1000; // Default to 1000 microlamports
    }
  }

  /**
   * Build an unsigned transaction
   */
  async buildTransaction(params: SolanaTxParams): Promise<UnsignedSolanaTx> {
    const recentBlockhash =
      params.recentBlockhash ?? (await this.getRecentBlockhash());

    // Build a simple transfer instruction
    // In production, this would use proper Solana SDK serialization
    const message = this.buildTransferMessage(
      params.from,
      params.to,
      params.amount,
      recentBlockhash
    );

    // Base fee + priority fee
    const baseFee = 5000n; // 5000 lamports
    const priorityFee = BigInt(params.priorityFee ?? 1000) * 200n; // Estimate 200 CU
    const estimatedFee = baseFee + priorityFee;

    return {
      message,
      recentBlockhash,
      summary: {
        from: params.from,
        to: params.to,
        amount: this.formatLamports(params.amount),
        estimatedFee: this.formatLamports(estimatedFee),
      },
    };
  }

  /**
   * Finalize a transaction with signature
   */
  finalizeTransaction(
    unsignedTx: UnsignedSolanaTx,
    signature: Uint8Array
  ): Uint8Array {
    // Combine message with signature
    // Solana transaction format: [signature_count, signatures..., message]
    const signatureCount = 1;
    const tx = new Uint8Array(1 + 64 + unsignedTx.message.length);
    tx[0] = signatureCount;
    tx.set(signature.slice(0, 64), 1);
    tx.set(unsignedTx.message, 65);
    return tx;
  }

  /**
   * Broadcast a signed transaction
   */
  async broadcast(signedTx: Uint8Array): Promise<TxHash> {
    const txBase64 = btoa(String.fromCharCode(...signedTx));

    const result = await this.rpcCall<string>('sendTransaction', [
      txBase64,
      {
        encoding: 'base64',
        preflightCommitment: this.config.commitment,
      },
    ]);

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
    signature: string,
    timeoutMs = 60000
  ): Promise<{ confirmed: boolean; slot?: number }> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeoutMs) {
      try {
        const result = await this.rpcCall<{
          value: { confirmationStatus: string; slot: number } | null;
        }>('getSignatureStatuses', [[signature]]);

        const status = result.value;
        if (status) {
          const confirmationStatus = status.confirmationStatus;
          if (
            confirmationStatus === 'confirmed' ||
            confirmationStatus === 'finalized'
          ) {
            return { confirmed: true, slot: status.slot };
          }
        }
      } catch {
        // Status not available yet
      }

      await sleep(2000);
    }

    return { confirmed: false };
  }

  /**
   * Check if an address is valid (base58)
   */
  isValidAddress(address: string): boolean {
    // Base58 alphabet check
    return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address);
  }

  /**
   * Get explorer URL for a transaction
   */
  getExplorerTxUrl(signature: string): string | undefined {
    if (!this.config.explorerUrl) return undefined;
    return `${this.config.explorerUrl}/tx/${signature}`;
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

  private buildTransferMessage(
    from: string,
    to: string,
    amount: bigint,
    recentBlockhash: string
  ): Uint8Array {
    // Simplified message building
    // In production, use proper Solana SDK
    const message = new TextEncoder().encode(
      JSON.stringify({
        from,
        to,
        amount: amount.toString(),
        recentBlockhash,
        programId: '11111111111111111111111111111111', // System program
      })
    );
    return message;
  }

  private formatLamports(lamports: bigint): string {
    const sol = Number(lamports) / 1e9;
    return `${sol.toFixed(9).replace(/\.?0+$/, '')} SOL`;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
