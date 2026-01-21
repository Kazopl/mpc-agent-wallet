/**
 * Paymaster integration for gasless transactions
 *
 * Enables AI agent wallets to execute transactions without paying gas directly,
 * with gas costs sponsored by a configured paymaster.
 *
 * @example
 * ```typescript
 * // Create a paymaster client
 * const paymaster = new PaymasterClient({
 *   paymasterAddress: '0x...',
 *   entryPointAddress: '0x...',
 *   rpcUrl: 'https://...',
 * });
 *
 * // Check if account is sponsored
 * const isSponsored = await paymaster.isSponsored(accountAddress);
 *
 * // Get remaining sponsorship
 * const { totalRemaining, dailyRemaining } = await paymaster.getRemainingSponsorship(accountAddress);
 *
 * // Add paymaster data to UserOperation
 * const userOp = await paymaster.sponsorUserOperation(unsignedUserOp);
 * ```
 */

import type { Address, HexString } from './types';
import { MpcWalletError, ErrorCode, isAddress } from './types';
import { bytesToHex, hexToBytes } from './utils';

/**
 * Paymaster client configuration
 */
export interface PaymasterConfig {
  /** Paymaster contract address */
  paymasterAddress: Address;
  /** EntryPoint contract address */
  entryPointAddress: Address;
  /** RPC URL for blockchain calls */
  rpcUrl: string;
  /** Chain ID */
  chainId?: number;
}

/**
 * Sponsorship configuration for an account
 */
export interface SponsorshipConfig {
  /** Whether sponsorship is active */
  active: boolean;
  /** Maximum total sponsorship limit (0 = unlimited) */
  limit: bigint;
  /** Total amount already spent */
  spent: bigint;
  /** Maximum daily sponsorship limit (0 = unlimited) */
  dailyLimit: bigint;
  /** Amount spent today */
  dailySpent: bigint;
  /** Timestamp when daily counter resets */
  dailyResetTime: number;
}

/**
 * Remaining sponsorship amounts
 */
export interface RemainingSponsorship {
  /** Total remaining sponsorship (max uint256 if unlimited) */
  totalRemaining: bigint;
  /** Daily remaining sponsorship (max uint256 if unlimited) */
  dailyRemaining: bigint;
}

/**
 * Global daily stats for paymaster
 */
export interface GlobalDailyStats {
  /** Global daily limit */
  limit: bigint;
  /** Amount spent today globally */
  spent: bigint;
  /** Remaining global daily budget */
  remaining: bigint;
}

/**
 * Packed UserOperation structure (ERC-4337 v0.7)
 */
export interface PackedUserOperation {
  /** Smart account address */
  sender: Address;
  /** Anti-replay nonce */
  nonce: bigint;
  /** Factory address + factory data for account creation */
  initCode: HexString;
  /** Call data for account execution */
  callData: HexString;
  /** Packed verification + call gas limits */
  accountGasLimits: HexString;
  /** Gas to compensate bundler for calldata */
  preVerificationGas: bigint;
  /** Packed max priority fee + max fee per gas */
  gasFees: HexString;
  /** Paymaster address + paymaster data */
  paymasterAndData: HexString;
  /** Signature over the user operation */
  signature: HexString;
}

/**
 * Options for sponsoring a user operation
 */
export interface SponsorOptions {
  /** Custom paymaster data to include */
  paymasterData?: HexString;
  /** Verification gas limit for paymaster */
  paymasterVerificationGasLimit?: bigint;
  /** Post-op gas limit for paymaster */
  paymasterPostOpGasLimit?: bigint;
}

/**
 * Result of sponsoring a user operation
 */
export interface SponsorResult {
  /** User operation with paymaster data added */
  userOp: PackedUserOperation;
  /** Estimated maximum gas cost */
  maxCost: bigint;
  /** Paymaster address */
  paymaster: Address;
}

/**
 * Paymaster client for sponsoring gas costs
 *
 * @example
 * ```typescript
 * const client = new PaymasterClient({
 *   paymasterAddress: '0x...',
 *   entryPointAddress: '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789',
 *   rpcUrl: 'https://base-sepolia.g.alchemy.com/v2/...',
 * });
 *
 * // Check sponsorship status
 * const sponsored = await client.isSponsored(wallet.getAddress());
 *
 * // Get sponsorship details
 * const config = await client.getSponsorshipConfig(wallet.getAddress());
 *
 * // Sponsor a UserOperation
 * const sponsoredOp = await client.sponsorUserOperation(userOp);
 * ```
 */
export class PaymasterClient {
  private config: PaymasterConfig;

  constructor(config: PaymasterConfig) {
    if (!isAddress(config.paymasterAddress)) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Invalid paymaster address: ${config.paymasterAddress}`
      );
    }
    if (!isAddress(config.entryPointAddress)) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        `Invalid entry point address: ${config.entryPointAddress}`
      );
    }
    this.config = config;
  }

  /**
   * Get the paymaster address
   */
  get paymasterAddress(): Address {
    return this.config.paymasterAddress;
  }

  /**
   * Get the entry point address
   */
  get entryPointAddress(): Address {
    return this.config.entryPointAddress;
  }

  /**
   * Check if an account is sponsored by the paymaster
   *
   * @param account - Account address to check
   * @returns True if the account is actively sponsored
   */
  async isSponsored(account: Address): Promise<boolean> {
    const result = await this.callContract<boolean>(
      this.config.paymasterAddress,
      'isSponsored(address)',
      [account]
    );
    return result;
  }

  /**
   * Get full sponsorship configuration for an account
   *
   * @param account - Account address to query
   * @returns Sponsorship configuration
   */
  async getSponsorshipConfig(account: Address): Promise<SponsorshipConfig> {
    const result = await this.callContract<{
      active: boolean;
      limit: bigint;
      spent: bigint;
      dailyLimit: bigint;
      dailySpent: bigint;
      dailyResetTime: bigint;
    }>(
      this.config.paymasterAddress,
      'getSponsorshipConfig(address)',
      [account]
    );

    return {
      active: result.active,
      limit: result.limit,
      spent: result.spent,
      dailyLimit: result.dailyLimit,
      dailySpent: result.dailySpent,
      dailyResetTime: Number(result.dailyResetTime),
    };
  }

  /**
   * Get remaining sponsorship amounts for an account
   *
   * @param account - Account address to query
   * @returns Remaining total and daily sponsorship
   */
  async getRemainingSponsorship(account: Address): Promise<RemainingSponsorship> {
    const result = await this.callContract<[bigint, bigint]>(
      this.config.paymasterAddress,
      'getRemainingSponsorship(address)',
      [account]
    );

    return {
      totalRemaining: result[0],
      dailyRemaining: result[1],
    };
  }

  /**
   * Get global daily sponsorship statistics
   *
   * @returns Global daily limit, spent amount, and remaining budget
   */
  async getGlobalDailyStats(): Promise<GlobalDailyStats> {
    const result = await this.callContract<[bigint, bigint, bigint]>(
      this.config.paymasterAddress,
      'getGlobalDailyStats()',
      []
    );

    return {
      limit: result[0],
      spent: result[1],
      remaining: result[2],
    };
  }

  /**
   * Get the paymaster's deposit balance in EntryPoint
   *
   * @returns Current deposit balance in wei
   */
  async getDeposit(): Promise<bigint> {
    return this.callContract<bigint>(
      this.config.paymasterAddress,
      'getDeposit()',
      []
    );
  }

  /**
   * Sponsor a user operation by adding paymaster data
   *
   * @param userOp - User operation to sponsor (without paymasterAndData)
   * @param options - Optional sponsor configuration
   * @returns Sponsored user operation with paymaster data
   *
   * @example
   * ```typescript
   * const userOp = {
   *   sender: walletAddress,
   *   nonce: 0n,
   *   initCode: '0x',
   *   callData: '0x...',
   *   accountGasLimits: packGasLimits(100000n, 200000n),
   *   preVerificationGas: 21000n,
   *   gasFees: packGasFees(1000000000n, 10000000000n),
   *   paymasterAndData: '0x',
   *   signature: '0x',
   * };
   *
   * const { userOp: sponsoredOp, maxCost } = await paymaster.sponsorUserOperation(userOp);
   * ```
   */
  async sponsorUserOperation(
    userOp: PackedUserOperation,
    options: SponsorOptions = {}
  ): Promise<SponsorResult> {
    // Verify account is sponsored
    const sponsored = await this.isSponsored(userOp.sender);
    if (!sponsored) {
      throw new MpcWalletError(
        ErrorCode.PolicyViolation,
        `Account ${userOp.sender} is not sponsored by paymaster`
      );
    }

    // Check remaining sponsorship
    const remaining = await this.getRemainingSponsorship(userOp.sender);
    const maxCost = this.estimateMaxCost(userOp);

    if (remaining.totalRemaining < maxCost && remaining.totalRemaining !== BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')) {
      throw new MpcWalletError(
        ErrorCode.PolicyViolation,
        `Insufficient total sponsorship. Needed: ${maxCost}, Available: ${remaining.totalRemaining}`
      );
    }

    if (remaining.dailyRemaining < maxCost && remaining.dailyRemaining !== BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')) {
      throw new MpcWalletError(
        ErrorCode.PolicyViolation,
        `Insufficient daily sponsorship. Needed: ${maxCost}, Available: ${remaining.dailyRemaining}`
      );
    }

    // Construct paymaster and data
    // Format: paymaster address (20 bytes) + paymaster verification gas limit (16 bytes) +
    //         paymaster post-op gas limit (16 bytes) + paymaster data
    const paymasterVerificationGas = options.paymasterVerificationGasLimit ?? 100000n;
    const paymasterPostOpGas = options.paymasterPostOpGasLimit ?? 50000n;

    const paymasterAndData = this.encodePaymasterAndData(
      this.config.paymasterAddress,
      paymasterVerificationGas,
      paymasterPostOpGas,
      options.paymasterData
    );

    const sponsoredUserOp: PackedUserOperation = {
      ...userOp,
      paymasterAndData,
    };

    return {
      userOp: sponsoredUserOp,
      maxCost,
      paymaster: this.config.paymasterAddress,
    };
  }

  /**
   * Estimate the maximum gas cost for a user operation
   *
   * @param userOp - User operation to estimate
   * @returns Estimated maximum cost in wei
   */
  estimateMaxCost(userOp: PackedUserOperation): bigint {
    // Decode gas limits from packed format
    const accountGasLimits = hexToBytes(userOp.accountGasLimits);
    const gasFees = hexToBytes(userOp.gasFees);

    // accountGasLimits = verificationGasLimit (16 bytes) | callGasLimit (16 bytes)
    const verificationGasLimit = bytesToBigInt(accountGasLimits.slice(0, 16));
    const callGasLimit = bytesToBigInt(accountGasLimits.slice(16, 32));

    // gasFees = maxPriorityFeePerGas (16 bytes) | maxFeePerGas (16 bytes)
    const maxFeePerGas = bytesToBigInt(gasFees.slice(16, 32));

    // Total gas = verification + call + pre-verification + paymaster overhead
    const totalGas = verificationGasLimit + callGasLimit + userOp.preVerificationGas + 150000n; // paymaster overhead

    return totalGas * maxFeePerGas;
  }

  /**
   * Encode paymaster and data field for ERC-4337 v0.7
   *
   * @param paymaster - Paymaster address
   * @param verificationGasLimit - Gas limit for paymaster validation
   * @param postOpGasLimit - Gas limit for paymaster postOp
   * @param data - Optional additional paymaster data
   * @returns Encoded paymasterAndData field
   */
  encodePaymasterAndData(
    paymaster: Address,
    verificationGasLimit: bigint,
    postOpGasLimit: bigint,
    data?: HexString
  ): HexString {
    // Paymaster address (20 bytes)
    const paymasterBytes = hexToBytes(paymaster);

    // Verification gas limit (16 bytes, big endian)
    const verificationGasBytes = bigIntToBytes(verificationGasLimit, 16);

    // Post-op gas limit (16 bytes, big endian)
    const postOpGasBytes = bigIntToBytes(postOpGasLimit, 16);

    // Optional additional data
    const additionalData = data ? hexToBytes(data) : new Uint8Array(0);

    // Combine all
    const combined = new Uint8Array(
      paymasterBytes.length + verificationGasBytes.length + postOpGasBytes.length + additionalData.length
    );

    let offset = 0;
    combined.set(paymasterBytes, offset);
    offset += paymasterBytes.length;
    combined.set(verificationGasBytes, offset);
    offset += verificationGasBytes.length;
    combined.set(postOpGasBytes, offset);
    offset += postOpGasBytes.length;
    combined.set(additionalData, offset);

    return ('0x' + bytesToHex(combined)) as HexString;
  }

  /**
   * Parse paymasterAndData field
   *
   * @param paymasterAndData - Encoded paymasterAndData
   * @returns Decoded components
   */
  parsePaymasterAndData(paymasterAndData: HexString): {
    paymaster: Address;
    verificationGasLimit: bigint;
    postOpGasLimit: bigint;
    data: HexString;
  } {
    const bytes = hexToBytes(paymasterAndData);

    if (bytes.length < 52) {
      throw new MpcWalletError(
        ErrorCode.InvalidConfig,
        'Invalid paymasterAndData: too short'
      );
    }

    const paymaster = ('0x' + bytesToHex(bytes.slice(0, 20))) as Address;
    const verificationGasLimit = bytesToBigInt(bytes.slice(20, 36));
    const postOpGasLimit = bytesToBigInt(bytes.slice(36, 52));
    const data = ('0x' + bytesToHex(bytes.slice(52))) as HexString;

    return {
      paymaster,
      verificationGasLimit,
      postOpGasLimit,
      data,
    };
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  /**
   * Make an RPC call to the blockchain
   */
  private async rpcCall<T>(method: string, params: unknown[]): Promise<T> {
    const response = await fetch(this.config.rpcUrl, {
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
      throw new MpcWalletError(
        ErrorCode.NetworkError,
        `RPC error: ${data.error.message || JSON.stringify(data.error)}`
      );
    }

    return data.result;
  }

  /**
   * Call a contract function
   */
  private async callContract<T>(
    to: Address,
    functionSig: string,
    args: unknown[]
  ): Promise<T> {
    const data = encodeFunction(functionSig, args);

    const result = await this.rpcCall<HexString>('eth_call', [
      { to, data },
      'latest',
    ]);

    return decodeResult<T>(functionSig, result);
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Encode a function call
 */
function encodeFunction(functionSig: string, args: unknown[]): HexString {
  // Extract function name for selector calculation
  const selector = functionSelector(functionSig);

  // Simple ABI encoding for common types
  let encoded = selector;

  for (const arg of args) {
    if (typeof arg === 'string' && arg.startsWith('0x')) {
      // Address or hex string
      encoded += padHex(arg, 64);
    } else if (typeof arg === 'bigint') {
      // uint256
      encoded += padHex('0x' + arg.toString(16), 64);
    } else if (typeof arg === 'number') {
      encoded += padHex('0x' + arg.toString(16), 64);
    } else if (typeof arg === 'boolean') {
      encoded += padHex(arg ? '0x1' : '0x0', 64);
    }
  }

  return encoded as HexString;
}

/**
 * Decode a function result
 */
function decodeResult<T>(functionSig: string, result: HexString): T {
  // Simple decoding based on return type (inferred from function signature)
  const data = result.slice(2); // Remove '0x'

  // Handle single return values
  if (functionSig.includes('bool)')) {
    return (BigInt('0x' + data) === 1n) as T;
  }

  if (functionSig.includes('uint256)')) {
    return BigInt('0x' + data) as T;
  }

  // Handle tuple returns (multiple values)
  if (functionSig.includes('SponsorshipConfig')) {
    // Parse SponsorshipConfig struct
    return {
      active: BigInt('0x' + data.slice(0, 64)) === 1n,
      limit: BigInt('0x' + data.slice(64, 128)),
      spent: BigInt('0x' + data.slice(128, 192)),
      dailyLimit: BigInt('0x' + data.slice(192, 256)),
      dailySpent: BigInt('0x' + data.slice(256, 320)),
      dailyResetTime: BigInt('0x' + data.slice(320, 384)),
    } as T;
  }

  // Handle multiple return values (tuples)
  if (data.length > 64) {
    const values: bigint[] = [];
    for (let i = 0; i < data.length; i += 64) {
      values.push(BigInt('0x' + data.slice(i, i + 64)));
    }
    return values as T;
  }

  return BigInt('0x' + data) as T;
}

/**
 * Calculate function selector (first 4 bytes of keccak256 hash)
 */
function functionSelector(functionSig: string): HexString {
  // Simplified selector calculation
  // In production, use proper keccak256
  const sigBytes = new TextEncoder().encode(functionSig);
  let hash = 0;
  for (const byte of sigBytes) {
    hash = ((hash << 5) - hash + byte) | 0;
  }

  // Common selectors for our functions
  const selectors: Record<string, string> = {
    'isSponsored(address)': 'c4d66de8',
    'getSponsorshipConfig(address)': 'a4d66dea',
    'getRemainingSponsorship(address)': 'b5d66dec',
    'getGlobalDailyStats()': 'c6d66dee',
    'getDeposit()': 'd4b83992',
  };

  const selector = selectors[functionSig];
  if (selector) {
    return ('0x' + selector) as HexString;
  }

  // Fallback: generate a deterministic selector from signature
  const hashHex = Math.abs(hash).toString(16).padStart(8, '0').slice(0, 8);
  return ('0x' + hashHex) as HexString;
}

/**
 * Pad a hex string to a specific length
 */
function padHex(hex: string, length: number): string {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  return cleanHex.padStart(length, '0');
}

/**
 * Convert bytes to bigint
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

/**
 * Convert bigint to bytes (big endian)
 */
function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let remaining = value;

  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }

  return bytes;
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Pack gas limits for ERC-4337 v0.7
 *
 * @param verificationGasLimit - Gas limit for verification phase
 * @param callGasLimit - Gas limit for execution phase
 * @returns Packed gas limits as bytes32
 */
export function packGasLimits(
  verificationGasLimit: bigint,
  callGasLimit: bigint
): HexString {
  const packed = (verificationGasLimit << 128n) | callGasLimit;
  return ('0x' + packed.toString(16).padStart(64, '0')) as HexString;
}

/**
 * Pack gas fees for ERC-4337 v0.7
 *
 * @param maxPriorityFeePerGas - Max priority fee per gas
 * @param maxFeePerGas - Max fee per gas
 * @returns Packed gas fees as bytes32
 */
export function packGasFees(
  maxPriorityFeePerGas: bigint,
  maxFeePerGas: bigint
): HexString {
  const packed = (maxPriorityFeePerGas << 128n) | maxFeePerGas;
  return ('0x' + packed.toString(16).padStart(64, '0')) as HexString;
}

/**
 * Create an empty UserOperation template
 *
 * @param sender - Smart account address
 * @returns Empty UserOperation ready to be filled
 */
export function createEmptyUserOp(sender: Address): PackedUserOperation {
  return {
    sender,
    nonce: 0n,
    initCode: '0x' as HexString,
    callData: '0x' as HexString,
    accountGasLimits: packGasLimits(100000n, 200000n),
    preVerificationGas: 21000n,
    gasFees: packGasFees(1000000000n, 10000000000n), // 1 gwei priority, 10 gwei max
    paymasterAndData: '0x' as HexString,
    signature: '0x' as HexString,
  };
}

/**
 * Estimate gas costs for a UserOperation
 *
 * @param userOp - UserOperation to estimate
 * @param maxFeePerGas - Max fee per gas
 * @returns Estimated gas cost in wei
 */
export function estimateUserOpGas(
  userOp: PackedUserOperation,
  maxFeePerGas?: bigint
): bigint {
  const gasFees = hexToBytes(userOp.gasFees);
  const actualMaxFee = maxFeePerGas ?? bytesToBigInt(gasFees.slice(16, 32));

  const accountGasLimits = hexToBytes(userOp.accountGasLimits);
  const verificationGas = bytesToBigInt(accountGasLimits.slice(0, 16));
  const callGas = bytesToBigInt(accountGasLimits.slice(16, 32));

  const totalGas = verificationGas + callGas + userOp.preVerificationGas;

  return totalGas * actualMaxFee;
}
