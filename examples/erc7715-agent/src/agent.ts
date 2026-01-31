/**
 * ERC-7715 AI Agent
 *
 * An AI agent that uses ERC-7715 wallet execution permissions to
 * autonomously execute transactions with fine-grained constraints.
 */

import {
  ERC7715Provider,
  createERC7715Provider,
  type ERC7715ProviderConfig,
} from '@mpc-wallet/sdk';

import type {
  ChainIdHex,
  PermissionId,
  PermissionResponse,
  PermissionsContext,
  SupportedPermissionsResponse,
  Action,
  ExecutionResponse,
} from '@mpc-wallet/sdk/erc7715';

// ============================================================================
// Types
// ============================================================================

export interface AgentConfig {
  /** User's wallet address */
  walletAddress: `0x${string}`;
  /** Agent's signing address */
  agentAddress?: `0x${string}`;
  /** Chain ID in hex format */
  chainId: ChainIdHex;
  /** Maximum spending limit the agent can request */
  maxSpendingLimit?: bigint;
}

export interface TradingPermissionRequest {
  /** Maximum ETH spending limit (in ETH, not wei) */
  spendingLimit: string;
  /** Duration in seconds */
  duration: number;
  /** Allowed protocol names */
  allowedProtocols?: string[];
  /** Rate limit (transactions per hour) */
  rateLimit?: number;
}

export interface SwapParams {
  /** Input token address (use 0xEeee... for ETH) */
  tokenIn: `0x${string}`;
  /** Output token address */
  tokenOut: `0x${string}`;
  /** Amount of input token (human-readable) */
  amountIn: string;
  /** Minimum output amount (human-readable) */
  minAmountOut: string;
  /** Deadline timestamp (optional, default: 30 mins) */
  deadline?: number;
}

export interface PermissionStatus {
  /** Number of active permissions */
  activeCount: number;
  /** Total spending limit across all permissions */
  totalSpendingLimit: string;
  /** Earliest expiry timestamp */
  earliestExpiry: number;
}

export interface RemainingAllowance {
  /** Remaining spending in wei */
  spending: string;
  /** Time remaining in seconds */
  timeSeconds: number;
}

// ============================================================================
// Protocol Registry
// ============================================================================

/**
 * Known protocol contract addresses by chain
 */
const PROTOCOL_REGISTRY: Record<string, Record<string, `0x${string}`>> = {
  // Mainnet
  '0x1': {
    uniswap_router: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
    uniswap_v2_router: '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',
    sushiswap_router: '0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F',
    aave_pool: '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2',
  },
  // Base
  '0x2105': {
    uniswap_router: '0x2626664c2603336E57B271c5C0b26F421741e481',
    aerodrome_router: '0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43',
  },
  // Base Sepolia
  '0x14a34': {
    uniswap_router: '0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4',
    mock_dex: '0x0000000000000000000000000000000000000001',
  },
};

/**
 * Common function selectors for DeFi protocols
 */
const SELECTORS = {
  // Uniswap V3 SwapRouter02
  multicall: '0x5ae401dc' as `0x${string}`,
  multicallLegacy: '0xac9650d8' as `0x${string}`,
  exactInputSingle: '0x04e45aaf' as `0x${string}`,
  exactOutputSingle: '0x5023b4df' as `0x${string}`,
  exactInput: '0xb858183f' as `0x${string}`,
  exactOutput: '0x09b81346' as `0x${string}`,

  // Uniswap V2
  swapExactTokensForTokens: '0x38ed1739' as `0x${string}`,
  swapTokensForExactTokens: '0x8803dbee' as `0x${string}`,
  swapExactETHForTokens: '0x7ff36ab5' as `0x${string}`,
  swapTokensForExactETH: '0x4a25d94a' as `0x${string}`,

  // ERC20
  transfer: '0xa9059cbb' as `0x${string}`,
  approve: '0x095ea7b3' as `0x${string}`,
};

// ============================================================================
// ERC-7715 Agent
// ============================================================================

/**
 * AI agent that uses ERC-7715 permissions for autonomous trading
 *
 * @example
 * ```typescript
 * const agent = new ERC7715Agent({
 *   walletAddress: '0x...',
 *   chainId: '0x2105', // Base
 * });
 *
 * // Request permission
 * const permission = await agent.requestTradingPermission({
 *   spendingLimit: '0.5',
 *   duration: 86400,
 *   allowedProtocols: ['uniswap'],
 * });
 *
 * // Execute trade
 * const tx = await agent.executeSwap({
 *   tokenIn: '0xEeee...',
 *   tokenOut: '0x...',
 *   amountIn: '0.1',
 *   minAmountOut: '100',
 * });
 * ```
 */
export class ERC7715Agent {
  private provider: ERC7715Provider;
  private config: AgentConfig;
  private activePermissions: Map<string, PermissionResponse> = new Map();
  private pendingApprovals: Set<string> = new Set();

  constructor(config: AgentConfig) {
    this.config = config;

    // Generate agent address if not provided
    const agentAddress = config.agentAddress ?? this.generateAgentAddress();

    // Create ERC-7715 provider
    const providerConfig: ERC7715ProviderConfig = {
      accountAddress: config.walletAddress,
      chainId: config.chainId,
      onApprovalRequest: async (request) => {
        // In a real application, this would show a UI to the user
        console.log('Permission request received:');
        console.log(`  Expiry: ${new Date(request.expiry * 1000).toISOString()}`);
        console.log(`  Permissions: ${request.permissions.length}`);

        // For demo, auto-approve if within limits
        return this.validatePermissionRequest(request);
      },
      onPermissionGranted: (response) => {
        this.activePermissions.set(response.permissionId, response);
        console.log(`Permission granted: ${response.permissionId.slice(0, 18)}...`);
      },
      onPermissionRevoked: (response) => {
        this.activePermissions.delete(response.permissionId);
        console.log(`Permission revoked: ${response.permissionId.slice(0, 18)}...`);
      },
      onExecuteActions: async (context, actions) => {
        // In production, this would submit to the blockchain
        console.log(`Executing ${actions.length} action(s) with context ${context.slice(0, 18)}...`);
        return '0x' + '0'.repeat(64) as `0x${string}`;
      },
    };

    this.provider = createERC7715Provider(providerConfig);
  }

  // ============================================================================
  // Permission Management
  // ============================================================================

  /**
   * Get supported permissions for the current chain
   */
  async getSupportedPermissions(): Promise<SupportedPermissionsResponse> {
    return this.provider.getSupportedPermissions();
  }

  /**
   * Request trading permissions
   */
  async requestTradingPermission(
    request: TradingPermissionRequest
  ): Promise<PermissionResponse> {
    const builder = this.provider.createPermissionRequest();

    // Set expiry
    builder.expireIn(request.duration);

    // Set signer (agent address)
    builder.withSigner({
      type: 'account',
      data: { id: this.config.agentAddress ?? this.generateAgentAddress() },
    });

    // Add native token transfer permission
    const spendingLimitWei = parseEther(request.spendingLimit);
    builder.allowNativeTransfer(spendingLimitWei);

    // Add contract call permissions for allowed protocols
    if (request.allowedProtocols) {
      const protocols = PROTOCOL_REGISTRY[this.config.chainId] ?? {};

      for (const protocol of request.allowedProtocols) {
        const protocolKey = `${protocol}_router`;
        const address = protocols[protocolKey];

        if (address) {
          // Allow Uniswap-style router calls
          builder.allowContractCall(address, [
            SELECTORS.multicall,
            SELECTORS.multicallLegacy,
            SELECTORS.exactInputSingle,
            SELECTORS.exactOutputSingle,
            SELECTORS.swapExactTokensForTokens,
            SELECTORS.swapExactETHForTokens,
          ]);
        }
      }
    }

    // Add rate limit if specified
    if (request.rateLimit) {
      builder.allowRateLimit(request.rateLimit, 3600); // per hour
    }

    // Add spending limit policy
    builder.withSpendingLimit(spendingLimitWei);

    // Request permission
    const permissionRequest = builder.build();
    return this.provider.requestPermissions(permissionRequest);
  }

  /**
   * Revoke a specific permission
   */
  async revokePermission(permissionId: PermissionId): Promise<void> {
    await this.provider.revokePermission(permissionId);
    this.activePermissions.delete(permissionId);
  }

  /**
   * Revoke all active permissions
   */
  async revokeAllPermissions(): Promise<void> {
    for (const permissionId of this.activePermissions.keys()) {
      await this.revokePermission(permissionId as PermissionId);
    }
  }

  /**
   * Get current permission status
   */
  async getPermissionStatus(): Promise<PermissionStatus> {
    const granted = await this.provider.getGrantedPermissions();
    const active = granted.permissions.filter((p) => p.status === 'active');

    let totalSpendingLimit = 0n;
    let earliestExpiry = Number.MAX_SAFE_INTEGER;

    for (const permission of active) {
      earliestExpiry = Math.min(earliestExpiry, permission.expiry);

      for (const perm of permission.permissions) {
        if (perm.type === 'native-token-transfer') {
          const data = perm.data as { allowance: string };
          totalSpendingLimit += BigInt(data.allowance);
        }
      }
    }

    return {
      activeCount: active.length,
      totalSpendingLimit: totalSpendingLimit.toString(),
      earliestExpiry: earliestExpiry === Number.MAX_SAFE_INTEGER ? 0 : earliestExpiry,
    };
  }

  /**
   * Get remaining allowance for a specific permission
   */
  getRemainingAllowance(permissionId?: PermissionId): RemainingAllowance {
    // If no specific permission, use the first active one
    const id = permissionId ?? Array.from(this.activePermissions.keys())[0];

    if (!id) {
      return { spending: '0', timeSeconds: 0 };
    }

    const timeRemaining = this.provider.getPermissionTimeRemaining(id as PermissionId);
    const permission = this.activePermissions.get(id);

    let spendingLimit = 0n;
    if (permission) {
      for (const perm of permission.permissions) {
        if (perm.type === 'native-token-transfer') {
          const data = perm.data as { allowance: string };
          spendingLimit += BigInt(data.allowance);
        }
      }
    }

    return {
      spending: spendingLimit.toString(),
      timeSeconds: timeRemaining,
    };
  }

  // ============================================================================
  // Trade Execution
  // ============================================================================

  /**
   * Execute a token swap
   */
  async executeSwap(params: SwapParams): Promise<ExecutionResponse> {
    // Find a valid permission
    const permission = this.findValidPermission();
    if (!permission) {
      throw new Error('No valid permission available for swap');
    }

    // Build swap action
    const action = this.buildSwapAction(params);

    // Execute with permission
    return this.provider.executeWithPermission(
      permission.permissionsContext,
      [action]
    );
  }

  /**
   * Execute a native ETH transfer
   */
  async executeTransfer(
    to: `0x${string}`,
    amount: string
  ): Promise<ExecutionResponse> {
    const permission = this.findValidPermission();
    if (!permission) {
      throw new Error('No valid permission available for transfer');
    }

    const amountWei = parseEther(amount);

    const action: Action = {
      to,
      value: amountWei,
      data: '0x',
    };

    return this.provider.executeWithPermission(
      permission.permissionsContext,
      [action]
    );
  }

  /**
   * Execute multiple actions in batch
   */
  async executeBatch(actions: Action[]): Promise<ExecutionResponse> {
    const permission = this.findValidPermission();
    if (!permission) {
      throw new Error('No valid permission available for batch execution');
    }

    return this.provider.executeWithPermission(
      permission.permissionsContext,
      actions
    );
  }

  // ============================================================================
  // Internal Methods
  // ============================================================================

  /**
   * Find a valid permission for execution
   */
  private findValidPermission(): PermissionResponse | null {
    for (const [id, permission] of this.activePermissions) {
      if (this.provider.isPermissionValid(id as PermissionId)) {
        return permission;
      }
    }
    return null;
  }

  /**
   * Build a swap action for Uniswap-style routers
   */
  private buildSwapAction(params: SwapParams): Action {
    const protocols = PROTOCOL_REGISTRY[this.config.chainId] ?? {};
    const routerAddress = protocols['uniswap_router'];

    if (!routerAddress) {
      throw new Error(`No router found for chain ${this.config.chainId}`);
    }

    const deadline = params.deadline ?? Math.floor(Date.now() / 1000) + 1800; // 30 mins
    const amountIn = parseEther(params.amountIn);

    // Build multicall data for Uniswap V3
    // This is a simplified version - real implementation would use proper encoding
    const swapData = encodeSwapExactInputSingle({
      tokenIn: params.tokenIn,
      tokenOut: params.tokenOut,
      fee: 3000, // 0.3% fee tier
      recipient: this.config.walletAddress,
      amountIn,
      amountOutMinimum: parseUnits(params.minAmountOut, 6), // Assuming USDC output
      sqrtPriceLimitX96: '0',
    });

    const isETH = params.tokenIn.toLowerCase() === '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';

    return {
      to: routerAddress,
      value: isETH ? amountIn : '0x0',
      data: swapData,
    };
  }

  /**
   * Validate a permission request against agent limits
   */
  private validatePermissionRequest(request: { expiry: number; permissions: readonly unknown[] }): boolean {
    // Check duration
    const now = Math.floor(Date.now() / 1000);
    const duration = request.expiry - now;

    if (duration > 7 * 24 * 3600) {
      console.log('Rejecting: Duration exceeds 7 days');
      return false;
    }

    // Check spending limit
    if (this.config.maxSpendingLimit) {
      for (const perm of request.permissions) {
        const permission = perm as { type: string; data: { allowance?: string } };
        if (permission.type === 'native-token-transfer' && permission.data.allowance) {
          const allowance = BigInt(permission.data.allowance);
          if (allowance > this.config.maxSpendingLimit) {
            console.log('Rejecting: Spending limit exceeds maximum');
            return false;
          }
        }
      }
    }

    return true;
  }

  /**
   * Generate a deterministic agent address
   */
  private generateAgentAddress(): `0x${string}` {
    // In production, this would be a proper key derivation
    const hash = simpleHash(this.config.walletAddress + this.config.chainId);
    return ('0x' + hash.slice(2, 42)) as `0x${string}`;
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Parse ETH amount to wei
 */
function parseEther(amount: string): `0x${string}` {
  const wei = BigInt(Math.floor(parseFloat(amount) * 1e18));
  return ('0x' + wei.toString(16)) as `0x${string}`;
}

/**
 * Parse units to smallest denomination
 */
function parseUnits(amount: string, decimals: number): `0x${string}` {
  const value = BigInt(Math.floor(parseFloat(amount) * Math.pow(10, decimals)));
  return ('0x' + value.toString(16)) as `0x${string}`;
}

/**
 * Simple hash function for demo purposes
 */
function simpleHash(input: string): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  const hex = Math.abs(hash).toString(16).padStart(40, '0');
  return '0x' + hex;
}

/**
 * Encode Uniswap V3 exactInputSingle call
 * This is a simplified version for demonstration
 */
function encodeSwapExactInputSingle(params: {
  tokenIn: string;
  tokenOut: string;
  fee: number;
  recipient: string;
  amountIn: string;
  amountOutMinimum: string;
  sqrtPriceLimitX96: string;
}): `0x${string}` {
  // In production, use viem or ethers.js for proper ABI encoding
  // This is a placeholder that generates a valid-looking calldata
  const selector = SELECTORS.exactInputSingle;
  const paddedParams = [
    params.tokenIn.slice(2).padStart(64, '0'),
    params.tokenOut.slice(2).padStart(64, '0'),
    params.fee.toString(16).padStart(64, '0'),
    params.recipient.slice(2).padStart(64, '0'),
    BigInt(params.amountIn).toString(16).padStart(64, '0'),
    BigInt(params.amountOutMinimum).toString(16).padStart(64, '0'),
    BigInt(params.sqrtPriceLimitX96).toString(16).padStart(64, '0'),
  ].join('');

  return (selector + paddedParams) as `0x${string}`;
}
