/**
 * MPC Wallet Plugin for ElizaOS
 *
 * Enables AI agents to securely manage cryptocurrency wallets
 * using threshold MPC cryptography.
 *
 * Updated for ElizaOS v2.0 API
 */

export {
  // v2 Plugin export (recommended)
  mpcWalletPlugin,
  // v2 Service class export
  MpcWalletService,
  // Legacy exports for backwards compatibility
  MpcWalletPlugin,
  createMpcWalletPlugin,
  type MpcWalletPluginConfig,
  type PluginContext,
} from './plugin.js';

// Action factory exports (for custom implementations)
export { balanceAction } from './actions/balance.js';
export { sendAction } from './actions/send.js';
export { swapAction } from './actions/swap.js';
export { policyAction } from './actions/policy.js';
