/**
 * MPC Wallet Plugin for ElizaOS
 *
 * Enables AI agents to securely manage cryptocurrency wallets
 * using threshold MPC cryptography.
 */

export {
  MpcWalletPlugin,
  createMpcWalletPlugin,
  type MpcWalletPluginConfig,
  type PluginContext,
} from './plugin.js';
export { balanceAction } from './actions/balance.js';
export { sendAction } from './actions/send.js';
export { swapAction } from './actions/swap.js';
export { policyAction } from './actions/policy.js';
