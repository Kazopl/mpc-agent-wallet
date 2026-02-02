/**
 * MPC Wallet Plugin for ElizaOS
 *
 * Enables AI agents to securely manage cryptocurrency wallets
 * using threshold MPC cryptography with ERC-8004 agent identity support.
 *
 * Updated for ElizaOS v2.0 API
 */

export {
  mpcWalletPlugin,
  MpcWalletService,
  MpcWalletPlugin,
  createMpcWalletPlugin,
  type MpcWalletPluginConfig,
  type PluginContext,
} from './plugin.js';

export { balanceAction } from './actions/balance.js';
export { sendAction } from './actions/send.js';
export { swapAction } from './actions/swap.js';
export { policyAction } from './actions/policy.js';

export {
  registerAgentAction,
  updateAgentProfileAction,
  getAgentIdentityAction,
} from './actions/identity.js';

export {
  checkReputationAction,
  giveFeedbackAction,
  revokeFeedbackAction,
} from './actions/reputation.js';

export {
  requestValidationAction,
  checkValidationStatusAction,
  listValidatorRequestsAction,
} from './actions/validation.js';
