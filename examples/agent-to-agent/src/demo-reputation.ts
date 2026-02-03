/**
 * Reputation Demo
 *
 * Demonstrates reputation management features:
 * - Submit positive and negative feedback
 * - Query reputation scores
 * - Filter by tags and reviewers
 * - Check reputation thresholds
 * - Revoke feedback
 */

import { AgentClient } from './agent.js';
import {
  registerInSimulatedRegistry,
  clearSimulatedRegistry,
} from './discovery.js';
import {
  submitFeedback,
  checkReputation,
  checkReputationWithFilters,
  meetsReputationThreshold,
  hasMinimumFeedback,
  getPositiveRatio,
  revokeFeedback,
  getFeedbackHistory,
  formatReputation,
  clearSimulatedReputation,
} from './reputation.js';

async function main() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('              Reputation Management Demo (ERC-8004)             ');
  console.log('═══════════════════════════════════════════════════════════════\n');

  clearSimulatedRegistry();
  clearSimulatedReputation();

  // ============================================================================
  // Setup: Create agents
  // ============================================================================
  console.log('[Setup] Creating agents...\n');

  const targetAgent = new AgentClient('target', {
    name: 'ServiceProvider',
    description: 'An agent providing DeFi services',
  });
  await targetAgent.initialize();
  await targetAgent.register();
  registerInSimulatedRegistry(targetAgent);

  const reviewer1 = new AgentClient('reviewer1', {
    name: 'TrustedProtocol',
    description: 'A major DeFi protocol',
  });
  await reviewer1.initialize();
  await reviewer1.register();

  const reviewer2 = new AgentClient('reviewer2', {
    name: 'CommunityMember',
    description: 'A community reviewer',
  });
  await reviewer2.initialize();
  await reviewer2.register();

  const reviewer3 = new AgentClient('reviewer3', {
    name: 'MaliciousActor',
    description: 'An untrusted reviewer',
  });
  await reviewer3.initialize();
  await reviewer3.register();

  console.log('');
  const targetId = targetAgent.getAgentId();

  // ============================================================================
  // Demo 1: Submit various feedback
  // ============================================================================
  console.log('[Demo 1] Submitting feedback from multiple reviewers...\n');

  await submitFeedback({
    fromAgent: reviewer1,
    toAgentId: targetId,
    value: 500n,
    decimals: 2,
    tags: ['reliability', 'execution'],
    proofOfPayment: '0x' + 'a'.repeat(64),
  });

  await submitFeedback({
    fromAgent: reviewer2,
    toAgentId: targetId,
    value: 350n,
    decimals: 2,
    tags: ['speed', 'accuracy'],
    proofOfPayment: '0x' + 'b'.repeat(64),
  });

  await submitFeedback({
    fromAgent: reviewer1,
    toAgentId: targetId,
    value: 420n,
    decimals: 2,
    tags: ['reliability', 'api'],
  });

  await submitFeedback({
    fromAgent: reviewer3,
    toAgentId: targetId,
    value: -200n,
    decimals: 2,
    tags: ['reliability', 'fake'],
  });

  console.log('');

  // ============================================================================
  // Demo 2: Check overall reputation
  // ============================================================================
  console.log('[Demo 2] Checking overall reputation...\n');

  const overallReputation = await checkReputation(targetId);

  console.log('\n--- Overall Reputation ---');
  console.log(formatReputation(overallReputation));
  console.log('');

  // ============================================================================
  // Demo 3: Filter by trusted reviewers
  // ============================================================================
  console.log('[Demo 3] Filtering reputation by trusted reviewers...\n');

  const trustedReputation = await checkReputationWithFilters(targetId, {
    reviewers: [reviewer1.getWalletAddress(), reviewer2.getWalletAddress()],
  });

  console.log('\n--- Reputation from Trusted Reviewers ---');
  console.log(formatReputation(trustedReputation));
  console.log('');

  // ============================================================================
  // Demo 4: Filter by tags
  // ============================================================================
  console.log('[Demo 4] Filtering reputation by tag...\n');

  const reliabilityReputation = await checkReputationWithFilters(targetId, {
    tag1: 'reliability',
  });

  console.log('\n--- Reputation for "reliability" tag ---');
  console.log(formatReputation(reliabilityReputation));
  console.log('');

  // ============================================================================
  // Demo 5: Check thresholds
  // ============================================================================
  console.log('[Demo 5] Checking reputation thresholds...\n');

  console.log('Threshold checks (using trusted reviewers only):');
  console.log(`  Meets 0.5 threshold: ${meetsReputationThreshold(trustedReputation, 0.5)}`);
  console.log(`  Meets 0.7 threshold: ${meetsReputationThreshold(trustedReputation, 0.7)}`);
  console.log(`  Meets 0.9 threshold: ${meetsReputationThreshold(trustedReputation, 0.9)}`);
  console.log(`  Has minimum 3 feedbacks: ${hasMinimumFeedback(trustedReputation, 3)}`);
  console.log(`  Positive ratio: ${(getPositiveRatio(trustedReputation) * 100).toFixed(1)}%`);
  console.log('');

  // ============================================================================
  // Demo 6: View feedback history
  // ============================================================================
  console.log('[Demo 6] Viewing feedback history...\n');

  const history = await getFeedbackHistory(targetId);

  console.log('Feedback History:');
  for (const feedback of history) {
    const scoreStr = (Number(feedback.value) / Math.pow(10, feedback.decimals)).toFixed(2);
    const sign = Number(feedback.value) > 0 ? '+' : '';
    console.log(`  [${feedback.feedbackIndex}] ${sign}${scoreStr} from ${feedback.reviewer.slice(0, 10)}... [${feedback.tag1}, ${feedback.tag2}]`);
  }
  console.log('');

  // ============================================================================
  // Demo 7: Revoke feedback
  // ============================================================================
  console.log('[Demo 7] Revoking feedback...\n');

  const negativeReviewer3Feedback = history.find(
    f => f.reviewer.toLowerCase() === reviewer3.getWalletAddress().toLowerCase()
  );

  if (negativeReviewer3Feedback) {
    console.log(`Revoking malicious feedback (index ${negativeReviewer3Feedback.feedbackIndex})...`);
    await revokeFeedback(reviewer3, targetId, negativeReviewer3Feedback.feedbackIndex);
  }

  console.log('');

  // ============================================================================
  // Demo 8: Check reputation after revocation
  // ============================================================================
  console.log('[Demo 8] Reputation after revoking malicious feedback...\n');

  const cleanReputation = await checkReputation(targetId);

  console.log('\n--- Clean Reputation (after revocation) ---');
  console.log(formatReputation(cleanReputation));
  console.log('');

  // ============================================================================
  // Summary
  // ============================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('                   Reputation Demo Complete                     ');
  console.log('═══════════════════════════════════════════════════════════════\n');

  console.log('Demonstrated:');
  console.log('  1. Submitted positive and negative feedback');
  console.log('  2. Calculated overall reputation score');
  console.log('  3. Filtered reputation by trusted reviewers');
  console.log('  4. Filtered reputation by service tags');
  console.log('  5. Checked reputation against thresholds');
  console.log('  6. Viewed full feedback history');
  console.log('  7. Revoked malicious feedback');
  console.log('  8. Verified improved reputation after cleanup');
  console.log('');
  console.log('Key insight: Filter by trusted reviewers to prevent Sybil attacks!\n');
}

main().catch(console.error);
