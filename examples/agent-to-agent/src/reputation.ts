import {
  ReputationAPI,
  FeedbackBuilder,
  SummaryQueryBuilder,
  REPUTATION_REGISTRY_ADDRESS,
  type FeedbackSignal,
  type ReputationSummary,
  type Address,
  type Hash,
} from '@mpc-wallet/sdk';
import { AgentClient } from './agent.js';

export interface AgentReputation {
  agentId: bigint;
  feedbackCount: bigint;
  aggregateValue: bigint;
  score: number;
  positiveCount: number;
  negativeCount: number;
}

export interface FeedbackSubmission {
  fromAgent: AgentClient;
  toAgentId: bigint;
  value: bigint;
  decimals: number;
  tags: [string, string] | [string] | [];
  proofOfPayment?: string;
}

const simulatedFeedback = new Map<string, FeedbackSignal[]>();

export async function submitFeedback(submission: FeedbackSubmission): Promise<void> {
  const { fromAgent, toAgentId, value, decimals, tags, proofOfPayment } = submission;

  console.log(`[Reputation] ${fromAgent.getName()} submitting feedback for agent ${toAgentId}...`);

  const feedback: FeedbackSignal = {
    agentId: toAgentId,
    reviewer: fromAgent.getWalletAddress(),
    value,
    decimals,
    tag1: tags[0] ?? '',
    tag2: tags[1] ?? '',
    proofOfPayment: (proofOfPayment ?? null) as Hash | null,
    timestamp: BigInt(Math.floor(Date.now() / 1000)),
    feedbackIndex: BigInt(getAgentFeedbackList(toAgentId).length),
    revoked: false,
  };

  const feedbackList = getAgentFeedbackList(toAgentId);
  feedbackList.push(feedback);
  simulatedFeedback.set(toAgentId.toString(), feedbackList);

  const scoreStr = (Number(value) / Math.pow(10, decimals)).toFixed(decimals);
  console.log(`[Reputation] Feedback submitted: ${Number(value) > 0 ? '+' : ''}${scoreStr} with tags [${tags.join(', ')}]`);
}

export async function checkReputation(agentId: bigint): Promise<AgentReputation> {
  console.log(`[Reputation] Checking reputation for agent ${agentId}...`);

  const feedbackList = getAgentFeedbackList(agentId);

  let aggregateValue = 0n;
  let positiveCount = 0;
  let negativeCount = 0;
  let decimals = 2;

  for (const feedback of feedbackList) {
    if (feedback.revoked) continue;

    aggregateValue += feedback.value;
    decimals = feedback.decimals;

    if (feedback.value > 0n) {
      positiveCount++;
    } else if (feedback.value < 0n) {
      negativeCount++;
    }
  }

  const count = BigInt(feedbackList.filter(f => !f.revoked).length);
  const score = count > 0n
    ? Number(aggregateValue) / Math.pow(10, decimals) / Number(count)
    : 0;

  const reputation: AgentReputation = {
    agentId,
    feedbackCount: count,
    aggregateValue,
    score,
    positiveCount,
    negativeCount,
  };

  console.log(`[Reputation] Agent ${agentId}: score=${score.toFixed(2)}, count=${count}, positive=${positiveCount}, negative=${negativeCount}`);

  return reputation;
}

export async function checkReputationWithFilters(
  agentId: bigint,
  options: {
    reviewers?: Address[];
    tag1?: string;
    tag2?: string;
  } = {}
): Promise<AgentReputation> {
  console.log(`[Reputation] Checking filtered reputation for agent ${agentId}...`);

  let feedbackList = getAgentFeedbackList(agentId);

  if (options.reviewers && options.reviewers.length > 0) {
    feedbackList = feedbackList.filter(f =>
      options.reviewers!.some(r => r.toLowerCase() === f.reviewer.toLowerCase())
    );
  }

  if (options.tag1) {
    feedbackList = feedbackList.filter(f => f.tag1 === options.tag1);
  }

  if (options.tag2) {
    feedbackList = feedbackList.filter(f => f.tag2 === options.tag2);
  }

  let aggregateValue = 0n;
  let positiveCount = 0;
  let negativeCount = 0;
  let decimals = 2;

  for (const feedback of feedbackList) {
    if (feedback.revoked) continue;

    aggregateValue += feedback.value;
    decimals = feedback.decimals;

    if (feedback.value > 0n) {
      positiveCount++;
    } else if (feedback.value < 0n) {
      negativeCount++;
    }
  }

  const count = BigInt(feedbackList.filter(f => !f.revoked).length);
  const score = count > 0n
    ? Number(aggregateValue) / Math.pow(10, decimals) / Number(count)
    : 0;

  return {
    agentId,
    feedbackCount: count,
    aggregateValue,
    score,
    positiveCount,
    negativeCount,
  };
}

export function meetsReputationThreshold(reputation: AgentReputation, threshold: number): boolean {
  if (reputation.feedbackCount === 0n) {
    console.log(`[Reputation] Agent has no feedback - cannot verify threshold`);
    return false;
  }

  const normalizedScore = (reputation.score + 5) / 10;
  const meetsThreshold = normalizedScore >= threshold;

  console.log(`[Reputation] Threshold check: ${normalizedScore.toFixed(2)} >= ${threshold} = ${meetsThreshold}`);

  return meetsThreshold;
}

export function hasMinimumFeedback(reputation: AgentReputation, minCount: number): boolean {
  return reputation.feedbackCount >= BigInt(minCount);
}

export function getPositiveRatio(reputation: AgentReputation): number {
  const total = reputation.positiveCount + reputation.negativeCount;
  if (total === 0) return 0;
  return reputation.positiveCount / total;
}

export async function revokeFeedback(
  fromAgent: AgentClient,
  toAgentId: bigint,
  feedbackIndex: bigint
): Promise<void> {
  console.log(`[Reputation] ${fromAgent.getName()} revoking feedback ${feedbackIndex} for agent ${toAgentId}...`);

  const feedbackList = getAgentFeedbackList(toAgentId);
  const index = Number(feedbackIndex);

  if (index >= feedbackList.length) {
    throw new Error(`Feedback index ${feedbackIndex} not found`);
  }

  const feedback = feedbackList[index];
  if (feedback.reviewer.toLowerCase() !== fromAgent.getWalletAddress().toLowerCase()) {
    throw new Error('Only the original reviewer can revoke feedback');
  }

  feedbackList[index] = { ...feedback, revoked: true };
  simulatedFeedback.set(toAgentId.toString(), feedbackList);

  console.log(`[Reputation] Feedback ${feedbackIndex} revoked`);
}

export async function getFeedbackHistory(agentId: bigint): Promise<FeedbackSignal[]> {
  return getAgentFeedbackList(agentId).filter(f => !f.revoked);
}

function getAgentFeedbackList(agentId: bigint): FeedbackSignal[] {
  return simulatedFeedback.get(agentId.toString()) ?? [];
}

export function formatReputation(reputation: AgentReputation): string {
  const lines = [
    `Agent ${reputation.agentId} Reputation:`,
    `  Score: ${reputation.score.toFixed(2)}`,
    `  Feedback Count: ${reputation.feedbackCount}`,
    `  Positive: ${reputation.positiveCount}`,
    `  Negative: ${reputation.negativeCount}`,
    `  Ratio: ${(getPositiveRatio(reputation) * 100).toFixed(1)}% positive`,
  ];
  return lines.join('\n');
}

export function clearSimulatedReputation(): void {
  simulatedFeedback.clear();
  console.log('[Reputation] Cleared all feedback data');
}
