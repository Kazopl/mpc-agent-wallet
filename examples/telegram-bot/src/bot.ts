/**
 * Telegram Bot Setup
 *
 * Updated for grammY v1.39.2+ with latest patterns
 */

import { Bot, Context, session, type SessionFlavor } from 'grammy';
import type { RelayClient } from './relay/client.js';
import { setupCommandHandlers } from './handlers/commands.js';
import { setupCallbackHandlers } from './handlers/callbacks.js';
import { setupApprovalFlow } from './handlers/approval.js';

export interface BotConfig {
  token: string;
  relay: RelayClient;
  allowedUserIds: number[];
}

export interface ApprovalRequest {
  sessionId: string;
  agentName: string;
  to: string;
  value: string;
  chain: string;
  chainId: number;
  gasEstimate?: string;
  timestamp: number;
  messageId?: number;
}

interface SessionData {
  linkedWalletAddress?: string;
  pendingApprovals: Map<string, ApprovalRequest>;
}

export type BotContext = Context & SessionFlavor<SessionData>;

export function createBot(config: BotConfig): Bot<BotContext> {
  const bot = new Bot<BotContext>(config.token);

  // Set up session middleware with initial data factory
  bot.use(
    session({
      initial: (): SessionData => ({
        pendingApprovals: new Map(),
      }),
    })
  );

  // Access control middleware
  bot.use(async (ctx, next) => {
    const userId = ctx.from?.id;

    // Allow if no restrictions or user is in list
    if (
      config.allowedUserIds.length === 0 ||
      (userId && config.allowedUserIds.includes(userId))
    ) {
      await next();
    } else {
      console.log(`Blocked unauthorized user: ${userId}`);
      await ctx.reply('⛔ Unauthorized. Contact the wallet administrator.');
    }
  });

  // Global error handler
  bot.catch((err) => {
    const ctx = err.ctx;
    console.error(`Error while handling update ${ctx.update.update_id}:`);
    console.error(err.error);
  });

  // Set up handlers
  setupCommandHandlers(bot, config.relay);
  setupCallbackHandlers(bot, config.relay);
  setupApprovalFlow(bot, config.relay);

  return bot;
}
