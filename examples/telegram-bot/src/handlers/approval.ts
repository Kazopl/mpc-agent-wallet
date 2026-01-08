/**
 * Approval Flow Handler
 *
 * Listens for approval requests from the relay and notifies users.
 * Updated for grammY v1.39.2+
 */

import type { Bot } from 'grammy';
import { InlineKeyboard } from 'grammy';
import type { BotContext, ApprovalRequest } from '../bot.js';
import type { RelayClient, ApprovalRequestEvent } from '../relay/client.js';

// Map of user IDs to chat IDs
const userChatMap = new Map<string, number>();

// Global pending requests map (in production, use proper state management)
const pendingRequests = new Map<string, ApprovalRequest & { chatId: number }>();

export function setupApprovalFlow(bot: Bot<BotContext>, relay: RelayClient): void {
  // Track user chat IDs when they interact with the bot
  bot.on('message', async (ctx, next) => {
    if (ctx.from) {
      userChatMap.set(ctx.from.id.toString(), ctx.chat.id);
    }
    await next();
  });

  // Listen for approval requests from relay
  relay.onApprovalRequest(async (event: ApprovalRequestEvent) => {
    console.log(`[APPROVAL] Received approval request: ${event.sessionId}`);

    // Find the user to notify
    const userId = event.userId;
    const chatId = userChatMap.get(userId);

    if (!chatId) {
      console.log(`[WARN] No chat found for user ${userId}`);
      return;
    }

    // Create approval request
    const request: ApprovalRequest = {
      sessionId: event.sessionId,
      agentName: event.agentName || 'AI Agent',
      to: event.to,
      value: event.value,
      chain: event.chain,
      chainId: event.chainId,
      gasEstimate: event.gasEstimate,
      timestamp: Date.now(),
    };

    // Format the message
    const valueEth = formatEther(event.value);
    const isHighValue = parseFloat(valueEth) > 1;

    let message = `*Transaction Approval Request*\n\n`;

    if (isHighValue) {
      message += `*HIGH VALUE TRANSACTION*\n\n`;
    }

    message += `*From:* ${request.agentName}\n`;
    message += `*To:* \`${event.to}\`\n`;
    message += `*Amount:* ${valueEth} ETH\n`;
    message += `*Chain:* ${event.chain}\n`;

    if (event.gasEstimate) {
      message += `*Gas:* ~${event.gasEstimate} gas\n`;
    }

    message += `\n_Request expires in 5 minutes_`;

    // Create inline keyboard with buttons using grammY v1.39+ pattern
    const keyboard = new InlineKeyboard()
      .text('Approve', `approve:${event.sessionId}`)
      .text('Reject', `reject:${event.sessionId}`)
      .row()
      .text('Details', `details:${event.sessionId}`);

    try {
      // Send the notification
      const sent = await bot.api.sendMessage(chatId, message, {
        parse_mode: 'Markdown',
        reply_markup: keyboard,
      });

      // Store the request
      request.messageId = sent.message_id;
      pendingRequests.set(event.sessionId, {
        ...request,
        chatId,
      });

      console.log(`[OK] Sent approval request to chat ${chatId}`);

      // Set expiration timer
      setTimeout(async () => {
        const pending = pendingRequests.get(event.sessionId);
        if (pending) {
          pendingRequests.delete(event.sessionId);

          try {
            const expiredMessage = `
*Request Expired*

To: \`${event.to}\`
Amount: ${valueEth} ETH

_This approval request has expired._
            `;

            await bot.api.editMessageText(chatId, sent.message_id, expiredMessage, {
              parse_mode: 'Markdown',
            });
          } catch {
            // Message might already be edited
          }
        }
      }, 5 * 60 * 1000); // 5 minutes
    } catch (error) {
      console.error('Error sending approval request:', error);
    }
  });
}

export function getPendingRequest(sessionId: string): (ApprovalRequest & { chatId: number }) | undefined {
  return pendingRequests.get(sessionId);
}

export function removePendingRequest(sessionId: string): void {
  pendingRequests.delete(sessionId);
}

function formatEther(wei: string): string {
  const value = BigInt(wei);
  const eth = Number(value) / 1e18;
  return eth.toFixed(4);
}
