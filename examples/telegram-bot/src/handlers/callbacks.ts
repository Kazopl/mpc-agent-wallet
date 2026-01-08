/**
 * Callback Query Handlers (button presses)
 *
 * Updated for grammY v1.39.2+ with latest patterns
 */

import type { Bot, Context } from 'grammy';
import type { BotContext } from '../bot.js';
import type { RelayClient } from '../relay/client.js';

type CallbackContext = Context & BotContext;

export function setupCallbackHandlers(bot: Bot<BotContext>, relay: RelayClient): void {
  // Handle approve button using filter pattern
  bot.callbackQuery(/^approve:(.+)$/, async (ctx: CallbackContext) => {
    const sessionId = ctx.match![1];
    const request = ctx.session.pendingApprovals.get(sessionId);

    if (!request) {
      await ctx.answerCallbackQuery({
        text: 'Request expired or already processed',
        show_alert: true,
      });
      return;
    }

    try {
      // Send approval to relay
      await relay.submitApproval(sessionId, {
        approved: true,
        userId: ctx.from!.id.toString(),
        timestamp: Date.now(),
      });

      // Remove from pending
      ctx.session.pendingApprovals.delete(sessionId);

      // Update message
      const approvedMessage = `
*Transaction Approved*

To: \`${request.to}\`
Amount: ${formatEther(request.value)} ETH
Chain: ${request.chain}

_Processing transaction..._
      `;

      await ctx.editMessageText(approvedMessage, { parse_mode: 'Markdown' });
      await ctx.answerCallbackQuery({ text: 'Approved!' });

      // In production, wait for tx hash and update message
      setTimeout(async () => {
        try {
          const finalMessage = `
*Transaction Confirmed*

To: \`${request.to}\`
Amount: ${formatEther(request.value)} ETH
Chain: ${request.chain}

[View on Etherscan](https://etherscan.io/tx/0x...)
          `;
          await ctx.editMessageText(finalMessage, {
            parse_mode: 'Markdown',
            link_preview_options: { is_disabled: true },
          });
        } catch {
          // Message might be too old to edit
        }
      }, 3000);
    } catch (error) {
      console.error('Approval error:', error);
      await ctx.answerCallbackQuery({
        text: 'Error submitting approval',
        show_alert: true,
      });
    }
  });

  // Handle reject button
  bot.callbackQuery(/^reject:(.+)$/, async (ctx: CallbackContext) => {
    const sessionId = ctx.match![1];
    const request = ctx.session.pendingApprovals.get(sessionId);

    if (!request) {
      await ctx.answerCallbackQuery({
        text: 'Request expired or already processed',
        show_alert: true,
      });
      return;
    }

    try {
      // Send rejection to relay
      await relay.submitApproval(sessionId, {
        approved: false,
        userId: ctx.from!.id.toString(),
        timestamp: Date.now(),
        reason: 'User rejected',
      });

      // Remove from pending
      ctx.session.pendingApprovals.delete(sessionId);

      // Update message
      const rejectedMessage = `
*Transaction Rejected*

To: \`${request.to}\`
Amount: ${formatEther(request.value)} ETH
Chain: ${request.chain}

_The AI agent has been notified._
      `;

      await ctx.editMessageText(rejectedMessage, { parse_mode: 'Markdown' });
      await ctx.answerCallbackQuery({ text: 'Rejected' });
    } catch (error) {
      console.error('Rejection error:', error);
      await ctx.answerCallbackQuery({
        text: 'Error submitting rejection',
        show_alert: true,
      });
    }
  });

  // Handle details button
  bot.callbackQuery(/^details:(.+)$/, async (ctx: CallbackContext) => {
    const sessionId = ctx.match![1];
    const request = ctx.session.pendingApprovals.get(sessionId);

    if (!request) {
      await ctx.answerCallbackQuery({
        text: 'Request not found',
        show_alert: true,
      });
      return;
    }

    const detailsMessage = `
*Transaction Details*

*From Agent:* ${request.agentName}
*To:* \`${request.to}\`
*Amount:* ${formatEther(request.value)} ETH
*Chain:* ${request.chain} (ID: ${request.chainId})
*Gas Estimate:* ~${request.gasEstimate || '21,000'} gas
*Requested:* ${new Date(request.timestamp).toLocaleString()}

*Session ID:* \`${sessionId.slice(0, 8)}...\`
    `;

    await ctx.answerCallbackQuery();
    await ctx.reply(detailsMessage, { parse_mode: 'Markdown' });
  });

  // Fallback handler for unknown callback queries (recommended by grammY)
  bot.on('callback_query:data', async (ctx: CallbackContext) => {
    console.log('Unknown button event with payload:', ctx.callbackQuery!.data);
    await ctx.answerCallbackQuery({
      text: 'Unknown action',
    });
  });
}

function formatEther(wei: string): string {
  const value = BigInt(wei);
  const eth = Number(value) / 1e18;
  return eth.toFixed(4);
}
