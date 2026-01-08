/**
 * Telegram Bot Command Handlers
 */

import type { Bot } from 'grammy';
import type { BotContext } from '../bot.js';
import type { RelayClient } from '../relay/client.js';

export function setupCommandHandlers(bot: Bot<BotContext>, relay: RelayClient): void {
  // /start command
  bot.command('start', async (ctx) => {
    const welcomeMessage = `
*MPC Wallet Approval Bot*

Welcome! I help you approve transactions from your AI agent's wallet.

*How it works:*
1. Your AI agent requests a transaction
2. I notify you with the details
3. You approve or reject with one tap
4. The transaction executes (if approved)

*Commands:*
/status - Check pending approvals
/history - View recent transactions
/settings - Configure notifications
/help - Show this message

*Ready to start?*
Your wallet is linked automatically when you receive your first approval request.
    `;

    await ctx.reply(welcomeMessage, { parse_mode: 'Markdown' });
  });

  // /help command
  bot.command('help', async (ctx) => {
    const helpMessage = `
*Available Commands*

/start - Initialize and show welcome
/status - Show pending approval requests
/history - View recent transactions
/settings - Configure notification preferences
/help - Show this help message

*About Approvals:*
- Approvals expire after 5 minutes
- You can approve or reject with buttons
- High-value transactions show warnings
- All actions are logged for your records

*Security Tips:*
- Verify recipient addresses carefully
- Check transaction amounts before approving
- Never share your bot access with others
    `;

    await ctx.reply(helpMessage, { parse_mode: 'Markdown' });
  });

  // /status command
  bot.command('status', async (ctx) => {
    const pending = ctx.session.pendingApprovals;

    if (pending.size === 0) {
      await ctx.reply('[OK] No pending approval requests.');
      return;
    }

    let message = `*Pending Approvals* (${pending.size})\n\n`;

    for (const [sessionId, request] of pending) {
      const age = Math.floor((Date.now() - request.timestamp) / 1000);
      const ageStr = age < 60 ? `${age}s` : `${Math.floor(age / 60)}m`;

      message += `- *${request.agentName}*\n`;
      message += `  To: \`${request.to.slice(0, 10)}...${request.to.slice(-8)}\`\n`;
      message += `  Amount: ${formatEther(request.value)} ETH\n`;
      message += `  Chain: ${request.chain}\n`;
      message += `  Age: ${ageStr}\n\n`;
    }

    message += '_Tap on the original message to approve/reject_';

    await ctx.reply(message, { parse_mode: 'Markdown' });
  });

  // /history command
  bot.command('history', async (ctx) => {
    // In production, fetch from relay/database
    const historyMessage = `
*Recent Transactions*

_No transactions yet._

Transaction history will appear here once you start approving transactions.
    `;

    await ctx.reply(historyMessage, { parse_mode: 'Markdown' });
  });

  // /settings command
  bot.command('settings', async (ctx) => {
    const settingsMessage = `
*Notification Settings*

Current settings:
- Notifications: Enabled
- Sound: Enabled
- High-value alerts: Enabled (>1 ETH)

_Settings customization coming soon._
    `;

    await ctx.reply(settingsMessage, { parse_mode: 'Markdown' });
  });

  // /wallet command
  bot.command('wallet', async (ctx) => {
    const address = ctx.session.linkedWalletAddress;

    if (!address) {
      await ctx.reply(
        'No wallet linked yet.\n\nYour wallet will be linked when you receive your first approval request.'
      );
      return;
    }

    await ctx.reply(
      `*Linked Wallet*\n\n\`${address}\`\n\n[View on Etherscan](https://etherscan.io/address/${address})`,
      { parse_mode: 'Markdown', link_preview_options: { is_disabled: true } }
    );
  });
}

function formatEther(wei: string): string {
  const value = BigInt(wei);
  const eth = Number(value) / 1e18;
  return eth.toFixed(4);
}
