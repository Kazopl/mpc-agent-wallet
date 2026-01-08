/**
 * MPC Wallet Telegram Bot
 *
 * Enables users to approve wallet transactions via Telegram.
 */

import 'dotenv/config';
import { createBot } from './bot.js';
import { RelayClient } from './relay/client.js';

async function main() {
  console.log('Starting MPC Wallet Telegram Bot...\n');

  // Validate environment
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  if (!botToken) {
    console.error('[ERROR] TELEGRAM_BOT_TOKEN not set');
    process.exit(1);
  }

  const relayUrl = process.env.RELAY_URL;
  if (!relayUrl) {
    console.error('[ERROR] RELAY_URL not set');
    process.exit(1);
  }

  // Parse allowed user IDs
  const allowedUserIds = process.env.ALLOWED_USER_IDS
    ?.split(',')
    .map((id) => parseInt(id.trim(), 10))
    .filter((id) => !isNaN(id)) ?? [];

  console.log(`Allowed users: ${allowedUserIds.length > 0 ? allowedUserIds.join(', ') : 'all'}`);

  // Create relay client
  const relay = new RelayClient(relayUrl);

  // Create and start bot
  const bot = createBot({
    token: botToken,
    relay,
    allowedUserIds,
  });

  // Connect to relay
  console.log('Connecting to relay service...');
  await relay.connect();
  console.log('[OK] Connected to relay\n');

  // Start bot
  console.log('Starting Telegram bot...');
  bot.start({
    onStart: (info) => {
      console.log(`[OK] Bot started: @${info.username}`);
      console.log('\nSend /start to the bot to begin\n');
    },
  });

  // Handle shutdown
  process.on('SIGINT', async () => {
    console.log('\nShutting down...');
    await relay.disconnect();
    bot.stop();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    console.log('\nShutting down...');
    await relay.disconnect();
    bot.stop();
    process.exit(0);
  });
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
