import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createApp } from './app.ts';
import { Store } from './db/store.ts';
import { loadConfig } from './config.ts';
import { bootstrapDemoData } from './oauth/clients.ts';
import { logger } from './util/logging.ts';

const databasePath = process.env.DATABASE_PATH ?? './data/oauth.sqlite';
mkdirSync(dirname(databasePath), { recursive: true });

const config = loadConfig({ logger });
const store = new Store(databasePath);

const bootstrap = bootstrapDemoData(store, config, Date.now());
if (bootstrap) {
  logger.warn('bootstrap_credentials_generated', {
    note: 'These credentials are shown once. Set DATABASE_PATH to a fresh file to regenerate.',
    users: bootstrap.users.map((user) => ({ username: user.username, password: user.password, role: user.role })),
    clients: bootstrap.clients.map((client) => ({
      id: client.id,
      secret: client.secret,
      name: client.name,
    })),
  });
}

const app = createApp({ store, config });
const port = Number(process.env.PORT ?? 8080);

const server = app.listen(port, () => {
  logger.info('server_started', { port, issuer: config.issuer });
});

// Periodic cleanup of expired rows; these never affect a live security check.
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
const cleanupTimer = setInterval(() => {
  try {
    store.cleanup(Date.now(), config.replayMarkerTtlSeconds * 1000);
  } catch (error) {
    logger.error('cleanup_failed', { message: error instanceof Error ? error.message : String(error) });
  }
}, CLEANUP_INTERVAL_MS);
cleanupTimer.unref();

function shutdown(signal: string): void {
  logger.info('shutting_down', { signal });
  clearInterval(cleanupTimer);
  server.close(() => {
    store.close();
    process.exit(0);
  });
  // Do not hang forever on a stuck connection.
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
