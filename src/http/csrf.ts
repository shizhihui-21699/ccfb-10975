import { randomToken } from '../util/crypto.ts';
import type { ServerConfig } from '../config.ts';

const generatedSecrets = new WeakMap<ServerConfig, string>();

/**
 * Returns the CSRF signing secret, generating an ephemeral one for a config
 * that did not provide it (development default). The secret only ever needs
 * to be stable for the lifetime of the process.
 */
export function ensureSessionSecret(config: ServerConfig): string {
  if (config.adminSessionSecret !== '') return config.adminSessionSecret;
  let secret = generatedSecrets.get(config);
  if (secret === undefined) {
    secret = randomToken(32);
    generatedSecrets.set(config, secret);
  }
  return secret;
}
