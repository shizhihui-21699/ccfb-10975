import type { Store } from '../db/store.ts';
import type { ServerConfig } from '../config.ts';
import type { ClientRecord } from '../types.ts';
import { invalidClient } from '../util/errors.ts';
import { hashSecret, randomToken, verifySecret } from '../util/crypto.ts';

export type ClientAuthMethod = 'none' | 'client_secret_basic' | 'client_secret_post';

export interface AuthenticatedClient {
  client: ClientRecord;
  method: ClientAuthMethod;
}

/**
 * Parses client credentials from the Authorization header (RFC 6749 §2.3.1)
 * or from the form body. Basic credentials are form-urlencoded before being
 * base64-encoded, so they must be decoded in that order.
 */
export function extractClientCredentials(
  authorizationHeader: string | undefined,
  body: Record<string, string>,
): { clientId: string; secret: string } | null {
  if (authorizationHeader !== undefined) {
    const match = /^Basic\s+(\S+)\s*$/i.exec(authorizationHeader);
    if (!match) return null;
    let decoded: string;
    try {
      decoded = Buffer.from(match[1] ?? '', 'base64').toString('utf8');
    } catch {
      return null;
    }
    const separator = decoded.indexOf(':');
    if (separator === -1) return null;
    try {
      return {
        clientId: decodeURIComponent(decoded.slice(0, separator).replace(/\+/g, ' ')),
        secret: decodeURIComponent(decoded.slice(separator + 1).replace(/\+/g, ' ')),
      };
    } catch {
      return null;
    }
  }

  const clientId = body.client_id;
  const secret = body.client_secret;
  if (clientId === undefined || secret === undefined) return null;
  return { clientId, secret };
}

/**
 * Authenticates a client for the token, introspection and revocation
 * endpoints. Always performs a comparable amount of hashing work so an
 * attacker cannot enumerate client ids by timing.
 */
export function authenticateClient(
  store: Store,
  config: ServerConfig,
  authorizationHeader: string | undefined,
  body: Record<string, string>,
  dummyHash: string,
): AuthenticatedClient {
  const usedBasic = authorizationHeader !== undefined;
  const credentials = extractClientCredentials(authorizationHeader, body);

  const clientId = credentials?.clientId ?? body.client_id ?? '';
  const client = clientId === '' ? null : store.getClient(clientId);

  if (!client) {
    verifySecret(randomToken(24), dummyHash, config.scrypt);
    throw invalidClient('client authentication failed');
  }

  const presentedSecret = credentials?.secret ?? '';
  const secretHashForComparison = client.secretHash ?? dummyHash;
  const secretMatched = verifySecret(presentedSecret === '' ? randomToken(24) : presentedSecret, secretHashForComparison, config.scrypt);

  if (client.disabled) {
    throw invalidClient('client is disabled');
  }

  if (client.tokenEndpointAuthMethod === 'none') {
    if (usedBasic || presentedSecret !== '') {
      // RFC 6749 §2.3: a public client must not present a secret.
      throw invalidClient('this client must not authenticate with a client secret');
    }
    return { client, method: 'none' };
  }

  if (!credentials) {
    throw invalidClient('client authentication is required');
  }

  const actualMethod: ClientAuthMethod = usedBasic ? 'client_secret_basic' : 'client_secret_post';
  if (actualMethod !== client.tokenEndpointAuthMethod) {
    throw invalidClient(
      `client is registered for ${client.tokenEndpointAuthMethod} but used ${actualMethod}`,
    );
  }

  if (!secretMatched) {
    throw invalidClient('client authentication failed');
  }

  return { client, method: actualMethod };
}

/** Pre-computed hash for the constant-work path above. */
export function makeDummyHash(config: ServerConfig): string {
  return hashSecret(randomToken(24), config.scrypt);
}
