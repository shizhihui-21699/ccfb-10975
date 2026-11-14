import type { Store } from '../db/store.ts';
import type { ClientRecord, UserRecord } from '../types.ts';
import type { ServerConfig } from '../config.ts';
import { hashSecret, newId, randomToken, sha256Base64Url, verifySecret } from '../util/crypto.ts';
import type { NormalizedRegistration } from './registration.ts';

export const DEFAULT_SCOPES = ['openid', 'profile', 'email', 'offline_access'];

export interface BootstrapResult {
  users: Array<{ username: string; password: string; role: 'user' | 'admin' }>;
  clients: Array<{ id: string; secret: string | null; name: string }>;
}

/**
 * Creates the demo user and a set of example clients on an empty database.
 * Returns the generated plaintext credentials exactly once; they are not
 * recoverable afterwards (only hashes are stored).
 */
export function bootstrapDemoData(
  store: Store,
  config: ServerConfig,
  now: number,
): BootstrapResult | null {
  if (store.countUsers() > 0) return null;

  const users: BootstrapResult['users'] = [];
  for (const [username, role] of [
    ['alice', 'user'],
    ['admin', 'admin'],
  ] as const) {
    const password = randomToken(18);
    store.insertUser(
      {
        id: newId(),
        username,
        passwordHash: hashSecret(password, config.scrypt),
        displayName: username === 'admin' ? 'Administrator' : 'Alice Example',
        role,
      },
      now,
    );
    users.push({ username, password, role });
  }

  const clients: BootstrapResult['clients'] = [];
  const definitions: Array<{
    name: string;
    redirectUris: string[];
    authMethod: 'none' | 'client_secret_basic';
    grantTypes: string[];
    requireDpop: boolean;
    scopes: string[];
  }> = [
    {
      name: 'Internal Portal (public, PKCE + DPoP)',
      redirectUris: ['http://localhost:3000/callback', 'https://portal.example.com/callback'],
      authMethod: 'none',
      grantTypes: ['authorization_code', 'refresh_token'],
      requireDpop: true,
      scopes: DEFAULT_SCOPES,
    },
    {
      name: 'Admin Console (confidential)',
      redirectUris: ['https://admin.example.com/callback'],
      authMethod: 'client_secret_basic',
      grantTypes: ['authorization_code', 'refresh_token'],
      requireDpop: true,
      scopes: DEFAULT_SCOPES,
    },
    {
      name: 'Reporting Batch Job (confidential, access only)',
      redirectUris: ['https://reports.example.com/callback'],
      authMethod: 'client_secret_basic',
      grantTypes: ['authorization_code'],
      requireDpop: false,
      scopes: ['profile', 'email'],
    },
  ];

  for (const definition of definitions) {
    const id = `${definition.name.split(' ')[0]?.toLowerCase() ?? 'client'}-${randomToken(6)}`;
    const secret = definition.authMethod === 'none' ? null : randomToken(32);
    store.insertClient(
      {
        id,
        name: definition.name,
        secretHash: secret ? hashSecret(secret, config.scrypt) : null,
        redirectUris: definition.redirectUris,
        grantTypes: definition.grantTypes,
        responseTypes: ['code'],
        scopes: definition.scopes,
        tokenEndpointAuthMethod: definition.authMethod,
        requireDpop: definition.requireDpop,
      },
      now,
    );
    clients.push({ id, secret, name: definition.name });
  }

  return { users, clients };
}

export function createRegisteredClient(
  store: Store,
  config: ServerConfig,
  registration: NormalizedRegistration,
  requestedId: string | undefined,
  now: number,
): { client: ClientRecord; plaintextSecret: string | null } {
  const id = requestedId ?? newId();
  const plaintextSecret =
    registration.tokenEndpointAuthMethod === 'none' ? null : randomToken(32);
  const client = store.insertClient(
    {
      id,
      name: registration.clientName,
      secretHash: plaintextSecret ? hashSecret(plaintextSecret, config.scrypt) : null,
      redirectUris: registration.redirectUris,
      grantTypes: registration.grantTypes,
      responseTypes: registration.responseTypes,
      scopes: registration.scope,
      tokenEndpointAuthMethod: registration.tokenEndpointAuthMethod,
      requireDpop: registration.requireDpop,
    },
    now,
  );
  return { client, plaintextSecret };
}

/** Creates a session cookie value and its stored digest. */
export function createSession(now: number, ttlSeconds: number): {
  sessionId: string;
  idHash: string;
  expiresAt: number;
} {
  const sessionId = randomToken(32);
  return { sessionId, idHash: sha256Base64Url(sessionId), expiresAt: now + ttlSeconds * 1000 };
}

export function verifyPassword(user: UserRecord, password: string, config: ServerConfig): boolean {
  return verifySecret(password, user.passwordHash, config.scrypt);
}

/**
 * Performs a comparable password-hash computation for a username that does
 * not exist, so login timing cannot reveal whether an account exists.
 */
export function verifyPasswordForUnknownUser(password: string, config: ServerConfig): void {
  hashSecret(password, config.scrypt);
}
