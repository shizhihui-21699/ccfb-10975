import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApp } from '../../src/app.ts';
import { Store } from '../../src/db/store.ts';
import { loadConfig, type ServerConfig } from '../../src/config.ts';
import { silentLogger } from '../../src/util/logging.ts';
import { hashSecret, newId, randomToken } from '../../src/util/crypto.ts';
import { DEFAULT_SCOPES } from '../../src/oauth/clients.ts';
import type { ClientRecord } from '../../src/types.ts';

export const TEST_PASSWORD = 'test-password-123';
export const PUBLIC_REDIRECT = 'https://app.example.com/callback';
export const CONFIDENTIAL_REDIRECT = 'https://confidential.example.com/callback';

export interface TestServer {
  baseUrl: string;
  store: Store;
  config: ServerConfig;
  publicClient: ClientRecord;
  confidentialClient: ClientRecord;
  confidentialSecret: string;
  confidentialOptionalDpop: ClientRecord;
  confidentialOptionalDpopSecret: string;
  publicSecretlessClient: ClientRecord;
  userId: string;
  close(): Promise<void>;
}

export interface TestServerOptions {
  dpopIatToleranceSeconds?: number;
  dpopIatFutureSkewSeconds?: number;
  accessTokenTtlSeconds?: number;
  authorizationCodeTtlSeconds?: number;
  registrationEnabled?: boolean;
}

/**
 * Boots the real app on an ephemeral port with an in-memory database, using
 * deliberately cheap scrypt parameters so tests stay fast.
 */
export async function startTestServer(options: TestServerOptions = {}): Promise<TestServer> {
  const config = loadConfig({
    logger: silentLogger(),
    adminSessionSecret: 'test-session-secret',
    scrypt: { N: 1024, r: 8, p: 1 },
    adminEnabled: true,
    registrationEnabled: options.registrationEnabled ?? true,
    accessTokenTtlSeconds: options.accessTokenTtlSeconds ?? 3600,
    authorizationCodeTtlSeconds: options.authorizationCodeTtlSeconds ?? 60,
    dpopIatToleranceSeconds: options.dpopIatToleranceSeconds ?? 60,
    dpopIatFutureSkewSeconds: options.dpopIatFutureSkewSeconds ?? 5,
  });

  const store = new Store(':memory:');
  const now = Date.now();

  const userId = newId();
  store.insertUser(
    {
      id: userId,
      username: 'alice',
      passwordHash: hashSecret(TEST_PASSWORD, config.scrypt),
      displayName: 'Alice',
      role: 'admin',
    },
    now,
  );

  const confidentialSecret = randomToken(32);
  const confidentialClient = store.insertClient(
    {
      id: 'confidential-client',
      name: 'Confidential Client',
      secretHash: hashSecret(confidentialSecret, config.scrypt),
      redirectUris: [CONFIDENTIAL_REDIRECT],
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      scopes: DEFAULT_SCOPES,
      tokenEndpointAuthMethod: 'client_secret_basic',
      requireDpop: true,
    },
    now,
  );

  const publicClient = store.insertClient(
    {
      id: 'public-client',
      name: 'Public Client',
      secretHash: null,
      redirectUris: [PUBLIC_REDIRECT, 'http://localhost:7777/callback'],
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      scopes: DEFAULT_SCOPES,
      tokenEndpointAuthMethod: 'none',
      requireDpop: true,
    },
    now,
  );

  // A public client that does not require DPoP: used to prove optional-DPoP
  // behaviour and that refresh tokens for public clients still need a key.
  const publicSecretlessClient = store.insertClient(
    {
      id: 'public-optional-dpop',
      name: 'Public Client (optional DPoP)',
      secretHash: null,
      redirectUris: ['https://optional.example.com/callback'],
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      scopes: DEFAULT_SCOPES,
      tokenEndpointAuthMethod: 'none',
      requireDpop: false,
    },
    now,
  );

  // A confidential client where DPoP is optional: proves that a
  // non-DPoP request still yields a Bearer token.
  const confidentialOptionalDpopSecret = randomToken(32);
  const confidentialOptionalDpop = store.insertClient(
    {
      id: 'confidential-optional-dpop',
      name: 'Confidential Client (optional DPoP)',
      secretHash: hashSecret(confidentialOptionalDpopSecret, config.scrypt),
      redirectUris: ['https://optional.example.com/confidential-callback'],
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      scopes: DEFAULT_SCOPES,
      tokenEndpointAuthMethod: 'client_secret_basic',
      requireDpop: false,
    },
    now,
  );

  // (the app is assembled after bind below)

  // The issuer must match the actual listening address, which is only known
  // after bind, so re-assemble the app once the port is assigned.
  const server: Server = createServer();
  let handler: ((req: IncomingMessage, res: ServerResponse) => void) | null = null;
  server.on('request', (req, res) => {
    if (handler === null) {
      res.statusCode = 503;
      res.end();
      return;
    }
    handler(req, res);
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}`;
  config.baseUrl = baseUrl;
  config.issuer = baseUrl;
  handler = createApp({ store, config }) as unknown as typeof handler;

  return {
    baseUrl,
    store,
    config,
    publicClient,
    confidentialClient,
    confidentialSecret,
    confidentialOptionalDpop,
    confidentialOptionalDpopSecret,
    publicSecretlessClient,
    userId,
    async close() {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
      store.close();
    },
  };
}

/** A browser-ish session holder: keeps cookies across requests. */
export class BrowserSession {
  private cookie = '';
  readonly baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  async request(path: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    if (this.cookie) headers.set('cookie', this.cookie);
    const response = await fetch(new URL(path, this.baseUrl), {
      ...init,
      headers,
      redirect: init.redirect ?? 'manual',
    });
    const setCookie = response.headers.getSetCookie();
    for (const entry of setCookie) {
      const pair = entry.split(';')[0] ?? '';
      if (pair.startsWith('oauth_session=')) {
        this.cookie = pair.endsWith('=') ? '' : pair;
      }
    }
    return response;
  }

  async login(username = 'alice', password = TEST_PASSWORD): Promise<void> {
    const response = await this.request('/login', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username, password }).toString(),
    });
    if (response.status !== 302) {
      throw new Error(`login failed with status ${response.status}`);
    }
  }

  get sessionCookie(): string {
    return this.cookie;
  }
}

/** Extracts the CSRF token and pending id from a consent page. */
export function parseConsentPage(html: string): { csrf: string; pendingId: string } {
  const csrf = /name="csrf_token" value="([^"]+)"/.exec(html)?.[1];
  const pendingId = /name="pending_id" value="([^"]+)"/.exec(html)?.[1];
  if (!csrf || !pendingId) throw new Error('consent page did not contain the expected fields');
  return { csrf, pendingId };
}

/** Runs the consent dance and returns the authorization code. */
export async function obtainAuthorizationCode(params: {
  session: BrowserSession;
  clientId: string;
  redirectUri: string;
  challenge: string;
  scope?: string;
  state?: string;
  nonce?: string;
  dpopJkt?: string;
  expectConsent?: boolean;
}): Promise<string> {
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: params.clientId,
    redirect_uri: params.redirectUri,
    code_challenge: params.challenge,
    code_challenge_method: 'S256',
  });
  if (params.scope !== undefined) query.set('scope', params.scope);
  if (params.state !== undefined) query.set('state', params.state);
  if (params.nonce !== undefined) query.set('nonce', params.nonce);
  if (params.dpopJkt !== undefined) query.set('dpop_jkt', params.dpopJkt);

  const page = await params.session.request(`/authorize?${query.toString()}`);
  if (page.status !== 200) {
    throw new Error(`authorize failed: ${page.status} ${await page.text()}`);
  }
  const html = await page.text();
  const { csrf, pendingId } = parseConsentPage(html);
  const approved = await params.session.request('/authorize', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ pending_id: pendingId, csrf_token: csrf, decision: 'allow' }).toString(),
  });
  if (approved.status !== 302) {
    throw new Error(`consent failed: ${approved.status} ${await approved.text()}`);
  }
  const location = approved.headers.get('location');
  if (!location) throw new Error('consent response had no Location header');
  const code = new URL(location).searchParams.get('code');
  if (!code) throw new Error(`no code in redirect: ${location}`);
  return code;
}

export function makeTempDir(): { path: string; cleanup(): void } {
  const path = mkdtempSync(join(tmpdir(), 'oauth-test-'));
  return {
    path,
    cleanup() {
      rmSync(path, { recursive: true, force: true });
    },
  };
}
