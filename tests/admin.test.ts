import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  startTestServer,
  BrowserSession,
  obtainAuthorizationCode,
  PUBLIC_REDIRECT,
  TEST_PASSWORD,
  type TestServer,
} from './helpers/server.ts';
import { DpopKey, pkcePair } from './helpers/dpop.ts';
import { tokenRequest } from './helpers/token.ts';

let server: TestServer;

before(async () => {
  server = await startTestServer();
});

after(async () => {
  await server.close();
});

async function adminSession(): Promise<BrowserSession> {
  const session = new BrowserSession(server.baseUrl);
  await session.login();
  return session;
}

describe('admin UI', () => {
  test('redirects anonymous visitors to the login page', async () => {
    const session = new BrowserSession(server.baseUrl);
    const response = await session.request('/admin');
    assert.equal(response.status, 302);
    assert.match(response.headers.get('location') ?? '', /^\/login/);
  });

  test('rejects a wrong password without revealing the username', async () => {
    const session = new BrowserSession(server.baseUrl);
    const response = await session.request('/login', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: 'alice', password: 'wrong' }).toString(),
    });
    assert.equal(response.status, 401);
    const html = await response.text();
    assert.match(html, /Invalid username or password/);
    assert.equal(response.headers.getSetCookie().length, 0);
  });

  test('lists clients with their metadata', async () => {
    const session = await adminSession();
    const response = await session.request('/admin');
    assert.equal(response.status, 200);
    const html = await response.text();
    assert.match(html, /Registered clients/);
    assert.match(html, new RegExp(server.publicClient.id));
    assert.match(html, /Public Client/);
  });

  test('shows a client detail page with token families', async () => {
    const key = await DpopKey.generate();
    const browser = await adminSession();
    const pkce = pkcePair();
    const code = await obtainAuthorizationCode({
      session: browser,
      clientId: server.publicClient.id,
      redirectUri: PUBLIC_REDIRECT,
      challenge: pkce.challenge,
      dpopJkt: await key.thumbprint(),
    });
    await tokenRequest(server, {
      form: {
        grant_type: 'authorization_code',
        code,
        redirect_uri: PUBLIC_REDIRECT,
        code_verifier: pkce.verifier,
      },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopKey: key,
    });

    const response = await browser.request(`/admin/clients/${server.publicClient.id}`);
    assert.equal(response.status, 200);
    const html = await response.text();
    assert.match(html, /Token families/);
    assert.match(html, /Redirect URIs/);
  });

  test('tokens page shows live families and replay detections', async () => {
    const session = await adminSession();
    const response = await session.request('/admin/tokens');
    assert.equal(response.status, 200);
    const html = await response.text();
    assert.match(html, /Token families/);
    assert.match(html, /Replay detections/);
  });

  test('audit page lists security events', async () => {
    const session = await adminSession();
    const response = await session.request('/admin/audit');
    assert.equal(response.status, 200);
    const html = await response.text();
    assert.match(html, /Audit log/);
    assert.match(html, /authorization_code_issued/);
  });

  test('creates a client from the admin form and reveals the secret once', async () => {
    const session = await adminSession();
    const page = await session.request('/admin');
    const html = await page.text();
    const csrf = /name="csrf_token" value="([^"]+)"/.exec(html)?.[1] ?? '';
    assert.ok(csrf);

    const response = await session.request('/admin/clients', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        csrf_token: csrf,
        client_name: 'Admin Created Client',
        redirect_uris: 'https://admin-created.example.com/callback',
        token_endpoint_auth_method: 'client_secret_basic',
        scope: 'openid profile offline_access',
      }).toString(),
    });
    assert.equal(response.status, 201);
    const body = await response.text();
    assert.match(body, /Client secret/);
  });

  test('admin form rejects an invalid redirect URI', async () => {
    const session = await adminSession();
    const page = await session.request('/admin');
    const csrf = /name="csrf_token" value="([^"]+)"/.exec(await page.text())?.[1] ?? '';
    const response = await session.request('/admin/clients', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        csrf_token: csrf,
        client_name: 'Bad Redirect',
        redirect_uris: 'http://not-loopback.example.com/cb',
        token_endpoint_auth_method: 'client_secret_basic',
      }).toString(),
    });
    assert.equal(response.status, 400);
    assert.match(await response.text(), /invalid_redirect_uri/);
  });

  test('logout invalidates the session', async () => {
    const session = await adminSession();
    const before = await session.request('/admin');
    assert.equal(before.status, 200);

    await session.request('/logout', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: '',
    });
    const after = await session.request('/admin');
    assert.equal(after.status, 302);
  });

  test('a non-admin user is denied', async () => {
    // Promote a fresh user as non-admin.
    const { hashSecret, newId } = await import('../src/util/crypto.ts');
    const userId = newId();
    server.store.insertUser(
      {
        id: userId,
        username: 'bob',
        passwordHash: hashSecret(TEST_PASSWORD, server.config.scrypt),
        displayName: 'Bob',
        role: 'user',
      },
      Date.now(),
    );
    const session = new BrowserSession(server.baseUrl);
    const login = await session.request('/login', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: 'bob', password: TEST_PASSWORD }).toString(),
    });
    assert.equal(login.status, 302);
    const response = await session.request('/admin');
    assert.equal(response.status, 403);
  });
});

describe('discovery metadata', () => {
  test('advertises the endpoints and PKCE/DPoP capabilities', async () => {
    const response = await fetch(`${server.baseUrl}/.well-known/oauth-authorization-server`);
    assert.equal(response.status, 200);
    const body = (await response.json()) as Record<string, unknown>;
    assert.equal(body.issuer, server.config.issuer);
    assert.equal(body.authorization_endpoint, `${server.baseUrl}/authorize`);
    assert.equal(body.token_endpoint, `${server.baseUrl}/token`);
    assert.equal(body.introspection_endpoint, `${server.baseUrl}/introspect`);
    assert.equal(body.revocation_endpoint, `${server.baseUrl}/revoke`);
    assert.deepEqual(body.code_challenge_methods_supported, ['S256']);
    assert.equal(body.dpop_bound_access_tokens, true);
    assert.deepEqual(body.grant_types_supported, ['authorization_code', 'refresh_token']);
  });
});
