import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, BrowserSession, PUBLIC_REDIRECT, type TestServer } from './helpers/server.ts';
import { pkcePair } from './helpers/dpop.ts';

let server: TestServer;

before(async () => {
  server = await startTestServer();
  server.store.recordAudit('test_start', Date.now(), {});
});

after(async () => {
  await server.close();
});

async function register(payload: Record<string, unknown>): Promise<Response> {
  return fetch(`${server.baseUrl}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

const VALID = {
  client_name: 'Registered App',
  redirect_uris: ['https://registered.example.com/callback'],
};

describe('dynamic client registration (RFC 7591)', () => {
  test('registers a confidential client and returns a one-time secret', async () => {
    const response = await register({ ...VALID, token_endpoint_auth_method: 'client_secret_basic' });
    assert.equal(response.status, 201);
    const body = (await response.json()) as Record<string, unknown>;
    assert.equal(typeof body.client_id, 'string');
    assert.equal(typeof body.client_secret, 'string');
    assert.equal(body.client_secret_expires_at, 0);
    assert.deepEqual(body.redirect_uris, VALID.redirect_uris);
    assert.equal(response.headers.get('location'), `/admin/clients/${String(body.client_id)}`);

    // Only the hash is stored.
    const stored = server.store.getClient(String(body.client_id));
    assert.ok(stored?.secretHash);
    assert.notEqual(stored?.secretHash, body.client_secret);
  });

  test('registers a public client with no secret and forces DPoP', async () => {
    const response = await register({ ...VALID, token_endpoint_auth_method: 'none' });
    assert.equal(response.status, 201);
    const body = (await response.json()) as Record<string, unknown>;
    assert.equal(body.client_secret, undefined);

    const stored = server.store.getClient(String(body.client_id));
    assert.equal(stored?.secretHash, null);
    assert.equal(stored?.requireDpop, true);
  });

  test('requires redirect_uris', async () => {
    const response = await register({ client_name: 'No redirects' });
    assert.equal(response.status, 400);
    const body = (await response.json()) as Record<string, unknown>;
    assert.equal(body.error, 'invalid_redirect_uri');
  });

  test('rejects a non-array redirect_uris', async () => {
    const response = await register({ redirect_uris: 'https://one.example.com/cb' });
    assert.equal(response.status, 400);
    assert.equal(((await response.json()) as Record<string, unknown>).error, 'invalid_redirect_uri');
  });

  test('rejects duplicate redirect URIs', async () => {
    const response = await register({
      redirect_uris: ['https://dup.example.com/cb', 'https://dup.example.com/cb'],
    });
    assert.equal(response.status, 400);
    assert.equal(((await response.json()) as Record<string, unknown>).error, 'invalid_redirect_uri');
  });

  test('rejects a fragment in a redirect URI', async () => {
    const response = await register({ redirect_uris: ['https://frag.example.com/cb#section'] });
    assert.equal(response.status, 400);
    assert.equal(((await response.json()) as Record<string, unknown>).error, 'invalid_redirect_uri');
  });

  test('rejects a wildcard redirect URI', async () => {
    const response = await register({ redirect_uris: ['https://wild.example.com/*'] });
    assert.equal(response.status, 400);
  });

  test('rejects plain http for a non-loopback host', async () => {
    const response = await register({ redirect_uris: ['http://insecure.example.com/cb'] });
    assert.equal(response.status, 400);
    assert.match(String(((await response.json()) as Record<string, unknown>).error_description), /loopback/);
  });

  test('allows plain http for loopback hosts', async () => {
    for (const uri of ['http://localhost:3000/cb', 'http://127.0.0.1:8080/cb', 'http://[::1]:9000/cb']) {
      const response = await register({ redirect_uris: [uri] });
      assert.equal(response.status, 201, `${uri} should be accepted`);
    }
  });

  test('allows a native-app private-use scheme with a path', async () => {
    const response = await register({ redirect_uris: ['com.example.app:/oauth/callback'] });
    assert.equal(response.status, 201);
  });

  test('rejects a dangerous scheme', async () => {
    for (const uri of ['javascript:alert(1)', 'data:text/html,x', 'file:///etc/passwd']) {
      const response = await register({ redirect_uris: [uri] });
      assert.equal(response.status, 400, `${uri} should be rejected`);
    }
  });

  test('rejects userinfo in a redirect URI', async () => {
    const response = await register({ redirect_uris: ['https://user:pass@evil.example.com/cb'] });
    assert.equal(response.status, 400);
  });

  test('rejects an unsupported grant type', async () => {
    const response = await register({ ...VALID, grant_types: ['password'] });
    assert.equal(response.status, 400);
    const body = (await response.json()) as Record<string, unknown>;
    assert.equal(body.error, 'invalid_client_metadata');
  });

  test('rejects response_type code without the authorization_code grant', async () => {
    const response = await register({ ...VALID, grant_types: ['refresh_token'] });
    assert.equal(response.status, 400);
    assert.equal(((await response.json()) as Record<string, unknown>).error, 'invalid_client_metadata');
  });

  test('rejects a duplicate client_id', async () => {
    const clientId = 'taken-client-id';
    const first = await register({ ...VALID, client_id: clientId });
    assert.equal(first.status, 201);
    const second = await register({ ...VALID, client_id: clientId });
    assert.equal(second.status, 400);
    assert.match(String(((await second.json()) as Record<string, unknown>).error_description), /already in use/);
  });

  test('rejects a non-JSON content type', async () => {
    const response = await fetch(`${server.baseUrl}/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'redirect_uris=https%3A%2F%2Fexample.com%2Fcb',
    });
    assert.equal(response.status, 415);
  });
});

describe('redirect URI matching at the authorization endpoint', () => {
  test('exact match is required', async () => {
    const session = new BrowserSession(server.baseUrl);
    await session.login();
    const pkce = pkcePair();
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: server.publicClient.id,
      redirect_uri: 'https://app.example.com/callback/extra',
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
    });
    const response = await session.request(`/authorize?${query.toString()}`);
    // Unregistered redirect URI: never redirect there, show an error page.
    assert.equal(response.status, 400);
    assert.equal(response.headers.get('location'), null);
  });

  test('a loopback redirect may vary its port', async () => {
    const session = new BrowserSession(server.baseUrl);
    await session.login();
    const pkce = pkcePair();
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: server.publicClient.id,
      redirect_uri: 'http://localhost:54321/callback',
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
    });
    const response = await session.request(`/authorize?${query.toString()}`);
    assert.equal(response.status, 200);
  });

  test('a non-loopback redirect may not vary its port', async () => {
    const session = new BrowserSession(server.baseUrl);
    await session.login();
    const pkce = pkcePair();
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: server.confidentialClient.id,
      redirect_uri: 'https://confidential.example.com:8443/callback',
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
    });
    const response = await session.request(`/authorize?${query.toString()}`);
    assert.equal(response.status, 400);
  });

  test('an unknown client is rejected without redirecting', async () => {
    const session = new BrowserSession(server.baseUrl);
    await session.login();
    const pkce = pkcePair();
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: 'no-such-client',
      redirect_uri: PUBLIC_REDIRECT,
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
    });
    const response = await session.request(`/authorize?${query.toString()}`);
    assert.equal(response.status, 400);
    assert.equal(response.headers.get('location'), null);
  });

  test('an unauthenticated user is sent to login and returned to the request', async () => {
    const session = new BrowserSession(server.baseUrl);
    const pkce = pkcePair();
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: server.publicClient.id,
      redirect_uri: PUBLIC_REDIRECT,
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
      state: 'roundtrip',
    });
    const response = await session.request(`/authorize?${query.toString()}`);
    assert.equal(response.status, 302);
    const location = response.headers.get('location') ?? '';
    assert.match(location, /^\/login\?next=/);
    const next = new URLSearchParams(location.split('?')[1] ?? '').get('next') ?? '';
    assert.equal(new URL(next, server.baseUrl).searchParams.get('state'), 'roundtrip');
  });

  test('denying consent produces access_denied with state', async () => {
    const session = new BrowserSession(server.baseUrl);
    await session.login();
    const pkce = pkcePair();
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: server.publicClient.id,
      redirect_uri: PUBLIC_REDIRECT,
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
      state: 'denied-state',
    });
    const page = await session.request(`/authorize?${query.toString()}`);
    const html = await page.text();
    const csrf = /name="csrf_token" value="([^"]+)"/.exec(html)?.[1] ?? '';
    const pendingId = /name="pending_id" value="([^"]+)"/.exec(html)?.[1] ?? '';

    const denied = await session.request('/authorize', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ pending_id: pendingId, csrf_token: csrf, decision: 'deny' }).toString(),
    });
    assert.equal(denied.status, 302);
    const location = new URL(denied.headers.get('location') ?? '');
    assert.equal(location.searchParams.get('error'), 'access_denied');
    assert.equal(location.searchParams.get('state'), 'denied-state');
  });

  test('a consent form without a CSRF token is rejected', async () => {
    const session = new BrowserSession(server.baseUrl);
    await session.login();
    const pkce = pkcePair();
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: server.publicClient.id,
      redirect_uri: PUBLIC_REDIRECT,
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
    });
    const page = await session.request(`/authorize?${query.toString()}`);
    const html = await page.text();
    const pendingId = /name="pending_id" value="([^"]+)"/.exec(html)?.[1] ?? '';

    const forged = await session.request('/authorize', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ pending_id: pendingId, decision: 'allow' }).toString(),
    });
    assert.equal(forged.status, 400);
  });
});
