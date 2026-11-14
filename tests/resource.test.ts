import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  startTestServer,
  BrowserSession,
  obtainAuthorizationCode,
  PUBLIC_REDIRECT,
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

async function issue(key: DpopKey, scope = 'openid profile email offline_access'): Promise<{
  accessToken: string;
  refreshToken: string;
}> {
  const session = new BrowserSession(server.baseUrl);
  await session.login();
  const pkce = pkcePair();
  const code = await obtainAuthorizationCode({
    session,
    clientId: server.publicClient.id,
    redirectUri: PUBLIC_REDIRECT,
    challenge: pkce.challenge,
    scope,
    dpopJkt: await key.thumbprint(),
  });
  const result = await tokenRequest(server, {
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
  assert.equal(result.status, 200);
  return { accessToken: String(result.body.access_token), refreshToken: String(result.body.refresh_token) };
}

async function userinfo(
  accessToken: string,
  proof: string | null,
): Promise<{ status: number; body: Record<string, unknown>; headers: Headers }> {
  const headers = new Headers({ authorization: `DPoP ${accessToken}` });
  if (proof !== null) headers.set('dpop', proof);
  const response = await fetch(`${server.baseUrl}/userinfo`, { headers });
  const body = (await response.json()) as Record<string, unknown>;
  return { status: response.status, body, headers: response.headers };
}

describe('resource server DPoP validation (RFC 9449 §7)', () => {
  test('accepts a token with a matching proof and ath', async () => {
    const key = await DpopKey.generate();
    const { accessToken } = await issue(key);
    const proof = await key.proof({ uri: `${server.baseUrl}/userinfo`, method: 'GET', accessToken });

    const response = await userinfo(accessToken, proof);
    assert.equal(response.status, 200);
    assert.equal(response.body.preferred_username, 'alice');
    assert.equal(response.body.email, 'alice@example.com');
    assert.equal(response.headers.get('cache-control'), 'no-store');
  });

  test('rejects a proof without ath', async () => {
    const key = await DpopKey.generate();
    const { accessToken } = await issue(key);
    const proof = await key.proof({ uri: `${server.baseUrl}/userinfo`, method: 'GET' });

    const response = await userinfo(accessToken, proof);
    assert.equal(response.status, 401);
    assert.equal(response.body.error, 'invalid_dpop_proof');
    assert.match(response.headers.get('www-authenticate') ?? '', /^DPoP /);
  });

  test('rejects an ath for a different access token', async () => {
    const key = await DpopKey.generate();
    const { accessToken } = await issue(key);
    const proof = await key.proof({
      uri: `${server.baseUrl}/userinfo`,
      method: 'GET',
      accessToken: 'a-different-token',
    });

    const response = await userinfo(accessToken, proof);
    assert.equal(response.status, 401);
    assert.equal(response.body.error, 'invalid_dpop_proof');
  });

  test('rejects a proof from a different key than the token is bound to', async () => {
    const key = await DpopKey.generate();
    const otherKey = await DpopKey.generate();
    const { accessToken } = await issue(key);
    const proof = await otherKey.proof({ uri: `${server.baseUrl}/userinfo`, method: 'GET', accessToken });

    const response = await userinfo(accessToken, proof);
    assert.equal(response.status, 401);
    assert.equal(response.body.error, 'invalid_token');
  });

  test('rejects a revoked access token', async () => {
    const key = await DpopKey.generate();
    const { accessToken } = await issue(key);
    const { sha256Base64Url } = await import('../src/util/crypto.ts');
    server.store.revokeAccessToken(sha256Base64Url(accessToken), Date.now());

    const proof = await key.proof({ uri: `${server.baseUrl}/userinfo`, method: 'GET', accessToken });
    const response = await userinfo(accessToken, proof);
    assert.equal(response.status, 401);
    assert.equal(response.body.error, 'invalid_token');
  });

  test('rejects a replayed proof at the resource server', async () => {
    const key = await DpopKey.generate();
    const { accessToken } = await issue(key);
    const proof = await key.proof({ uri: `${server.baseUrl}/userinfo`, method: 'GET', accessToken });

    const first = await userinfo(accessToken, proof);
    assert.equal(first.status, 200);

    const replay = await userinfo(accessToken, proof);
    assert.equal(replay.status, 401);
    assert.equal(replay.body.error, 'invalid_dpop_proof');
    assert.match(String(replay.body.error_description), /jti/);
  });

  test('rejects a bearer-style request with no proof', async () => {
    const key = await DpopKey.generate();
    const { accessToken } = await issue(key);
    const response = await userinfo(accessToken, null);
    assert.equal(response.status, 401);
    assert.match(response.headers.get('www-authenticate') ?? '', /algs=/);
  });
});
