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
import { tokenRequest, managementRequest } from './helpers/token.ts';

let server: TestServer;

before(async () => {
  server = await startTestServer();
});

after(async () => {
  await server.close();
});

async function issue(): Promise<{ key: DpopKey; accessToken: string; refreshToken: string }> {
  const key = await DpopKey.generate();
  const session = new BrowserSession(server.baseUrl);
  await session.login();
  const pkce = pkcePair();
  const code = await obtainAuthorizationCode({
    session,
    clientId: server.publicClient.id,
    redirectUri: PUBLIC_REDIRECT,
    challenge: pkce.challenge,
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
  return {
    key,
    accessToken: String(result.body.access_token),
    refreshToken: String(result.body.refresh_token),
  };
}

describe('introspection (RFC 7662)', () => {
  test('reports an active access token with its metadata and cnf.jkt', async () => {
    const tokens = await issue();
    const response = await managementRequest(server, '/introspect', {
      form: { token: tokens.accessToken },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(response.status, 200);
    assert.equal(response.body.active, true);
    assert.equal(response.body.token_type, 'DPoP');
    assert.equal(response.body.client_id, server.publicClient.id);
    assert.equal(response.body.scope, 'openid profile email offline_access');
    assert.equal(typeof response.body.exp, 'number');
    assert.deepEqual(response.body.cnf, { jkt: await tokens.key.thumbprint() });
    assert.equal(response.headers.get('cache-control'), 'no-store');
  });

  test('reports active:false for an unknown token', async () => {
    const response = await managementRequest(server, '/introspect', {
      form: { token: 'definitely-not-a-token' },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, { active: false });
  });

  test('reports active:false once an access token is revoked', async () => {
    const tokens = await issue();
    const revoke = await managementRequest(server, '/revoke', {
      form: { token: tokens.accessToken },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(revoke.status, 200);

    const response = await managementRequest(server, '/introspect', {
      form: { token: tokens.accessToken },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(response.body.active, false);
  });

  test('reports active:false once an access token expires', async () => {
    const shortServer = await startTestServer({ accessTokenTtlSeconds: 1 });
    try {
      const key = await DpopKey.generate();
      const session = new BrowserSession(shortServer.baseUrl);
      await session.login();
      const pkce = pkcePair();
      const code = await obtainAuthorizationCode({
        session,
        clientId: shortServer.publicClient.id,
        redirectUri: PUBLIC_REDIRECT,
        challenge: pkce.challenge,
        dpopJkt: await key.thumbprint(),
      });
      const issued = await tokenRequest(shortServer, {
        form: {
          grant_type: 'authorization_code',
          code,
          redirect_uri: PUBLIC_REDIRECT,
          code_verifier: pkce.verifier,
        },
        clientId: shortServer.publicClient.id,
        auth: { none: true },
        dpopKey: key,
      });
      assert.equal(issued.body.expires_in, 1);

      // Simulate the clock moving past expiry rather than sleeping.
      const record = shortServer.store.getAccessToken(
        (await import('../src/util/crypto.ts')).sha256Base64Url(String(issued.body.access_token)),
      );
      assert.ok(record);
      shortServer.store.db
        .prepare('UPDATE access_tokens SET expires_at = ? WHERE token_hash = ?')
        .run(Date.now() - 1000, record.tokenHash);

      const response = await managementRequest(shortServer, '/introspect', {
        form: { token: String(issued.body.access_token) },
        clientId: shortServer.publicClient.id,
        auth: { none: true },
      });
      assert.equal(response.body.active, false);
    } finally {
      await shortServer.close();
    }
  });

  test('does not disclose another client\'s token', async () => {
    const tokens = await issue();
    const response = await managementRequest(server, '/introspect', {
      form: { token: tokens.accessToken },
      clientId: server.confidentialOptionalDpop.id,
      auth: { secret: server.confidentialOptionalDpopSecret },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, { active: false });
  });

  test('requires client authentication', async () => {
    const tokens = await issue();
    const response = await managementRequest(server, '/introspect', {
      form: { token: tokens.accessToken },
    });
    assert.equal(response.status, 401);
    assert.equal(response.body.error, 'invalid_client');
  });

  test('rejects a bad client secret', async () => {
    const tokens = await issue();
    const response = await managementRequest(server, '/introspect', {
      form: { token: tokens.accessToken },
      clientId: server.confidentialOptionalDpop.id,
      auth: { secret: 'wrong-secret' },
    });
    assert.equal(response.status, 401);
    assert.equal(response.body.error, 'invalid_client');
  });

  test('a refresh token introspects as active until it is used', async () => {
    const tokens = await issue();
    const before = await managementRequest(server, '/introspect', {
      form: { token: tokens.refreshToken },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(before.body.active, true);

    const rotated = await tokenRequest(server, {
      form: { grant_type: 'refresh_token', refresh_token: tokens.refreshToken },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopKey: tokens.key,
    });
    assert.equal(rotated.status, 200);

    const after = await managementRequest(server, '/introspect', {
      form: { token: tokens.refreshToken },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(after.body.active, false);
  });
});

describe('revocation (RFC 7009)', () => {
  test('returns 200 for an unknown token', async () => {
    const response = await managementRequest(server, '/revoke', {
      form: { token: 'unknown-token-value' },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(response.status, 200);
  });

  test('requires the token parameter', async () => {
    const response = await managementRequest(server, '/revoke', {
      form: {},
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(response.status, 400);
    assert.equal(response.body.error, 'invalid_request');
  });

  test('revoking a refresh token also revokes its access tokens', async () => {
    const tokens = await issue();
    const revoke = await managementRequest(server, '/revoke', {
      form: { token: tokens.refreshToken, token_type_hint: 'refresh_token' },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(revoke.status, 200);

    const access = await managementRequest(server, '/introspect', {
      form: { token: tokens.accessToken },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(access.body.active, false);

    const refresh = await managementRequest(server, '/introspect', {
      form: { token: tokens.refreshToken },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(refresh.body.active, false);
  });

  test('ignores an unrecognized token_type_hint and still revokes', async () => {
    const tokens = await issue();
    const revoke = await managementRequest(server, '/revoke', {
      form: { token: tokens.accessToken, token_type_hint: 'not_a_real_hint' },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(revoke.status, 200);

    const access = await managementRequest(server, '/introspect', {
      form: { token: tokens.accessToken },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(access.body.active, false);
  });

  test('one client cannot revoke another client\'s token', async () => {
    const tokens = await issue();
    const attempt = await managementRequest(server, '/revoke', {
      form: { token: tokens.accessToken },
      clientId: server.confidentialOptionalDpop.id,
      auth: { secret: server.confidentialOptionalDpopSecret },
    });
    assert.equal(attempt.status, 200);

    // Still active: the cross-client attempt was a no-op.
    const access = await managementRequest(server, '/introspect', {
      form: { token: tokens.accessToken },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(access.body.active, true);
  });

  test('revoking an access token does not kill the refresh token', async () => {
    const tokens = await issue();
    await managementRequest(server, '/revoke', {
      form: { token: tokens.accessToken },
      clientId: server.publicClient.id,
      auth: { none: true },
    });

    const refresh = await managementRequest(server, '/introspect', {
      form: { token: tokens.refreshToken },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(refresh.body.active, true);
  });

  test('revocation requires client authentication', async () => {
    const tokens = await issue();
    const response = await managementRequest(server, '/revoke', {
      form: { token: tokens.accessToken },
    });
    assert.equal(response.status, 401);
  });
});
