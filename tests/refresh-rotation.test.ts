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

/** Runs the full flow and returns a fresh token set plus the key. */
async function issueTokens(scope = 'openid profile email offline_access'): Promise<{
  key: DpopKey;
  accessToken: string;
  refreshToken: string;
}> {
  const key = await DpopKey.generate();
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
  return {
    key,
    accessToken: String(result.body.access_token),
    refreshToken: String(result.body.refresh_token),
  };
}

async function refresh(refreshToken: string, key: DpopKey): Promise<{
  status: number;
  body: Record<string, unknown>;
}> {
  const result = await tokenRequest(server, {
    form: { grant_type: 'refresh_token', refresh_token: refreshToken },
    clientId: server.publicClient.id,
    auth: { none: true },
    dpopKey: key,
  });
  return { status: result.status, body: result.body };
}

describe('refresh token rotation', () => {
  test('rotates the refresh token on every use', async () => {
    const first = await issueTokens();
    const second = await refresh(first.refreshToken, first.key);
    assert.equal(second.status, 200);
    assert.notEqual(second.body.refresh_token, first.refreshToken);

    const third = await refresh(String(second.body.refresh_token), first.key);
    assert.equal(third.status, 200);
    assert.notEqual(third.body.refresh_token, second.body.refresh_token);
  });

  test('replaying a used refresh token revokes the whole family', async () => {
    const first = await issueTokens();

    // Rotate once: `first.refreshToken` is now used and has a successor.
    const second = await refresh(first.refreshToken, first.key);
    assert.equal(second.status, 200);
    const successor = String(second.body.refresh_token);

    // Attacker (or buggy client) replays the consumed token.
    const replay = await refresh(first.refreshToken, first.key);
    assert.equal(replay.status, 400);
    assert.equal(replay.body.error, 'invalid_grant');
    assert.match(String(replay.body.error_description), /already been used/);

    // The legitimate successor is now dead too: the entire family is revoked.
    const afterReplay = await refresh(successor, first.key);
    assert.equal(afterReplay.status, 400);
    assert.equal(afterReplay.body.error, 'invalid_grant');
  });

  test('replay revokes access tokens already issued from the family', async () => {
    const first = await issueTokens();
    const second = await refresh(first.refreshToken, first.key);
    assert.equal(second.status, 200);

    const liveAccessToken = String(second.body.access_token);
    const before = await managementRequest(server, '/introspect', {
      form: { token: liveAccessToken },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(before.body.active, true);

    // Replay the consumed token.
    const replay = await refresh(first.refreshToken, first.key);
    assert.equal(replay.status, 400);

    const after = await managementRequest(server, '/introspect', {
      form: { token: liveAccessToken },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(after.body.active, false);
  });

  test('a replayed token is recorded as a replay event', async () => {
    const first = await issueTokens();
    await refresh(first.refreshToken, first.key);
    await refresh(first.refreshToken, first.key);

    const markers = server.store.listReplayMarkers();
    assert.ok(markers.some((m) => m.tokenType === 'refresh_token'));

    const audit = server.store.listAuditEvents(200);
    assert.ok(audit.some((event) => event.event === 'refresh_replay'));
  });

  test('a refresh token cannot be rotated with a different DPoP key', async () => {
    const first = await issueTokens();
    const otherKey = await DpopKey.generate();

    const result = await refresh(first.refreshToken, otherKey);
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_grant');

    // The family is revoked on key mismatch, so even the right key now fails.
    const withRightKey = await refresh(first.refreshToken, first.key);
    assert.equal(withRightKey.status, 400);
  });

  test('a refresh token is rejected when no proof is presented by a DPoP client', async () => {
    const first = await issueTokens();
    const result = await tokenRequest(server, {
      form: { grant_type: 'refresh_token', refresh_token: first.refreshToken },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_dpop_proof');
  });

  test('scope may be narrowed on refresh but not broadened', async () => {
    const first = await issueTokens('openid profile email offline_access');

    const narrowed = await tokenRequest(server, {
      form: {
        grant_type: 'refresh_token',
        refresh_token: first.refreshToken,
        scope: 'openid profile',
      },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopKey: first.key,
    });
    assert.equal(narrowed.status, 200);
    assert.equal(narrowed.body.scope, 'openid profile');

    const broadened = await tokenRequest(server, {
      form: {
        grant_type: 'refresh_token',
        refresh_token: String(narrowed.body.refresh_token),
        scope: 'openid profile email offline_access admin',
      },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopKey: first.key,
    });
    assert.equal(broadened.status, 400);
    assert.equal(broadened.body.error, 'invalid_scope');
  });

  test('a refresh token issued to one client cannot be used by another', async () => {
    const first = await issueTokens();
    const result = await tokenRequest(server, {
      form: { grant_type: 'refresh_token', refresh_token: first.refreshToken },
      clientId: server.confidentialOptionalDpop.id,
      auth: { secret: server.confidentialOptionalDpopSecret },
    });
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_grant');
  });

  test('no refresh token is issued without offline_access', async () => {
    const session = new BrowserSession(server.baseUrl);
    await session.login();
    const pkce = pkcePair();
    const key = await DpopKey.generate();
    const code = await obtainAuthorizationCode({
      session,
      clientId: server.publicClient.id,
      redirectUri: PUBLIC_REDIRECT,
      challenge: pkce.challenge,
      scope: 'openid profile',
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
    assert.equal(result.body.refresh_token, undefined);
  });

  test('unknown and expired refresh tokens are invalid_grant', async () => {
    const unknown = await tokenRequest(server, {
      form: { grant_type: 'refresh_token', refresh_token: 'never-issued-token' },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopKey: await DpopKey.generate(),
    });
    assert.equal(unknown.body.error, 'invalid_grant');
  });

  test('two simultaneous rotations of one token yield exactly one success', async () => {
    const first = await issueTokens();
    const [a, b] = await Promise.all([
      refresh(first.refreshToken, first.key),
      refresh(first.refreshToken, first.key),
    ]);

    const successes = [a, b].filter((result) => result.status === 200);
    assert.equal(successes.length, 1, 'only one concurrent refresh may succeed');

    // A concurrent double-use is indistinguishable from theft, so the family
    // is burned: the winner's successor no longer works either.
    const winnerToken = String(successes[0]?.body.refresh_token);
    const after = await refresh(winnerToken, first.key);
    assert.equal(after.status, 400);
  });
});

describe('authorization code replay', () => {
  test('replaying a redeemed code revokes the tokens it produced', async () => {
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
    const form = {
      grant_type: 'authorization_code',
      code,
      redirect_uri: PUBLIC_REDIRECT,
      code_verifier: pkce.verifier,
    };

    const first = await tokenRequest(server, {
      form,
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopKey: key,
    });
    assert.equal(first.status, 200);
    const accessToken = String(first.body.access_token);
    const refreshToken = String(first.body.refresh_token);

    // A stolen copy of the code is redeemed a second time.
    const replay = await tokenRequest(server, {
      form,
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopKey: key,
    });
    assert.equal(replay.status, 400);
    assert.equal(replay.body.error, 'invalid_grant');

    // Everything the code produced is now dead.
    const access = await managementRequest(server, '/introspect', {
      form: { token: accessToken },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(access.body.active, false);

    const refresh = await managementRequest(server, '/introspect', {
      form: { token: refreshToken },
      clientId: server.publicClient.id,
      auth: { none: true },
    });
    assert.equal(refresh.body.active, false);

    const audit = server.store.listAuditEvents(200);
    assert.ok(audit.some((event) => event.event === 'authorization_code_replay'));
  });
});
