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

async function authorizationPage(query: Record<string, string>): Promise<Response> {
  const session = new BrowserSession(server.baseUrl);
  await session.login();
  const params = new URLSearchParams(query);
  return session.request(`/authorize?${params.toString()}`);
}

describe('PKCE enforcement at the authorization endpoint', () => {
  test('rejects a request with no code_challenge', async () => {
    const response = await authorizationPage({
      response_type: 'code',
      client_id: server.publicClient.id,
      redirect_uri: PUBLIC_REDIRECT,
      state: 'abc',
    });
    assert.equal(response.status, 302);
    const location = new URL(response.headers.get('location') ?? '');
    assert.equal(location.searchParams.get('error'), 'invalid_request');
    assert.match(location.searchParams.get('error_description') ?? '', /code_challenge is required/);
    assert.equal(location.searchParams.get('state'), 'abc');
  });

  test('rejects code_challenge_method=plain even with a valid challenge', async () => {
    const pkce = pkcePair();
    const response = await authorizationPage({
      response_type: 'code',
      client_id: server.publicClient.id,
      redirect_uri: PUBLIC_REDIRECT,
      code_challenge: pkce.verifier,
      code_challenge_method: 'plain',
    });
    assert.equal(response.status, 302);
    const location = new URL(response.headers.get('location') ?? '');
    assert.equal(location.searchParams.get('error'), 'invalid_request');
    assert.match(location.searchParams.get('error_description') ?? '', /S256/);
  });

  test('rejects a malformed code_challenge', async () => {
    const response = await authorizationPage({
      response_type: 'code',
      client_id: server.publicClient.id,
      redirect_uri: PUBLIC_REDIRECT,
      code_challenge: 'too-short',
      code_challenge_method: 'S256',
    });
    const location = new URL(response.headers.get('location') ?? '');
    assert.equal(location.searchParams.get('error'), 'invalid_request');
  });
});

describe('PKCE enforcement at the token endpoint', () => {
  test('a wrong code_verifier fails with invalid_grant', async () => {
    const key = await DpopKey.generate();
    const pkce = pkcePair();
    const session = new BrowserSession(server.baseUrl);
    await session.login();
    const code = await obtainAuthorizationCode({
      session,
      clientId: server.publicClient.id,
      redirectUri: PUBLIC_REDIRECT,
      challenge: pkce.challenge,
      dpopJkt: await key.thumbprint(),
    });

    const wrongVerifier = 'wrong-verifier-0123456789-0123456789-0123456789-xyz';
    const result = await tokenRequest(server, {
      form: {
        grant_type: 'authorization_code',
        code,
        redirect_uri: PUBLIC_REDIRECT,
        code_verifier: wrongVerifier,
      },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopKey: key,
    });

    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_grant');
    assert.match(String(result.body.error_description), /PKCE verification failed/);
  });

  test('a missing code_verifier fails even when the challenge matches nothing', async () => {
    const key = await DpopKey.generate();
    const pkce = pkcePair();
    const session = new BrowserSession(server.baseUrl);
    await session.login();
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
      },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopKey: key,
    });
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_grant');
    assert.match(String(result.body.error_description), /verifier_missing/);
  });

  test('a code that failed PKCE can no longer be redeemed with the right verifier', async () => {
    const key = await DpopKey.generate();
    const pkce = pkcePair();
    const session = new BrowserSession(server.baseUrl);
    await session.login();
    const code = await obtainAuthorizationCode({
      session,
      clientId: server.publicClient.id,
      redirectUri: PUBLIC_REDIRECT,
      challenge: pkce.challenge,
      dpopJkt: await key.thumbprint(),
    });

    const failed = await tokenRequest(server, {
      form: {
        grant_type: 'authorization_code',
        code,
        redirect_uri: PUBLIC_REDIRECT,
        code_verifier: 'bad-verifier-0123456789-0123456789-0123456789-abcdefgh',
      },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopKey: key,
    });
    assert.equal(failed.status, 400);

    // The legitimate client now presents the correct verifier: the code must
    // be dead, not merely "not yet redeemed".
    const retry = await tokenRequest(server, {
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
    assert.equal(retry.status, 400);
    assert.equal(retry.body.error, 'invalid_grant');
    assert.match(String(retry.body.error_description), /already been used/);
  });

  test('a code_verifier outside the allowed charset is rejected', async () => {
    const key = await DpopKey.generate();
    const pkce = pkcePair();
    const session = new BrowserSession(server.baseUrl);
    await session.login();
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
        code_verifier: `${'a'.repeat(42)}!`,
      },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopKey: key,
    });
    assert.equal(result.status, 400);
    assert.match(String(result.body.error_description), /verifier_malformed/);
  });
});
