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

async function codeFor(params: {
  clientId: string;
  redirectUri: string;
  scope?: string;
  dpopJkt?: string;
  verifier?: string;
}): Promise<{ code: string; verifier: string; session: BrowserSession }> {
  const session = new BrowserSession(server.baseUrl);
  await session.login();
  const pkce = pkcePair(params.verifier);
  const code = await obtainAuthorizationCode({
    session,
    clientId: params.clientId,
    redirectUri: params.redirectUri,
    challenge: pkce.challenge,
    scope: params.scope ?? 'openid profile email offline_access',
    dpopJkt: params.dpopJkt,
  });
  return { code, verifier: pkce.verifier, session };
}

describe('authorization code exchange', () => {
  test('public client with PKCE and DPoP receives DPoP-bound tokens', async () => {
    const key = await DpopKey.generate();
    const { code, verifier } = await codeFor({
      clientId: server.publicClient.id,
      redirectUri: PUBLIC_REDIRECT,
      dpopJkt: await key.thumbprint(),
    });

    const result = await tokenRequest(server, {
      form: {
        grant_type: 'authorization_code',
        code,
        redirect_uri: PUBLIC_REDIRECT,
        code_verifier: verifier,
      },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopKey: key,
    });

    assert.equal(result.status, 200);
    assert.equal(result.body.token_type, 'DPoP');
    assert.ok(typeof result.body.access_token === 'string');
    assert.ok(typeof result.body.refresh_token === 'string');
    assert.equal(result.headers.get('cache-control'), 'no-store');
  });

  test('confidential client authenticates with Basic and gets Bearer when no proof is sent', async () => {
    const { code, verifier } = await codeFor({
      clientId: server.confidentialOptionalDpop.id,
      redirectUri: 'https://optional.example.com/confidential-callback',
    });

    const result = await tokenRequest(server, {
      form: {
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://optional.example.com/confidential-callback',
        code_verifier: verifier,
      },
      clientId: server.confidentialOptionalDpop.id,
      auth: { secret: server.confidentialOptionalDpopSecret },
    });

    assert.equal(result.status, 200);
    assert.equal(result.body.token_type, 'Bearer');
  });

  test('rejects a second exchange of the same authorization code', async () => {
    const key = await DpopKey.generate();
    const { code, verifier } = await codeFor({
      clientId: server.publicClient.id,
      redirectUri: PUBLIC_REDIRECT,
      dpopJkt: await key.thumbprint(),
    });
    const form = {
      grant_type: 'authorization_code',
      code,
      redirect_uri: PUBLIC_REDIRECT,
      code_verifier: verifier,
    };

    const first = await tokenRequest(server, {
      form,
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopKey: key,
    });
    assert.equal(first.status, 200);

    const replay = await tokenRequest(server, {
      form,
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopKey: key,
    });
    assert.equal(replay.status, 400);
    assert.equal(replay.body.error, 'invalid_grant');
  });
});
