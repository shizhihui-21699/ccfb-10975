import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT, generateKeyPair } from 'jose';
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
  server = await startTestServer({ dpopIatToleranceSeconds: 30, dpopIatFutureSkewSeconds: 5 });
});

after(async () => {
  await server.close();
});

async function freshCode(key: DpopKey): Promise<{ code: string; verifier: string }> {
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
  return { code, verifier: pkce.verifier };
}

describe('DPoP proof validation', () => {
  test('accepts a valid proof and binds the access token to the key', async () => {
    const key = await DpopKey.generate();
    const { code, verifier } = await freshCode(key);

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

    const tokenRecord = server.store.getAccessToken(
      (await import('../src/util/crypto.ts')).sha256Base64Url(String(result.body.access_token)),
    );
    assert.equal(tokenRecord?.dpopJkt, await key.thumbprint());
  });

  test('rejects a proof whose jti was already used', async () => {
    const key = await DpopKey.generate();
    const uri = `${server.baseUrl}/token`;
    const jti = 'fixed-jti-for-replay-test';

    // First request establishes the jti in the replay cache. It fails later at
    // the grant step, but proof validation happens first and succeeds.
    const firstProof = await key.proof({ uri, method: 'POST', jti });
    const first = await tokenRequest(server, {
      form: { grant_type: 'refresh_token', refresh_token: 'nonexistent-token-value' },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopProof: firstProof,
    });
    assert.equal(first.status, 400);
    // The grant fails, not the proof.
    assert.equal(first.body.error, 'invalid_grant');

    // Reusing the identical proof must now fail on the jti check.
    const second = await tokenRequest(server, {
      form: { grant_type: 'refresh_token', refresh_token: 'nonexistent-token-value' },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopProof: firstProof,
    });
    assert.equal(second.status, 400);
    assert.equal(second.body.error, 'invalid_dpop_proof');
    assert.match(String(second.body.error_description), /jti has already been used/);
  });

  test('rejects an iat older than the tolerance window', async () => {
    const key = await DpopKey.generate();
    const uri = `${server.baseUrl}/token`;
    const proof = await key.proof({ uri, method: 'POST', iatOffsetSeconds: -120 });

    const result = await tokenRequest(server, {
      form: { grant_type: 'refresh_token', refresh_token: 'whatever' },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopProof: proof,
    });
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_dpop_proof');
    assert.match(String(result.body.error_description), /too old/);
  });

  test('rejects an iat too far in the future', async () => {
    const key = await DpopKey.generate();
    const uri = `${server.baseUrl}/token`;
    const proof = await key.proof({ uri, method: 'POST', iatOffsetSeconds: 120 });

    const result = await tokenRequest(server, {
      form: { grant_type: 'refresh_token', refresh_token: 'whatever' },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopProof: proof,
    });
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_dpop_proof');
    assert.match(String(result.body.error_description), /too far in the future/);
  });

  test('tolerates a small clock skew into the future', async () => {
    const key = await DpopKey.generate();
    const uri = `${server.baseUrl}/token`;
    const proof = await key.proof({ uri, method: 'POST', iatOffsetSeconds: 2 });

    const result = await tokenRequest(server, {
      form: { grant_type: 'refresh_token', refresh_token: 'whatever' },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopProof: proof,
    });
    // The proof passes; the (bogus) refresh token is what fails.
    assert.equal(result.body.error, 'invalid_grant');
  });

  test('rejects a proof for the wrong htu', async () => {
    const key = await DpopKey.generate();
    const proof = await key.proof({ uri: `${server.baseUrl}/other-endpoint`, method: 'POST' });

    const result = await tokenRequest(server, {
      form: { grant_type: 'refresh_token', refresh_token: 'whatever' },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopProof: proof,
    });
    assert.equal(result.body.error, 'invalid_dpop_proof');
    assert.match(String(result.body.error_description), /htu/);
  });

  test('ignores query and fragment when comparing htu', async () => {
    const key = await DpopKey.generate();
    const proof = await key.proof({
      uri: `${server.baseUrl}/token?foo=bar#frag`,
      method: 'POST',
    });

    const result = await tokenRequest(server, {
      form: { grant_type: 'refresh_token', refresh_token: 'whatever' },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopProof: proof,
    });
    // Proof accepted: the failure is the unknown refresh token.
    assert.equal(result.body.error, 'invalid_grant');
  });

  test('rejects a proof for the wrong htm', async () => {
    const key = await DpopKey.generate();
    const uri = `${server.baseUrl}/token`;
    const proof = await key.proof({ uri, method: 'GET' });

    const result = await tokenRequest(server, {
      form: { grant_type: 'refresh_token', refresh_token: 'whatever' },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopProof: proof,
    });
    assert.equal(result.body.error, 'invalid_dpop_proof');
    assert.match(String(result.body.error_description), /htm/);
  });

  test('rejects a proof with typ != dpop+jwt', async () => {
    const key = await DpopKey.generate();
    const uri = `${server.baseUrl}/token`;
    const proof = await key.proof({ uri, method: 'POST', header: { typ: 'JWT' } });

    const result = await tokenRequest(server, {
      form: { grant_type: 'refresh_token', refresh_token: 'whatever' },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopProof: proof,
    });
    assert.equal(result.body.error, 'invalid_dpop_proof');
    assert.match(String(result.body.error_description), /typ/);
  });

  test('rejects a symmetric alg (HS256)', async () => {
    const key = await DpopKey.generate();
    const uri = `${server.baseUrl}/token`;
    // Hand-build an HS256 proof: jose will not sign with a JWK header, so a
    // raw compact JWS with the right shape proves the server refuses it.
    const { createHmac } = await import('node:crypto');
    const b64 = (value: object): string => Buffer.from(JSON.stringify(value)).toString('base64url');
    const header = b64({ typ: 'dpop+jwt', alg: 'HS256', jwk: key.publicJwk });
    const payload = b64({
      jti: 'hs256-jti-0123456789',
      htm: 'POST',
      htu: uri,
      iat: Math.floor(Date.now() / 1000),
    });
    const signature = createHmac('sha256', 'secret').update(`${header}.${payload}`).digest('base64url');
    const proof = `${header}.${payload}.${signature}`;

    const result = await tokenRequest(server, {
      form: { grant_type: 'refresh_token', refresh_token: 'whatever' },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopProof: proof,
    });
    assert.equal(result.body.error, 'invalid_dpop_proof');
    assert.match(String(result.body.error_description), /algorithm/);
  });

  test('rejects a jwk header containing private key material', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    const { exportJWK } = await import('jose');
    const publicJwk = await exportJWK(publicKey);
    const privateJwk = await exportJWK(privateKey);
    const uri = `${server.baseUrl}/token`;

    const proof = await new SignJWT({
      jti: 'private-key-jti-0123456789',
      htm: 'POST',
      htu: uri,
      iat: Math.floor(Date.now() / 1000),
    })
      .setProtectedHeader({
        typ: 'dpop+jwt',
        alg: 'ES256',
        jwk: { ...publicJwk, d: privateJwk.d },
      } as never)
      .sign(privateKey);

    const result = await tokenRequest(server, {
      form: { grant_type: 'refresh_token', refresh_token: 'whatever' },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopProof: proof,
    });
    assert.equal(result.body.error, 'invalid_dpop_proof');
    assert.match(String(result.body.error_description), /private key/);
  });

  test('rejects a proof signed by a key other than the embedded jwk', async () => {
    const embedded = await DpopKey.generate();
    const signer = await DpopKey.generate();
    const uri = `${server.baseUrl}/token`;
    const proof = await embedded.proof({
      uri,
      method: 'POST',
      signingKey: signer.privateKey as CryptoKey,
    });

    const result = await tokenRequest(server, {
      form: { grant_type: 'refresh_token', refresh_token: 'whatever' },
      clientId: server.publicClient.id,
      auth: { none: true },
      dpopProof: proof,
    });
    assert.equal(result.body.error, 'invalid_dpop_proof');
    assert.match(String(result.body.error_description), /signature/);
  });

  test('rejects a proof missing required claims', async () => {
    for (const claim of ['jti', 'htm', 'htu', 'iat'] as const) {
      const key = await DpopKey.generate();
      const proof = await key.proof({
        uri: `${server.baseUrl}/token`,
        method: 'POST',
        omit: [claim],
      });
      const result = await tokenRequest(server, {
        form: { grant_type: 'refresh_token', refresh_token: 'whatever' },
        clientId: server.publicClient.id,
        auth: { none: true },
        dpopProof: proof,
      });
      assert.equal(result.body.error, 'invalid_dpop_proof', `claim ${claim} should be required`);
    }
  });

  test('rejects several DPoP headers', async () => {
    const key = await DpopKey.generate();
    const uri = `${server.baseUrl}/token`;
    const proof = await key.proof({ uri, method: 'POST' });

    const headers = new Headers({ 'content-type': 'application/x-www-form-urlencoded' });
    headers.append('dpop', proof);
    headers.append('dpop', proof);
    const response = await fetch(uri, {
      method: 'POST',
      headers,
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: 'x', client_id: server.publicClient.id }).toString(),
    });
    const body = (await response.json()) as Record<string, unknown>;
    // RFC 9449 §4.3: at most one DPoP header field is allowed.
    assert.equal(body.error, 'invalid_dpop_proof');
    assert.match(String(body.error_description), /more than one DPoP/);
  });

  test('a client that requires DPoP cannot get tokens without a proof', async () => {
    const session = new BrowserSession(server.baseUrl);
    await session.login();
    const pkce = pkcePair();
    const code = await obtainAuthorizationCode({
      session,
      clientId: server.confidentialClient.id,
      redirectUri: 'https://confidential.example.com/callback',
      challenge: pkce.challenge,
    });

    const result = await tokenRequest(server, {
      form: {
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://confidential.example.com/callback',
        code_verifier: pkce.verifier,
      },
      clientId: server.confidentialClient.id,
      auth: { secret: server.confidentialSecret },
    });
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_dpop_proof');
  });

  test('dpop_jkt from the authorization request must match the token proof key', async () => {
    const boundKey = await DpopKey.generate();
    const attackerKey = await DpopKey.generate();
    const session = new BrowserSession(server.baseUrl);
    await session.login();
    const pkce = pkcePair();
    const code = await obtainAuthorizationCode({
      session,
      clientId: server.publicClient.id,
      redirectUri: PUBLIC_REDIRECT,
      challenge: pkce.challenge,
      dpopJkt: await boundKey.thumbprint(),
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
      dpopKey: attackerKey,
    });
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_grant');
    assert.match(String(result.body.error_description), /dpop_jkt/);
  });

  test('a code bound via dpop_jkt rejects a token request with no proof at all', async () => {
    const boundKey = await DpopKey.generate();
    const session = new BrowserSession(server.baseUrl);
    await session.login();
    const pkce = pkcePair();
    const code = await obtainAuthorizationCode({
      session,
      clientId: server.publicClient.id,
      redirectUri: PUBLIC_REDIRECT,
      challenge: pkce.challenge,
      dpopJkt: await boundKey.thumbprint(),
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
    });
    // The client requires DPoP, so the missing proof is caught at the proof
    // layer before the code's dpop_jkt binding is even consulted.
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_dpop_proof');
  });
});
