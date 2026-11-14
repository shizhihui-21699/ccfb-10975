import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../src/db/store.ts';
import { TokenService } from '../src/oauth/tokens.ts';
import { loadConfig } from '../src/config.ts';
import { silentLogger } from '../src/util/logging.ts';
import {
  hashSecret,
  randomToken,
  sha256Base64Url,
  s256Challenge,
  timingSafeEqualString,
  verifySecret,
} from '../src/util/crypto.ts';
import { normalizeHtu, athFor, verifyDpopProof, DpopError } from '../src/oauth/dpop.ts';
import { isValidCodeChallenge, isValidCodeVerifier, verifyPkce } from '../src/oauth/pkce.ts';
import { matchRedirectUri, validateRedirectUri } from '../src/oauth/registration.ts';
import { newId } from '../src/util/crypto.ts';
import { DpopKey } from './helpers/dpop.ts';

const scrypt = { N: 1024, r: 8, p: 1 };

function makeConfig() {
  return loadConfig({
    logger: silentLogger(),
    scrypt,
    adminSessionSecret: 'unit-test-secret',
  });
}

describe('crypto helpers', () => {
  test('hashSecret accepts the right secret and rejects others', () => {
    const hash = hashSecret('hunter2', scrypt);
    assert.equal(verifySecret('hunter2', hash, scrypt), true);
    assert.equal(verifySecret('hunter3', hash, scrypt), false);
    assert.equal(verifySecret('', hash, scrypt), false);
    assert.equal(verifySecret('hunter2', null, scrypt), false);
    assert.equal(verifySecret('hunter2', 'garbage', scrypt), false);
  });

  test('hashes are salted: the same secret yields different stored values', () => {
    assert.notEqual(hashSecret('same', scrypt), hashSecret('same', scrypt));
  });

  test('timingSafeEqualString handles different lengths without throwing', () => {
    assert.equal(timingSafeEqualString('abc', 'abc'), true);
    assert.equal(timingSafeEqualString('abc', 'abcd'), false);
    assert.equal(timingSafeEqualString('', 'x'), false);
  });

  test('randomToken is URL-safe and unique', () => {
    const tokens = new Set(Array.from({ length: 200 }, () => randomToken(32)));
    assert.equal(tokens.size, 200);
    for (const token of tokens) assert.match(token, /^[A-Za-z0-9_-]{43}$/);
  });

  test('s256Challenge matches the RFC 7636 test vector', () => {
    // RFC 7636 Appendix B.
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    assert.equal(s256Challenge(verifier), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });
});

describe('PKCE validation', () => {
  test('accepts the RFC test vector', () => {
    const result = verifyPkce(
      'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    );
    assert.deepEqual(result, { ok: true });
  });

  test('enforces the 43..128 character verifier length', () => {
    assert.equal(isValidCodeVerifier('a'.repeat(42)), false);
    assert.equal(isValidCodeVerifier('a'.repeat(43)), true);
    assert.equal(isValidCodeVerifier('a'.repeat(128)), true);
    assert.equal(isValidCodeVerifier('a'.repeat(129)), false);
  });

  test('rejects characters outside unreserved', () => {
    for (const bad of ['a'.repeat(42) + ' ', 'a'.repeat(42) + '/', 'a'.repeat(42) + '+', 'a'.repeat(42) + '=']) {
      assert.equal(isValidCodeVerifier(bad), false);
    }
  });

  test('challenges must be 43 base64url characters', () => {
    assert.equal(isValidCodeChallenge('a'.repeat(43)), true);
    assert.equal(isValidCodeChallenge('a'.repeat(42)), false);
    assert.equal(isValidCodeChallenge('a'.repeat(42) + '='), false);
  });

  test('distinguishes missing, malformed and mismatched verifiers', () => {
    const challenge = s256Challenge('a'.repeat(43));
    assert.deepEqual(verifyPkce(undefined, challenge), { ok: false, reason: 'verifier_missing' });
    assert.deepEqual(verifyPkce('', challenge), { ok: false, reason: 'verifier_missing' });
    assert.deepEqual(verifyPkce('short', challenge), { ok: false, reason: 'verifier_malformed' });
    assert.deepEqual(verifyPkce('b'.repeat(43), challenge), { ok: false, reason: 'challenge_mismatch' });
  });
});

describe('htu normalization (RFC 9449 §4.3)', () => {
  test('strips query and fragment', () => {
    assert.equal(normalizeHtu('https://as.example.com/token?x=1#frag'), 'https://as.example.com/token');
  });

  test('lowercases scheme and host, keeps path case', () => {
    assert.equal(normalizeHtu('HTTPS://AS.Example.COM/Token'), 'https://as.example.com/Token');
  });

  test('elides default ports and preserves non-default ones', () => {
    assert.equal(normalizeHtu('https://as.example.com:443/token'), 'https://as.example.com/token');
    assert.equal(normalizeHtu('http://as.example.com:80/token'), 'http://as.example.com/token');
    assert.equal(normalizeHtu('https://as.example.com:8443/token'), 'https://as.example.com:8443/token');
  });

  test('normalizes an empty path to /', () => {
    assert.equal(normalizeHtu('https://as.example.com'), 'https://as.example.com/');
  });

  test('rejects non-http(s) and userinfo', () => {
    assert.equal(normalizeHtu('ftp://as.example.com/token'), null);
    assert.equal(normalizeHtu('https://user:pw@as.example.com/token'), null);
    assert.equal(normalizeHtu('not a uri'), null);
  });

  test('ath is the base64url SHA-256 of the ASCII token', () => {
    assert.equal(
      athFor('Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU'),
      sha256Base64Url('Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU'),
    );
  });
});

describe('DPoP verification unit behaviour', () => {
  test('reports a structured error for a malformed proof', async () => {
    await assert.rejects(
      verifyDpopProof('not.a.jwt', {
        method: 'POST',
        uri: 'https://as.example.com/token',
        iatToleranceSeconds: 60,
        futureSkewSeconds: 5,
        now: Date.now(),
      }),
      (error: unknown) => {
        assert.ok(error instanceof DpopError);
        assert.equal(error.code, 'invalid_dpop_proof');
        return true;
      },
    );
  });

  test('accepts a proof with a leading-zero iat at the window edge', async () => {
    const key = await DpopKey.generate();
    const now = Date.now();
    const proof = await key.proof({
      uri: 'https://as.example.com/token',
      method: 'POST',
      iat: Math.floor(now / 1000) - 60,
    });
    const verified = await verifyDpopProof(proof, {
      method: 'POST',
      uri: 'https://as.example.com/token',
      iatToleranceSeconds: 60,
      futureSkewSeconds: 5,
      now,
    });
    assert.equal(verified.jkt, await key.thumbprint());
  });
});

describe('redirect URI validation', () => {
  test('classifies loopback and native schemes', () => {
    assert.deepEqual(validateRedirectUri('https://app.example.com/cb'), {
      uri: 'https://app.example.com/cb',
      loopback: false,
      nativeScheme: false,
    });
    assert.equal(validateRedirectUri('http://127.0.0.1:5000/cb').loopback, true);
    assert.equal(validateRedirectUri('com.example.app:/cb').nativeScheme, true);
  });

  test('matches exact strings and loopback ports only', () => {
    const registered = [validateRedirectUri('http://localhost:3000/cb')];
    assert.deepEqual(matchRedirectUri('http://localhost:3000/cb', registered), { ok: true });
    assert.deepEqual(matchRedirectUri('http://localhost:4000/cb', registered), { ok: true });
    assert.deepEqual(matchRedirectUri('http://localhost:4000/other', registered), {
      ok: false,
      reason: 'not_registered',
    });
  });

  test('rejects a fragment-bearing request even if the path matches', () => {
    const registered = [validateRedirectUri('https://app.example.com/cb')];
    assert.equal(matchRedirectUri('https://app.example.com/cb#x', registered).ok, false);
  });
});

describe('store transactions and token service invariants', () => {
  function makeStore(): { store: Store; tokens: TokenService; config: ReturnType<typeof makeConfig> } {
    const store = new Store(':memory:');
    const config = makeConfig();
    return { store, tokens: new TokenService(store, config), config };
  }

  test('a thrown error rolls the transaction back', () => {
    const { store } = makeStore();
    const now = Date.now();
    assert.throws(() =>
      store.transaction(() => {
        store.insertClient(
          {
            id: 'rolled-back',
            name: 'Rolled Back',
            secretHash: null,
            redirectUris: ['https://example.com/cb'],
            grantTypes: ['authorization_code'],
            responseTypes: ['code'],
            scopes: ['openid'],
            tokenEndpointAuthMethod: 'none',
            requireDpop: true,
          },
          now,
        );
        throw new Error('boom');
      }),
    );
    assert.equal(store.getClient('rolled-back'), null);
    store.close();
  });

  test('nested transactions join the outer one', () => {
    const { store } = makeStore();
    const now = Date.now();
    assert.throws(() =>
      store.transaction(() => {
        store.transaction(() => {
          store.insertClient(
            {
              id: 'nested',
              name: 'Nested',
              secretHash: null,
              redirectUris: ['https://example.com/cb'],
              grantTypes: ['authorization_code'],
              responseTypes: ['code'],
              scopes: ['openid'],
              tokenEndpointAuthMethod: 'none',
              requireDpop: true,
            },
            now,
          );
        });
        throw new Error('outer boom');
      }),
    );
    assert.equal(store.getClient('nested'), null);
    store.close();
  });

  test('consumeRefreshToken is single-winner', () => {
    const { store } = makeStore();
    const now = Date.now();
    store.insertFamily({ id: 'fam', clientId: 'c', userId: 'u', scope: ['openid'], dpopJkt: null, createdAt: now });
    store.insertRefreshToken({ tokenHash: 'h1', familyId: 'fam', generation: 1, issuedAt: now, expiresAt: now + 1000 });
    assert.equal(store.consumeRefreshToken('h1', now, 'h2'), true);
    assert.equal(store.consumeRefreshToken('h1', now, 'h3'), false);
    store.close();
  });

  test('revokeFamily revokes refresh and access tokens and records the reason once', () => {
    const { store } = makeStore();
    const now = Date.now();
    store.insertFamily({ id: 'fam', clientId: 'c', userId: 'u', scope: ['openid'], dpopJkt: null, createdAt: now });
    store.insertRefreshToken({ tokenHash: 'r1', familyId: 'fam', generation: 1, issuedAt: now, expiresAt: now + 1000 });
    store.insertAccessToken({
      tokenHash: 'a1',
      familyId: 'fam',
      clientId: 'c',
      userId: 'u',
      scope: ['openid'],
      issuedAt: now,
      expiresAt: now + 1000,
      dpopJkt: null,
      jti: 'j1',
    });

    assert.equal(store.revokeFamily('fam', now, 'first_reason'), true);
    assert.equal(store.getFamily('fam')?.revokedAt, now);
    assert.equal(store.getFamily('fam')?.revokedReason, 'first_reason');
    assert.equal(store.getRefreshToken('r1')?.revokedAt, now);
    assert.equal(store.getAccessToken('a1')?.revokedAt, now);

    // A second revocation does not overwrite the original reason.
    assert.equal(store.revokeFamily('fam', now + 1, 'second_reason'), false);
    assert.equal(store.getFamily('fam')?.revokedReason, 'first_reason');
    store.close();
  });

  test('dpop jti recording is per-key and rejects duplicates', () => {
    const { store } = makeStore();
    const now = Date.now();
    assert.equal(store.recordDpopJti('jkt-a', 'jti-1', now, now + 1000), true);
    assert.equal(store.recordDpopJti('jkt-a', 'jti-1', now, now + 1000), false);
    // Same jti under a different key is a distinct proof.
    assert.equal(store.recordDpopJti('jkt-b', 'jti-1', now, now + 1000), true);
    store.close();
  });

  test('issuing a new family stores only digests of the tokens', () => {
    const { store, tokens } = makeStore();
    const now = Date.now();
    const issued = tokens.issueNewFamily({
      familyId: 'family-1',
      clientId: 'client',
      userId: 'user',
      scope: ['openid'],
      accessTokenJkt: 'jkt',
      refreshBindingJkt: 'jkt',
      withRefreshToken: true,
      now,
    });

    assert.equal(store.getAccessToken(sha256Base64Url(issued.accessToken)) !== null, true);
    assert.equal(store.getRefreshToken(sha256Base64Url(issued.refreshToken ?? '')) !== null, true);
    // The plaintext is not stored anywhere.
    assert.equal(store.getAccessToken(issued.accessToken), null);
    assert.equal(store.getRefreshToken(issued.refreshToken ?? ''), null);
    store.close();
  });

  test('concurrent rotation of the same refresh token yields exactly one success', async () => {
    const { store, tokens } = makeStore();
    const now = Date.now();
    const raw = randomToken(32);
    store.insertFamily({ id: 'fam', clientId: 'c', userId: 'u', scope: ['openid'], dpopJkt: null, createdAt: now });
    store.insertRefreshToken({
      tokenHash: sha256Base64Url(raw),
      familyId: 'fam',
      generation: 1,
      issuedAt: now,
      expiresAt: now + 60_000,
    });

    const attempt = () =>
      Promise.resolve().then(() =>
        tokens.rotateRefreshToken({
          refreshToken: raw,
          clientId: 'c',
          dpopJkt: null,
          senderConstrainedByKey: false,
          requestedScope: null,
          now,
        }),
      );
    const results = await Promise.allSettled([attempt(), attempt()]);

    const fulfilled = results.filter((result) => result.status === 'fulfilled');
    assert.equal(fulfilled.length, 1, 'exactly one rotation should win');

    // The loser is treated as a replay, so the family is revoked and even the
    // winner's successor is unusable: a concurrent double-use is
    // indistinguishable from theft, and failing closed is the safe choice.
    const winner = fulfilled[0] as PromiseFulfilledResult<{ refreshToken: string | null }>;
    assert.equal(store.getFamily('fam')?.revokedAt !== null, true);
    assert.throws(() =>
      tokens.rotateRefreshToken({
        refreshToken: String(winner.value.refreshToken),
        clientId: 'c',
        dpopJkt: null,
        senderConstrainedByKey: false,
        requestedScope: null,
        now,
      }),
    );
    store.close();
  });

  test('expired refresh tokens are rejected', () => {
    const { store, tokens } = makeStore();
    const now = Date.now();
    const raw = randomToken(32);
    store.insertFamily({ id: 'fam2', clientId: 'c', userId: 'u', scope: ['openid'], dpopJkt: null, createdAt: now });
    store.insertRefreshToken({
      tokenHash: sha256Base64Url(raw),
      familyId: 'fam2',
      generation: 1,
      issuedAt: now - 10_000,
      expiresAt: now - 1000,
    });
    assert.throws(
      () =>
        tokens.rotateRefreshToken({
          refreshToken: raw,
          clientId: 'c',
          dpopJkt: null,
          senderConstrainedByKey: false,
          requestedScope: null,
          now,
        }),
      /expired/,
    );
    store.close();
  });

  test('newId produces unique identifiers', () => {
    const ids = new Set(Array.from({ length: 100 }, () => newId()));
    assert.equal(ids.size, 100);
  });
});
