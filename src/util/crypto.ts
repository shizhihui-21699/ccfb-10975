import { createHash, randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';

/** Cryptographically random, URL-safe token material (default 256 bits). */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function newId(): string {
  return randomUUID();
}

export function sha256Base64Url(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('base64url');
}

/** RFC 7636 S256: BASE64URL(SHA256(ASCII(code_verifier))). */
export function s256Challenge(codeVerifier: string): string {
  return sha256Base64Url(codeVerifier);
}

/** Constant-time comparison that also hides length differences. */
export function timingSafeEqualString(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) {
    // Still burn a comparison so the length difference is not a fast path.
    const h1 = createHash('sha256').update(left).digest();
    const h2 = createHash('sha256').update(right).digest();
    timingSafeEqual(h1, h2);
    return false;
  }
  return timingSafeEqual(left, right);
}

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
}

const SCRYPT_KEY_BYTES = 32;

function maxmemFor(params: ScryptParams): number {
  // 128 * N * r is the working-set formula; double it for headroom.
  return Math.max(64 * 1024 * 1024, 128 * params.N * params.r * 2);
}

/** Hash a low-entropy secret (password / client secret) with scrypt + per-value salt. */
export function hashSecret(secret: string, params: ScryptParams): string {
  const salt = randomBytes(16);
  const key = scryptSync(secret, salt, SCRYPT_KEY_BYTES, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: maxmemFor(params),
  });
  return [
    'scrypt',
    String(params.N),
    String(params.r),
    String(params.p),
    salt.toString('base64url'),
    key.toString('base64url'),
  ].join('$');
}

export function verifySecret(
  secret: string,
  stored: string | null | undefined,
  fallbackParams: ScryptParams,
): boolean {
  if (!stored) return false;
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (!Number.isSafeInteger(N) || !Number.isSafeInteger(r) || !Number.isSafeInteger(p)) return false;
  if (N <= 0 || r <= 0 || p <= 0) return false;
  let expected: Buffer;
  let actual: Buffer;
  try {
    expected = Buffer.from(parts[5] ?? '', 'base64url');
    actual = scryptSync(secret, Buffer.from(parts[4] ?? '', 'base64url'), expected.length, {
      N,
      r,
      p,
      maxmem: maxmemFor({ N, r, p }),
    });
  } catch {
    return false;
  }
  if (expected.length === 0 || expected.length !== actual.length) return false;
  return timingSafeEqual(expected, actual);
}

/**
 * A throwaway hash used to keep response timing uniform when a client id is
 * unknown, so the token endpoint does not become a client-id oracle.
 */
export function makeDummySecretHash(params: ScryptParams): string {
  return hashSecret(randomToken(24), params);
}
