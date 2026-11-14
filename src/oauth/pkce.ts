import { s256Challenge } from '../util/crypto.ts';

/**
 * PKCE (RFC 7636). Only `S256` is supported: `plain` exists solely for clients
 * that cannot compute SHA-256, and accepting it would let an attacker who
 * observes the authorization request redeem the code (RFC 9700 §4.1).
 */
export const PKCE_METHOD = 'S256' as const;

/** ABNF: code-verifier = 43*128unreserved */
const CODE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;
/** base64url(SHA-256(...)) is always exactly 43 characters. */
const S256_CHALLENGE_PATTERN = /^[A-Za-z0-9\-_]{43}$/;

export function isValidCodeChallenge(challenge: string): boolean {
  return S256_CHALLENGE_PATTERN.test(challenge);
}

export function isValidCodeVerifier(verifier: string): boolean {
  return CODE_VERIFIER_PATTERN.test(verifier);
}

export type PkceVerification =
  | { ok: true }
  | { ok: false; reason: 'verifier_missing' | 'verifier_malformed' | 'challenge_mismatch' };

export function verifyPkce(
  codeVerifier: string | undefined,
  storedChallenge: string,
): PkceVerification {
  if (codeVerifier === undefined || codeVerifier === '') {
    return { ok: false, reason: 'verifier_missing' };
  }
  if (!isValidCodeVerifier(codeVerifier)) {
    return { ok: false, reason: 'verifier_malformed' };
  }
  if (s256Challenge(codeVerifier) !== storedChallenge) {
    return { ok: false, reason: 'challenge_mismatch' };
  }
  return { ok: true };
}
