import { calculateJwkThumbprint, importJWK, jwtVerify, type JWK } from 'jose';
import { createHash } from 'node:crypto';

/**
 * DPoP support per RFC 9449.
 *
 * Only asymmetric JWS algorithms are accepted; `none` and the HMAC family are
 * rejected outright (RFC 9449 §4.3).
 */
export const DPOP_ALGORITHMS = [
  'ES256',
  'ES384',
  'ES512',
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'EdDSA',
] as const;

export type DpopAlgorithm = (typeof DPOP_ALGORITHMS)[number];

export interface DpopProof {
  /** Key thumbprint, the identifier used for binding checks. */
  jkt: string;
  /** Public key exported from the proof header. */
  jwk: JWK;
  jti: string;
  htm: string;
  htu: string;
  iat: number;
  ath?: string;
  nonce?: string;
  algorithm: string;
}

export class DpopError extends Error {
  readonly code: 'invalid_dpop_proof' | 'use_dpop_nonce';

  constructor(code: 'invalid_dpop_proof' | 'use_dpop_nonce', message: string) {
    super(message);
    this.name = 'DpopError';
    this.code = code;
  }
}

const PRIVATE_KEY_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'];

function hasPrivateMaterial(jwk: JWK): boolean {
  const record = jwk as Record<string, unknown>;
  return PRIVATE_KEY_MEMBERS.some((member) => record[member] !== undefined);
}

/**
 * RFC 9449 §4.3 htu comparison. Query and fragment are ignored, then
 * scheme/host are normalized per RFC 3986 syntax-based + scheme-based
 * normalization (lowercase scheme and host, default port elided).
 */
export function normalizeHtu(value: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
  if (parsed.username || parsed.password) return null;
  const host = parsed.hostname.toLowerCase();
  const port = parsed.port;
  const defaultPort = parsed.protocol === 'https:' ? '443' : '80';
  const authority = port && port !== defaultPort ? `${host}:${port}` : host;
  const path = parsed.pathname === '' ? '/' : parsed.pathname;
  return `${parsed.protocol.slice(0, -1)}://${authority}${path}`;
}

/** The absolute request URI as the client should have signed it. */
export function requestUri(req: {
  protocol: string;
  get(header: string): string | undefined;
  originalUrl?: string;
  path?: string;
}): string | null {
  const host = req.get('host');
  if (!host) return null;
  const pathname = (req.originalUrl ?? req.path ?? '/').split(/[?#]/)[0] ?? '/';
  const uri = `${req.protocol}://${host}${pathname}`;
  return normalizeHtu(uri);
}

export function athFor(accessToken: string): string {
  return createHash('sha256').update(accessToken, 'ascii').digest('base64url');
}

export interface DpopVerificationOptions {
  /** HTTP method of the request being authenticated. */
  method: string;
  /** Absolute request URI (query/fragment stripped). */
  uri: string;
  /** The access token being presented, when one is (for the `ath` check). */
  accessToken?: string;
  iatToleranceSeconds: number;
  futureSkewSeconds: number;
  now: number;
}

/**
 * Verifies a DPoP proof's own integrity: syntax, typ, alg, embedded public
 * key, signature, htm/htu, iat window, and optionally `ath`.
 *
 * Replay (`jti`) checking is deliberately a separate step because it needs
 * durable state (see `DpopReplayCache`).
 */
export async function verifyDpopProof(
  proofJwt: string,
  options: DpopVerificationOptions,
): Promise<DpopProof> {
  const parts = proofJwt.split('.');
  if (parts.length !== 3) {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof is not a well-formed JWT');
  }

  let header: Record<string, unknown>;
  try {
    header = JSON.parse(Buffer.from(parts[0] ?? '', 'base64url').toString('utf8')) as Record<string, unknown>;
  } catch {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof header is not valid JSON');
  }

  if (header.typ !== 'dpop+jwt') {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof typ must be dpop+jwt');
  }
  const alg = header.alg;
  if (typeof alg !== 'string' || !(DPOP_ALGORITHMS as readonly string[]).includes(alg)) {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof uses an unsupported or symmetric algorithm');
  }
  const jwk = header.jwk;
  if (jwk === null || typeof jwk !== 'object' || Array.isArray(jwk)) {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof is missing its jwk header');
  }
  if (hasPrivateMaterial(jwk as JWK)) {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof jwk must not contain private key material');
  }
  if ((jwk as JWK).kty === 'oct') {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof jwk must be an asymmetric key');
  }

  let key: Awaited<ReturnType<typeof importJWK>>;
  try {
    key = await importJWK(jwk as JWK, alg);
  } catch {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof jwk is not a valid public key');
  }

  let payload: Record<string, unknown>;
  try {
    const verified = await jwtVerify(proofJwt, key, {
      algorithms: DPOP_ALGORITHMS as unknown as string[],
      typ: 'dpop+jwt',
      // `iat` freshness is enforced below so the window is configurable.
      clockTolerance: Math.max(options.futureSkewSeconds, options.iatToleranceSeconds),
      maxTokenAge: undefined,
    });
    payload = verified.payload as Record<string, unknown>;
  } catch {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof signature could not be verified');
  }

  const jti = payload.jti;
  if (typeof jti !== 'string' || jti.length < 8) {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof must carry a sufficiently unique jti');
  }
  const htm = payload.htm;
  if (typeof htm !== 'string' || htm.toUpperCase() !== options.method.toUpperCase()) {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof htm does not match the request method');
  }
  const htu = payload.htu;
  if (typeof htu !== 'string') {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof must carry an htu claim');
  }
  if (normalizeHtu(htu) !== options.uri) {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof htu does not match the request URI');
  }
  const iat = payload.iat;
  if (typeof iat !== 'number' || !Number.isFinite(iat)) {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof must carry a numeric iat claim');
  }
  const nowSeconds = Math.floor(options.now / 1000);
  if (iat > nowSeconds + options.futureSkewSeconds) {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof iat is too far in the future');
  }
  if (iat < nowSeconds - options.iatToleranceSeconds) {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof iat is too old');
  }

  if (options.accessToken !== undefined) {
    const ath = payload.ath;
    if (typeof ath !== 'string') {
      throw new DpopError('invalid_dpop_proof', 'DPoP proof must carry ath when presenting an access token');
    }
    if (ath !== athFor(options.accessToken)) {
      throw new DpopError('invalid_dpop_proof', 'DPoP proof ath does not match the access token');
    }
  }

  const jkt = await calculateJwkThumbprint(jwk as JWK, 'sha256');

  return {
    jkt,
    jwk: jwk as JWK,
    jti,
    htm,
    htu,
    iat,
    ath: typeof payload.ath === 'string' ? payload.ath : undefined,
    nonce: typeof payload.nonce === 'string' ? payload.nonce : undefined,
    algorithm: alg,
  };
}
