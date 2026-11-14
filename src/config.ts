import type { Logger } from './util/logging.ts';

export interface ServerConfig {
  issuer: string;
  /** Public base URL, used to derive endpoint URIs in discovery. */
  baseUrl: string;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  authorizationCodeTtlSeconds: number;
  /** How long after issuance a DPoP proof `iat` may be (RFC 9449 §4.3 "acceptable window"). */
  dpopIatToleranceSeconds: number;
  /** How far in the future a DPoP proof `iat` may be, for client clock skew. */
  dpopIatFutureSkewSeconds: number;
  /** How long a DPoP `jti` is remembered for replay rejection. */
  dpopJtiRetentionSeconds: number;
  replayMarkerTtlSeconds: number;
  scrypt: { N: number; r: number; p: number };
  /** Maximum request body accepted on form endpoints. */
  maxFormBodyBytes: string;
  /** Number of trusted reverse proxies; 0 disables X-Forwarded-* handling. */
  trustProxy: number | boolean;
  /** Whether to serve the admin UI at all. */
  adminEnabled: boolean;
  /** Allow registering new clients at /register (RFC 7591). */
  registrationEnabled: boolean;
  /** Key used to derive CSRF tokens bound to browser sessions. */
  adminSessionSecret: string;
  /** Whether the authorization endpoint requires the resource owner to log in. */
  requireLogin: boolean;
  logger: Logger;
}

function intFromEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return fallback;
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`Environment variable ${name} must be a positive integer, got ${JSON.stringify(raw)}`);
  }
  return parsed;
}

function boolFromEnv(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return fallback;
  const normalized = raw.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  throw new Error(`Environment variable ${name} must be a boolean, got ${JSON.stringify(raw)}`);
}

export function loadConfig(overrides: Partial<ServerConfig> = {}): ServerConfig {
  const port = intFromEnv('PORT', 8080);
  const baseUrl = (process.env.ISSUER ?? `http://localhost:${port}`).replace(/\/+$/, '');

  const config: ServerConfig = {
    issuer: baseUrl,
    baseUrl,
    accessTokenTtlSeconds: intFromEnv('ACCESS_TOKEN_TTL_SECONDS', 3600),
    refreshTokenTtlSeconds: intFromEnv('REFRESH_TOKEN_TTL_SECONDS', 30 * 24 * 60 * 60),
    authorizationCodeTtlSeconds: intFromEnv('AUTHORIZATION_CODE_TTL_SECONDS', 60),
    dpopIatToleranceSeconds: intFromEnv('DPOP_IAT_TOLERANCE_SECONDS', 60),
    dpopIatFutureSkewSeconds: intFromEnv('DPOP_IAT_FUTURE_SKEW_SECONDS', 5),
    dpopJtiRetentionSeconds: intFromEnv('DPOP_JTI_RETENTION_SECONDS', 120),
    replayMarkerTtlSeconds: intFromEnv('REPLAY_MARKER_TTL_SECONDS', 7 * 24 * 60 * 60),
    // N=2^14 keeps a single hash near ~16 MB of scrypt memory; tests dial this down.
    scrypt: {
      N: intFromEnv('SCRYPT_N', 16384),
      r: intFromEnv('SCRYPT_R', 8),
      p: intFromEnv('SCRYPT_P', 1),
    },
    maxFormBodyBytes: `${intFromEnv('MAX_FORM_BODY_BYTES', 32 * 1024)}b`,
    trustProxy: boolFromEnv('TRUST_PROXY', false),
    adminEnabled: boolFromEnv('ADMIN_ENABLED', true),
    registrationEnabled: boolFromEnv('REGISTRATION_ENABLED', true),
    adminSessionSecret: process.env.SESSION_SECRET ?? '',
    requireLogin: boolFromEnv('REQUIRE_LOGIN', true),
    logger: console,
  };

  return { ...config, ...overrides };
}
