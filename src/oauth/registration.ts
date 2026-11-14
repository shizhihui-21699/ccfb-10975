import { RegistrationError } from '../util/errors.ts';

/**
 * Client metadata validation per RFC 7591 §2 and redirect URI rules per
 * RFC 9700 §4.1.2 / RFC 8252 §7.
 */

const FORBIDDEN_SCHEMES = new Set(['javascript', 'data', 'file', 'vbscript', 'about', 'blob']);

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

export interface RedirectUriClassification {
  uri: string;
  /** True when the host is a loopback address, which RFC 9700 allows a variable port for. */
  loopback: boolean;
  /** True for RFC 8252 private-use URI schemes (native apps). */
  nativeScheme: boolean;
}

/**
 * Validates one redirect URI. Returns the classification, or throws a
 * registration error naming the offending value.
 */
export function validateRedirectUri(raw: string): RedirectUriClassification {
  if (raw.length === 0) {
    throw new RegistrationError(400, 'invalid_redirect_uri', 'redirect_uris entries must not be empty');
  }
  if (raw.length > 2048) {
    throw new RegistrationError(400, 'invalid_redirect_uri', 'redirect_uris entries must be at most 2048 characters');
  }
  // Redirect URIs must be exact strings; a wildcard is never acceptable.
  if (raw.includes('*')) {
    throw new RegistrationError(400, 'invalid_redirect_uri', 'redirect_uris must be absolute URIs without wildcards');
  }

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new RegistrationError(400, 'invalid_redirect_uri', `redirect_uris entry is not an absolute URI: ${raw}`);
  }

  if (parsed.hash !== '') {
    throw new RegistrationError(400, 'invalid_redirect_uri', `redirect_uris must not contain a fragment: ${raw}`);
  }
  if (parsed.username !== '' || parsed.password !== '') {
    throw new RegistrationError(400, 'invalid_redirect_uri', `redirect_uris must not contain userinfo: ${raw}`);
  }

  const scheme = parsed.protocol.slice(0, -1).toLowerCase();
  if (FORBIDDEN_SCHEMES.has(scheme)) {
    throw new RegistrationError(400, 'invalid_redirect_uri', `redirect_uris must not use the ${scheme}: scheme`);
  }

  if (scheme === 'https') {
    return { uri: raw, loopback: false, nativeScheme: false };
  }

  if (scheme === 'http') {
    if (!LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase())) {
      throw new RegistrationError(
        400,
        'invalid_redirect_uri',
        `http redirect_uris are only permitted for loopback hosts (localhost, 127.0.0.1, [::1]): ${raw}`,
      );
    }
    return { uri: raw, loopback: true, nativeScheme: false };
  }

  // Private-use URI scheme for native apps (RFC 8252 §7.1). The scheme must
  // be a syntactically valid URI scheme and must carry a path or host.
  if (!/^[a-z][a-z0-9+.-]*$/.test(scheme)) {
    throw new RegistrationError(400, 'invalid_redirect_uri', `redirect_uris has an invalid scheme: ${raw}`);
  }
  if (parsed.hostname === '' && parsed.pathname === '') {
    throw new RegistrationError(
      400,
      'invalid_redirect_uri',
      `native-app redirect_uris must include a path or host: ${raw}`,
    );
  }
  return { uri: raw, loopback: false, nativeScheme: true };
}

export function validateRedirectUris(raw: unknown): { uris: string[]; classifications: RedirectUriClassification[] } {
  if (raw === undefined) {
    throw new RegistrationError(400, 'invalid_redirect_uri', 'redirect_uris is required');
  }
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new RegistrationError(400, 'invalid_redirect_uri', 'redirect_uris must be a non-empty array of strings');
  }
  if (raw.length > 20) {
    throw new RegistrationError(400, 'invalid_redirect_uri', 'redirect_uris must contain at most 20 entries');
  }
  const classifications: RedirectUriClassification[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    if (typeof entry !== 'string') {
      throw new RegistrationError(400, 'invalid_redirect_uri', 'redirect_uris entries must be strings');
    }
    if (seen.has(entry)) {
      throw new RegistrationError(400, 'invalid_redirect_uri', `redirect_uris contains a duplicate: ${entry}`);
    }
    seen.add(entry);
    classifications.push(validateRedirectUri(entry));
  }
  return { uris: classifications.map((c) => c.uri), classifications };
}

export type RedirectMatch =
  | { ok: true }
  | { ok: false; reason: 'not_registered' | 'port_mismatch_not_loopback' };

/**
 * Exact string match, with the single RFC 9700 exception: a loopback
 * redirect URI may vary its port (native apps that bind an ephemeral port).
 */
export function matchRedirectUri(
  requested: string,
  registered: RedirectUriClassification[],
): RedirectMatch {
  if (registered.some((entry) => entry.uri === requested)) return { ok: true };

  let requestedUrl: URL;
  try {
    requestedUrl = new URL(requested);
  } catch {
    return { ok: false, reason: 'not_registered' };
  }
  if (requestedUrl.hash !== '') return { ok: false, reason: 'not_registered' };

  for (const entry of registered) {
    if (!entry.loopback) continue;
    let registeredUrl: URL;
    try {
      registeredUrl = new URL(entry.uri);
    } catch {
      continue;
    }
    if (
      registeredUrl.protocol === requestedUrl.protocol &&
      registeredUrl.hostname.toLowerCase() === requestedUrl.hostname.toLowerCase() &&
      registeredUrl.pathname === requestedUrl.pathname &&
      registeredUrl.search === requestedUrl.search
    ) {
      // Only the port may differ, and only for a loopback host.
      return { ok: true };
    }
  }

  return { ok: false, reason: 'not_registered' };
}

const GRANT_TYPES = new Set(['authorization_code', 'refresh_token']);
const RESPONSE_TYPES = new Set(['code']);
const AUTH_METHODS = new Set(['none', 'client_secret_basic', 'client_secret_post']);

export interface NormalizedRegistration {
  clientName: string;
  redirectUris: string[];
  redirectClassifications: RedirectUriClassification[];
  grantTypes: string[];
  responseTypes: string[];
  tokenEndpointAuthMethod: 'none' | 'client_secret_basic' | 'client_secret_post';
  requireDpop: boolean;
  scope: string[];
}

function stringArray(raw: unknown, field: string, allowed: Set<string>): string[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new RegistrationError(400, 'invalid_client_metadata', `${field} must be a non-empty array of strings`);
  }
  const values: string[] = [];
  for (const entry of raw) {
    if (typeof entry !== 'string') {
      throw new RegistrationError(400, 'invalid_client_metadata', `${field} entries must be strings`);
    }
    if (!allowed.has(entry)) {
      throw new RegistrationError(400, 'invalid_client_metadata', `${field} contains an unsupported value: ${entry}`);
    }
    if (!values.includes(entry)) values.push(entry);
  }
  return values;
}

export function normalizeRegistrationMetadata(
  body: Record<string, unknown>,
  options: { defaultScopes: string[]; requireDpopByDefault: boolean },
): NormalizedRegistration {
  const clientName = typeof body.client_name === 'string' && body.client_name.trim() !== ''
    ? body.client_name.trim().slice(0, 200)
    : 'Unnamed client';

  const redirect = validateRedirectUris(body.redirect_uris);

  const grantTypes = body.grant_types === undefined
    ? ['authorization_code']
    : stringArray(body.grant_types, 'grant_types', GRANT_TYPES);

  const responseTypes = body.response_types === undefined
    ? ['code']
    : stringArray(body.response_types, 'response_types', RESPONSE_TYPES);

  // RFC 7591 §2.1: response_type "code" corresponds to grant_type "authorization_code".
  if (responseTypes.includes('code') && !grantTypes.includes('authorization_code')) {
    throw new RegistrationError(
      400,
      'invalid_client_metadata',
      'response_types code requires grant_types to include authorization_code',
    );
  }

  let tokenEndpointAuthMethod: NormalizedRegistration['tokenEndpointAuthMethod'] = 'client_secret_basic';
  if (body.token_endpoint_auth_method !== undefined) {
    if (typeof body.token_endpoint_auth_method !== 'string' || !AUTH_METHODS.has(body.token_endpoint_auth_method)) {
      throw new RegistrationError(
        400,
        'invalid_client_metadata',
        'token_endpoint_auth_method must be one of none, client_secret_basic, client_secret_post',
      );
    }
    tokenEndpointAuthMethod = body.token_endpoint_auth_method as NormalizedRegistration['tokenEndpointAuthMethod'];
  }

  let scope = options.defaultScopes;
  if (body.scope !== undefined) {
    if (typeof body.scope !== 'string') {
      throw new RegistrationError(400, 'invalid_client_metadata', 'scope must be a space-delimited string');
    }
    scope = body.scope.split(/\s+/).filter(Boolean);
  }

  // DPoP is mandatory for public clients: a public client has no client
  // secret, so the proof key is the only sender-constraint available.
  const requireDpop = tokenEndpointAuthMethod === 'none' ? true : options.requireDpopByDefault;
  if (tokenEndpointAuthMethod === 'none' && grantTypes.includes('refresh_token') && !requireDpop) {
    throw new RegistrationError(
      400,
      'invalid_client_metadata',
      'public clients requesting refresh_token require DPoP',
    );
  }

  return {
    clientName,
    redirectUris: redirect.uris,
    redirectClassifications: redirect.classifications,
    grantTypes,
    responseTypes,
    tokenEndpointAuthMethod,
    requireDpop,
    scope,
  };
}
