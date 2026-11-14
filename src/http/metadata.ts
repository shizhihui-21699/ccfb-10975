import type { ServerConfig } from '../config.ts';

/**
 * RFC 8414 authorization-server metadata. Only the endpoints this server
 * implements are advertised, plus the capability flags that tell clients
 * PKCE is required and DPoP is supported.
 */
export function authorizationServerMetadata(config: ServerConfig): Record<string, unknown> {
  return {
    issuer: config.issuer,
    authorization_endpoint: `${config.baseUrl}/authorize`,
    token_endpoint: `${config.baseUrl}/token`,
    introspection_endpoint: `${config.baseUrl}/introspect`,
    revocation_endpoint: `${config.baseUrl}/revoke`,
    registration_endpoint: config.registrationEnabled ? `${config.baseUrl}/register` : undefined,
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    revocation_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    introspection_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    code_challenge_methods_supported: ['S256'],
    dpop_signing_alg_values_supported: [
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
    ],
    // RFC 9449 §7.1 registers this metadata member; it tells clients every
    // token is a DPoP token when a proof is presented.
    dpop_bound_access_tokens: true,
  };
}

export function pruneUndefined(record: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(record).filter(([, value]) => value !== undefined));
}
