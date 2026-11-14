/**
 * OAuth 2.0 error type. `error` / `error_description` follow RFC 6749 §5.2 so
 * that responses can be serialized verbatim.
 */
export class OAuthError extends Error {
  readonly status: number;
  readonly error: string;
  readonly description: string;
  readonly headers: Record<string, string>;

  constructor(
    status: number,
    error: string,
    description: string,
    headers: Record<string, string> = {},
  ) {
    super(description);
    this.name = 'OAuthError';
    this.status = status;
    this.error = error;
    this.description = description;
    this.headers = headers;
  }

  toResponseBody(): { error: string; error_description: string } {
    return { error: this.error, error_description: this.description };
  }
}

/** RFC 7591 §3.2.2 registration errors. */
export class RegistrationError extends Error {
  readonly status: number;
  readonly error: string;
  readonly description: string;

  constructor(status: number, error: string, description: string) {
    super(description);
    this.name = 'RegistrationError';
    this.status = status;
    this.error = error;
    this.description = description;
  }
}

export function invalidRequest(description: string): OAuthError {
  return new OAuthError(400, 'invalid_request', description);
}

export function invalidClient(description: string): OAuthError {
  return new OAuthError(401, 'invalid_client', description, {
    'WWW-Authenticate': 'Basic realm="oauth", charset="UTF-8"',
  });
}

export function invalidGrant(description: string): OAuthError {
  return new OAuthError(400, 'invalid_grant', description);
}

export function invalidScope(description: string): OAuthError {
  return new OAuthError(400, 'invalid_scope', description);
}

export function invalidDpopProof(description: string): OAuthError {
  return new OAuthError(400, 'invalid_dpop_proof', description);
}

export function unsupportedGrantType(description: string): OAuthError {
  return new OAuthError(400, 'unsupported_grant_type', description);
}

export function unauthorizedClient(description: string): OAuthError {
  return new OAuthError(400, 'unauthorized_client', description);
}
