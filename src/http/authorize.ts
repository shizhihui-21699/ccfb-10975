import { Router, type NextFunction, type Request, type Response } from 'express';
import type { Store } from '../db/store.ts';
import type { ServerConfig } from '../config.ts';
import type { AuthorizationRequestParams, ClientRecord } from '../types.ts';
import { matchRedirectUri, validateRedirectUri, type RedirectUriClassification } from '../oauth/registration.ts';
import { isValidCodeChallenge } from '../oauth/pkce.ts';
import { newId, randomToken, sha256Base64Url } from '../util/crypto.ts';
import { buildRedirectUri, escapeHtml } from '../http/util.ts';
import { csrfTokenFor, readCookie, SESSION_COOKIE, verifyCsrf } from '../http/session.ts';

/** How long a user has to decide on a consent screen. */
const PENDING_TTL_MS = 10 * 60 * 1000;

const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'Confirm your identity',
  profile: 'Read your basic profile information',
  email: 'Read your email address',
  offline_access: 'Stay signed in and act on your behalf after you leave',
};

/**
 * An authorization-request error. `redirectable` is false when the client or
 * redirect URI could not be trusted, in which case the error is rendered
 * locally instead of being sent to an unverified destination
 * (RFC 6749 §4.1.2.1).
 */
class AuthorizeError extends Error {
  readonly error: string;
  readonly description: string;
  readonly redirectUri: string | null;
  readonly state: string | null;

  constructor(
    error: string,
    description: string,
    redirectUri: string | null,
    state: string | null,
  ) {
    super(description);
    this.error = error;
    this.description = description;
    this.redirectUri = redirectUri;
    this.state = state;
  }
}

function readSingle(query: Record<string, unknown>, name: string): string | null {
  const value = query[name];
  if (value === undefined) return null;
  if (typeof value !== 'string') {
    throw new Error(`parameter ${name} must not be repeated`);
  }
  return value;
}

function classificationsOf(client: ClientRecord): RedirectUriClassification[] {
  const out: RedirectUriClassification[] = [];
  for (const uri of client.redirectUris) {
    try {
      out.push(validateRedirectUri(uri));
    } catch {
      // Stored values are validated on write; ignore any that cannot be parsed.
    }
  }
  return out;
}

function parseAuthorizeRequest(
  rawQuery: unknown,
  store: Store,
): { client: ClientRecord; params: AuthorizationRequestParams } {
  if (rawQuery === null || typeof rawQuery !== 'object' || Array.isArray(rawQuery)) {
    throw new AuthorizeError('invalid_request', 'malformed query string', null, null);
  }
  const query = rawQuery as Record<string, unknown>;
  const state = typeof query.state === 'string' ? query.state : null;

  let clientId: string | null;
  try {
    clientId = readSingle(query, 'client_id');
  } catch {
    throw new AuthorizeError('invalid_request', 'client_id must not be repeated', null, state);
  }
  if (!clientId) {
    throw new AuthorizeError('invalid_request', 'client_id is required', null, state);
  }
  const client = store.getClient(clientId);
  if (!client || client.disabled) {
    throw new AuthorizeError('invalid_request', 'unknown or disabled client', null, state);
  }

  let redirectUri: string | null;
  try {
    redirectUri = readSingle(query, 'redirect_uri');
  } catch {
    throw new AuthorizeError('invalid_request', 'redirect_uri must not be repeated', null, state);
  }
  if (!redirectUri) {
    throw new AuthorizeError('invalid_request', 'redirect_uri is required', null, state);
  }
  const match = matchRedirectUri(redirectUri, classificationsOf(client));
  if (!match.ok) {
    throw new AuthorizeError(
      'invalid_request',
      'redirect_uri is not registered for this client',
      null,
      state,
    );
  }

  // The client and redirect URI are now trusted: further errors are returned
  // to the client via the redirect URI.
  const fail = (error: string, description: string): never => {
    throw new AuthorizeError(error, description, redirectUri, state);
  };

  let parsed: {
    response_type: string | null;
    code_challenge: string | null;
    code_challenge_method: string | null;
    scope: string | null;
    nonce: string | null;
    dpop_jkt: string | null;
  };
  try {
    parsed = {
      response_type: readSingle(query, 'response_type'),
      code_challenge: readSingle(query, 'code_challenge'),
      code_challenge_method: readSingle(query, 'code_challenge_method'),
      scope: readSingle(query, 'scope'),
      nonce: readSingle(query, 'nonce'),
      dpop_jkt: readSingle(query, 'dpop_jkt'),
    };
  } catch (error) {
    return fail('invalid_request', (error as Error).message);
  }

  if (parsed.response_type === null) {
    fail('invalid_request', 'response_type is required');
  }
  if (parsed.response_type !== 'code') {
    fail('unsupported_response_type', 'only response_type=code is supported');
  }
  if (!client.responseTypes.includes('code')) {
    fail('unauthorized_client', 'this client may not use response_type=code');
  }
  if (!client.grantTypes.includes('authorization_code')) {
    fail('unauthorized_client', 'this client may not use the authorization_code grant');
  }

  // PKCE is mandatory for every client. Accepting a request without it would
  // let an intercepted code be redeemed (RFC 9700 §2.1.1).
  if (!parsed.code_challenge) {
    fail(
      'invalid_request',
      'code_challenge is required: this server requires PKCE with the authorization code flow',
    );
  }
  if (parsed.code_challenge_method !== 'S256') {
    fail('invalid_request', "code_challenge_method must be 'S256'");
  }
  if (!isValidCodeChallenge(parsed.code_challenge ?? '')) {
    fail('invalid_request', 'code_challenge is not a valid S256 challenge');
  }

  let scope: string[];
  if (parsed.scope === null || parsed.scope === '') {
    scope = client.scopes;
  } else {
    scope = parsed.scope.split(/\s+/).filter(Boolean);
    if (scope.length !== new Set(scope).size) {
      fail('invalid_scope', 'scope must not contain duplicate values');
    }
    const notAllowed = scope.filter((s) => !client.scopes.includes(s));
    if (notAllowed.length > 0) {
      fail('invalid_scope', `scope not registered for this client: ${notAllowed.join(' ')}`);
    }
  }
  if (scope.length === 0) {
    fail('invalid_scope', 'at least one scope is required');
  }

  if (parsed.nonce !== null && (parsed.nonce.length < 8 || parsed.nonce.length > 512)) {
    fail('invalid_request', 'nonce must be between 8 and 512 characters');
  }

  // RFC 9449 §10: optional binding of the authorization code to the client's
  // proof key. When present, the token request's proof must use the same key.
  if (parsed.dpop_jkt !== null && !/^[A-Za-z0-9_-]{43}$/.test(parsed.dpop_jkt)) {
    fail('invalid_request', 'dpop_jkt must be a base64url SHA-256 JWK thumbprint');
  }

  return {
    client,
    params: {
      clientId: client.id,
      redirectUri,
      scope,
      state,
      codeChallenge: parsed.code_challenge ?? '',
      codeChallengeMethod: 'S256',
      nonce: parsed.nonce,
      dpopJkt: parsed.dpop_jkt,
    },
  };
}

function renderErrorPage(error: string, description: string, status = 400): { status: number; body: string } {
  return {
    status,
    body: `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Authorization error</title>
<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#111;line-height:1.5}
h1{color:#b00020;font-size:1.35rem}code{background:#f4f4f4;padding:.15rem .35rem;border-radius:4px}</style>
</head><body>
<h1>Authorization request rejected</h1>
<p><code>${escapeHtml(error)}</code></p>
<p>${escapeHtml(description)}</p>
<p>This request could not be redirected to the client because the client identifier or redirect URI could not be verified.</p>
</body></html>`,
  };
}

export function authorizeRouter(store: Store, config: ServerConfig): Router {
  const router = Router();

  router.get('/authorize', (req: Request, res: Response, next: NextFunction) => {
    let parsed: ReturnType<typeof parseAuthorizeRequest>;
    try {
      parsed = parseAuthorizeRequest(req.query, store);
    } catch (error) {
      if (error instanceof AuthorizeError) {
        if (error.redirectUri !== null) {
          res.redirect(
            302,
            buildRedirectUri(error.redirectUri, {
              error: error.error,
              error_description: error.description,
              state: error.state,
            }),
          );
          return;
        }
        const page = renderErrorPage(error.error, error.description);
        res.status(page.status).type('html').send(page.body);
        return;
      }
      next(error);
      return;
    }

    if (!req.user) {
      // Preserve the full authorization request across the login round-trip.
      const query = new URLSearchParams();
      for (const [key, value] of Object.entries(req.query as Record<string, unknown>)) {
        if (typeof value === 'string') query.append(key, value);
      }
      const target = `/authorize?${query.toString()}`;
      res.redirect(302, `/login?next=${encodeURIComponent(target)}`);
      return;
    }

    const now = Date.now();
    const pendingId = newId();
    store.insertPendingAuthorization({
      id: pendingId,
      userId: req.user.id,
      clientId: parsed.client.id,
      params: parsed.params,
      createdAt: now,
      expiresAt: now + PENDING_TTL_MS,
    });

    res.status(200).type('html').send(renderConsentPage(parsed.client, parsed.params, pendingId, config, req));
  });

  router.post('/authorize', (req: Request, res: Response) => {
    if (!req.user) {
      res.redirect(302, '/login');
      return;
    }
    if (!verifyCsrf(req, config.adminSessionSecret)) {
      const page = renderErrorPage('invalid_request', 'form expired or CSRF validation failed');
      res.status(page.status).type('html').send(page.body);
      return;
    }
    const body = req.body as Record<string, unknown>;
    const pendingId = typeof body.pending_id === 'string' ? body.pending_id : '';
    const pending = store.getPendingAuthorization(pendingId);

    if (!pending || pending.userId !== req.user.id || pending.expiresAt <= Date.now()) {
      if (pending) store.deletePendingAuthorization(pending.id);
      const page = renderErrorPage('invalid_request', 'this authorization request has expired; start again');
      res.status(page.status).type('html').send(page.body);
      return;
    }

    store.deletePendingAuthorization(pending.id);
    const { params } = pending;

    if (body.decision !== 'allow') {
      store.recordAudit('authorization_denied', Date.now(), {
        clientId: params.clientId,
        userId: req.user.id,
      });
      res.redirect(
        302,
        buildRedirectUri(params.redirectUri, {
          error: 'access_denied',
          error_description: 'the resource owner denied the request',
          state: params.state,
        }),
      );
      return;
    }

    const now = Date.now();
    const code = randomToken(32);
    store.insertAuthorizationCode({
      codeHash: sha256Base64Url(code),
      clientId: params.clientId,
      userId: req.user.id,
      redirectUri: params.redirectUri,
      scope: params.scope,
      codeChallenge: params.codeChallenge,
      codeChallengeMethod: 'S256',
      nonce: params.nonce,
      dpopJkt: params.dpopJkt,
      issuedAt: now,
      expiresAt: now + config.authorizationCodeTtlSeconds * 1000,
      consumedAt: null,
      familyId: null,
      failedAt: null,
    });
    store.recordAudit('authorization_code_issued', now, {
      clientId: params.clientId,
      userId: req.user.id,
      extra: { scope: params.scope.join(' '), keyBound: params.dpopJkt !== null },
    });

    res.redirect(302, buildRedirectUri(params.redirectUri, { code, state: params.state }));
  });

  return router;
}

function renderConsentPage(
  client: ClientRecord,
  params: AuthorizationRequestParams,
  pendingId: string,
  config: ServerConfig,
  req: Request,
): string {
  // The CSRF token is bound to the session cookie, so a cross-site form
  // cannot mint a valid value.
  const sessionCookie = readCookie(req, SESSION_COOKIE) ?? '';
  const csrf = csrfTokenFor(sessionCookie, config.adminSessionSecret);

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize ${escapeHtml(client.name)}</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;color:#111;line-height:1.5}
h1{font-size:1.4rem}.card{border:1px solid #e2e2e2;border-radius:12px;padding:1.5rem}
ul{padding-left:1.2rem}li{margin:.35rem 0}
.actions{display:flex;gap:.75rem;margin-top:1.5rem}
button{font-size:1rem;padding:.6rem 1.4rem;border-radius:8px;border:1px solid #333;cursor:pointer}
.allow{background:#14532d;color:#fff;border-color:#14532d}.deny{background:#fff;color:#333}
.meta{color:#666;font-size:.85rem;margin-top:1rem;word-break:break-all}
</style></head><body>
<h1>Authorization request</h1>
<div class="card">
<p><strong>${escapeHtml(client.name)}</strong> wants to access your account.</p>
<ul>${params.scope
    .map((s) => `<li><strong>${escapeHtml(s)}</strong> &mdash; ${escapeHtml(SCOPE_DESCRIPTIONS[s] ?? 'Granted by this client')}</li>`)
    .join('')}</ul>
<p class="meta">You will be returned to <code>${escapeHtml(params.redirectUri)}</code></p>
<form method="post" action="/authorize">
  <input type="hidden" name="pending_id" value="${escapeHtml(pendingId)}">
  <input type="hidden" name="csrf_token" value="${escapeHtml(csrf)}">
  <div class="actions">
    <button class="allow" type="submit" name="decision" value="allow">Allow</button>
    <button class="deny" type="submit" name="decision" value="deny">Deny</button>
  </div>
</form>
</div>
</body></html>`;
}
