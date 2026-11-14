import { Router, type NextFunction, type Request, type Response } from 'express';
import type { Store } from '../db/store.ts';
import type { ServerConfig } from '../config.ts';
import type { AuthenticatedClient } from '../oauth/clientAuth.ts';
import { authenticateClient } from '../oauth/clientAuth.ts';
import { OAuthError, invalidGrant, invalidRequest, unsupportedGrantType } from '../util/errors.ts';
import { newId, sha256Base64Url } from '../util/crypto.ts';
import { DpopError, normalizeHtu, verifyDpopProof, type DpopProof } from '../oauth/dpop.ts';
import { verifyPkce } from '../oauth/pkce.ts';
import { parseFormBody, rejectDuplicateParameters, sendOAuthError } from '../http/util.ts';
import type { IssuedTokens, TokenService } from '../oauth/tokens.ts';

/**
 * POST /token — authorization_code and refresh_token grants.
 *
 * Every successful response whose access token is DPoP-bound carries
 * `token_type: DPoP` (RFC 9449 §5). A DPoP proof, when presented, must pass
 * full validation plus single-use `jti` checking.
 */
export function tokenRouter(store: Store, config: ServerConfig, tokens: TokenService, dummyHash: string): Router {
  const router = Router();

  router.post('/token', (req: Request, res: Response, next: NextFunction) => {
    handleTokenRequest(req, res, store, config, tokens, dummyHash).catch(next);
  });

  return router;
}

async function handleTokenRequest(
  req: Request,
  res: Response,
  store: Store,
  config: ServerConfig,
  tokens: TokenService,
  dummyHash: string,
): Promise<void> {
  try {
    rejectDuplicateParameters(req);
  } catch (error) {
    sendOAuthError(res, error as OAuthError);
    return;
  }

  const body = parseFormBody(req);
  const now = Date.now();

  try {
    const authenticated = authenticateClient(store, config, req.get('authorization'), body, dummyHash);
    const proof = await verifyProof(req, store, config, authenticated, now);

    const grantType = body.grant_type;
    if (grantType === undefined || grantType === '') {
      throw invalidRequest('grant_type is required');
    }

    if (grantType === 'authorization_code') {
      handleAuthorizationCodeGrant({ body, authenticated, proof, store, tokens, now, res });
      return;
    }
    if (grantType === 'refresh_token') {
      handleRefreshTokenGrant({ body, authenticated, proof, store, tokens, now, res });
      return;
    }
    throw unsupportedGrantType('only authorization_code and refresh_token are supported');
  } catch (error) {
    if (error instanceof OAuthError) {
      sendOAuthError(res, error);
      return;
    }
    throw error;
  }
}

/**
 * Validates the DPoP proof, if any, and enforces the client's DPoP policy.
 * The `jti` is recorded before any grant processing so a replayed proof can
 * never be used twice, even concurrently.
 */
async function verifyProof(
  req: Request,
  store: Store,
  config: ServerConfig,
  authenticated: AuthenticatedClient,
  now: number,
): Promise<DpopProof | null> {
  const header = req.headers.dpop;
  if (Array.isArray(header)) {
    throw new OAuthError(400, 'invalid_dpop_proof', 'more than one DPoP request header was supplied');
  }
  // Node merges repeated header fields into one comma-separated value, and a
  // compact JWS can never contain a comma, so this detects duplicates too.
  if (typeof header === 'string' && header.includes(',')) {
    throw new OAuthError(400, 'invalid_dpop_proof', 'more than one DPoP request header was supplied');
  }
  if (typeof header !== 'string') {
    if (authenticated.client.requireDpop) {
      throw new OAuthError(400, 'invalid_dpop_proof', 'this client requires a DPoP proof');
    }
    return null;
  }

  const host = req.get('host');
  if (!host) throw invalidRequest('Host header is required');
  const pathname = (req.originalUrl || req.path || '/').split(/[?#]/)[0] || '/';
  const uri = normalizeHtu(`${req.protocol}://${host}${pathname}`);
  if (uri === null) throw invalidRequest('request URI could not be determined');

  let proof: DpopProof;
  try {
    proof = await verifyDpopProof(header, {
      method: req.method,
      uri,
      iatToleranceSeconds: config.dpopIatToleranceSeconds,
      futureSkewSeconds: config.dpopIatFutureSkewSeconds,
      now,
    });
  } catch (error) {
    if (error instanceof DpopError) throw new OAuthError(400, error.code, error.message);
    throw error;
  }

  const accepted = store.recordDpopJti(proof.jkt, proof.jti, now, now + config.dpopJtiRetentionSeconds * 1000);
  if (!accepted) {
    store.recordAudit('dpop_jti_replay', now, {
      clientId: authenticated.client.id,
      extra: { jkt: proof.jkt, jti: proof.jti },
    });
    throw new OAuthError(400, 'invalid_dpop_proof', 'DPoP proof jti has already been used');
  }

  return proof;
}

function handleAuthorizationCodeGrant(params: {
  body: Record<string, string>;
  authenticated: AuthenticatedClient;
  proof: DpopProof | null;
  store: Store;
  tokens: TokenService;
  now: number;
  res: Response;
}): void {
  const { body, authenticated, proof, store, tokens, now, res } = params;

  const code = body.code;
  if (code === undefined || code === '') throw invalidRequest('code is required');
  const redirectUri = body.redirect_uri;
  if (redirectUri === undefined || redirectUri === '') {
    // Required when the authorization request included it — this server always does.
    throw invalidRequest('redirect_uri is required');
  }

  const codeHash = sha256Base64Url(code);
  const record = store.getAuthorizationCode(codeHash);
  if (!record) throw invalidGrant('authorization code is invalid or has expired');

  if (record.clientId !== authenticated.client.id) {
    throw invalidGrant('authorization code was issued to another client');
  }

  // A second presentation is a replay: everything the code produced is revoked.
  if (record.consumedAt !== null || record.failedAt !== null) {
    tokens.handleAuthorizationCodeReplay(codeHash, now, {
      clientId: authenticated.client.id,
      reason: record.consumedAt !== null ? 'code_already_redeemed' : 'code_previously_failed',
    });
    throw invalidGrant('authorization code has already been used');
  }
  if (record.expiresAt <= now) throw invalidGrant('authorization code has expired');
  if (record.redirectUri !== redirectUri) {
    throw invalidGrant('redirect_uri does not match the authorization request');
  }

  // PKCE must be verified before anything is issued. On failure the code is
  // burned, so an attacker cannot keep guessing verifiers or race the client.
  const pkce = verifyPkce(body.code_verifier, record.codeChallenge);
  if (!pkce.ok) {
    store.markCodeFailed(codeHash, now);
    store.recordAudit('pkce_verification_failed', now, {
      clientId: authenticated.client.id,
      userId: record.userId,
      extra: { reason: pkce.reason },
    });
    throw invalidGrant(`PKCE verification failed: ${pkce.reason}`);
  }

  // RFC 9449 §10: when the authorization request carried dpop_jkt, the token
  // request proof must use the same key.
  if (record.dpopJkt !== null && proof?.jkt !== record.dpopJkt) {
    store.markCodeFailed(codeHash, now);
    throw invalidGrant('DPoP proof key does not match the dpop_jkt from the authorization request');
  }

  const accessTokenJkt = proof?.jkt ?? null;
  const isPublicClient = authenticated.client.tokenEndpointAuthMethod === 'none';
  const withRefreshToken =
    authenticated.client.grantTypes.includes('refresh_token') &&
    record.scope.includes('offline_access');

  // A public client's refresh token must be sender-constrained (RFC 9449 §5,
  // RFC 9700 §4.14). Client authentication covers confidential clients.
  if (withRefreshToken && isPublicClient && accessTokenJkt === null) {
    throw new OAuthError(
      400,
      'invalid_dpop_proof',
      'a DPoP proof is required to issue a refresh token to a public client',
    );
  }

  const familyId = newId();
  let issued: IssuedTokens;
  try {
    issued = store.transaction(() => {
      // Consume atomically: if another request won the race, treat this as a
      // replay rather than issuing a second set of tokens.
      if (!store.markCodeConsumed(codeHash, now, familyId)) {
        throw invalidGrant('authorization code has already been used');
      }
      return tokens.issueNewFamily({
        familyId,
        clientId: authenticated.client.id,
        userId: record.userId,
        scope: record.scope,
        accessTokenJkt,
        // Only a public client's refresh token is bound to the proof key;
        // confidential clients are constrained by client authentication.
        refreshBindingJkt: isPublicClient ? accessTokenJkt : null,
        withRefreshToken,
        now,
      });
    });
  } catch (error) {
    if (error instanceof OAuthError && error.error === 'invalid_grant') {
      tokens.handleAuthorizationCodeReplay(codeHash, now, {
        clientId: authenticated.client.id,
        reason: 'concurrent_redemption',
      });
    }
    throw error;
  }

  store.recordAudit('tokens_issued', now, {
    clientId: authenticated.client.id,
    userId: record.userId,
    extra: { grant: 'authorization_code', dpop: accessTokenJkt !== null, scope: issued.scope.join(' ') },
  });

  sendTokenResponse(res, issued);
}

function handleRefreshTokenGrant(params: {
  body: Record<string, string>;
  authenticated: AuthenticatedClient;
  proof: DpopProof | null;
  store: Store;
  tokens: TokenService;
  now: number;
  res: Response;
}): void {
  const { body, authenticated, proof, store, tokens, now, res } = params;

  const refreshToken = body.refresh_token;
  if (refreshToken === undefined || refreshToken === '') {
    throw invalidRequest('refresh_token is required');
  }
  if (!authenticated.client.grantTypes.includes('refresh_token')) {
    throw new OAuthError(400, 'unauthorized_client', 'client may not use the refresh_token grant');
  }

  let requestedScope: string[] | null = null;
  if (body.scope !== undefined) {
    requestedScope = body.scope.split(/\s+/).filter(Boolean);
    if (requestedScope.length === 0) throw invalidRequest('scope must not be empty when present');
  }

  const issued = tokens.rotateRefreshToken({
    refreshToken,
    clientId: authenticated.client.id,
    dpopJkt: proof?.jkt ?? null,
    senderConstrainedByKey: authenticated.client.tokenEndpointAuthMethod === 'none',
    requestedScope,
    now,
  });

  store.recordAudit('tokens_rotated', now, {
    clientId: authenticated.client.id,
    extra: { grant: 'refresh_token', familyId: issued.familyId },
  });

  sendTokenResponse(res, issued);
}

function sendTokenResponse(res: Response, issued: IssuedTokens): void {
  const payload: Record<string, unknown> = {
    access_token: issued.accessToken,
    // RFC 9449 §5: DPoP when the token is sender-constrained, else Bearer.
    token_type: issued.dpopJkt !== null ? 'DPoP' : 'Bearer',
    expires_in: issued.expiresIn,
    scope: issued.scope.join(' '),
  };
  if (issued.refreshToken !== null) payload.refresh_token = issued.refreshToken;
  res.status(200).json(payload);
}
