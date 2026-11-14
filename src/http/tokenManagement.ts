import { Router, type Request, type Response } from 'express';
import type { Store } from '../db/store.ts';
import type { ServerConfig } from '../config.ts';
import { authenticateClient } from '../oauth/clientAuth.ts';
import { OAuthError } from '../util/errors.ts';
import { parseFormBody, rejectDuplicateParameters, sendOAuthError } from '../http/util.ts';
import type { TokenService } from '../oauth/tokens.ts';
import { sha256Base64Url } from '../util/crypto.ts';

/**
 * RFC 7662 introspection and RFC 7009 revocation, both client-authenticated.
 *
 * Both endpoints are deliberately uninformative about tokens that do not
 * belong to the calling client: introspection reports `active: false` and
 * revocation reports success (RFC 7009 §2.2 treats unknown tokens as success).
 */
export function tokenManagementRouter(
  store: Store,
  config: ServerConfig,
  tokens: TokenService,
  dummyHash: string,
): Router {
  const router = Router();

  router.post('/introspect', (req: Request, res: Response) => {
    try {
      rejectDuplicateParameters(req);
      const body = parseFormBody(req);
      const authenticated = authenticateClient(store, config, req.get('authorization'), body, dummyHash);
      const token = body.token;
      if (token === undefined || token === '') {
        throw new OAuthError(400, 'invalid_request', 'token is required');
      }

      const now = Date.now();
      const info = introspect(token, authenticated.client.id, store, config, tokens, now);
      res.status(200).json(info);
    } catch (error) {
      if (error instanceof OAuthError) {
        sendOAuthError(res, error);
        return;
      }
      throw error;
    }
  });

  router.post('/revoke', (req: Request, res: Response) => {
    try {
      rejectDuplicateParameters(req);
      const body = parseFormBody(req);
      const authenticated = authenticateClient(store, config, req.get('authorization'), body, dummyHash);
      const token = body.token;
      if (token === undefined || token === '') {
        throw new OAuthError(400, 'invalid_request', 'token is required');
      }

      const hint = body.token_type_hint;
      if (hint !== undefined && hint !== 'access_token' && hint !== 'refresh_token') {
        // RFC 7009 §2.1: an unrecognized hint is ignored, not an error.
      }

      const now = Date.now();
      revoke(token, hint, authenticated.client.id, store, tokens, now);

      // RFC 7009 §2.2: 200 whether or not the token existed.
      res.status(200).end();
    } catch (error) {
      if (error instanceof OAuthError) {
        sendOAuthError(res, error);
        return;
      }
      throw error;
    }
  });

  return router;
}

function introspect(
  token: string,
  callerClientId: string,
  store: Store,
  config: ServerConfig,
  tokens: TokenService,
  now: number,
): Record<string, unknown> {
  const tokenHash = sha256Base64Url(token);

  const access = store.getAccessToken(tokenHash);
  if (access) {
    if (access.clientId !== callerClientId) {
      // Do not disclose the existence of another client's token.
      return { active: false };
    }
    const usable = access.revokedAt === null && access.expiresAt > now;
    if (!usable) return { active: false };
    return {
      active: true,
      scope: access.scope.join(' '),
      client_id: access.clientId,
      token_type: access.dpopJkt !== null ? 'DPoP' : 'Bearer',
      exp: Math.floor(access.expiresAt / 1000),
      iat: Math.floor(access.issuedAt / 1000),
      sub: access.userId,
      aud: access.clientId,
      iss: config.issuer,
      jti: access.jti,
      // RFC 9449 §6.2: the resource server compares this to the proof key.
      ...(access.dpopJkt !== null ? { cnf: { jkt: access.dpopJkt } } : {}),
    };
  }

  const refresh = store.getRefreshToken(tokenHash);
  if (refresh) {
    const family = store.getFamily(refresh.familyId);
    if (!family || family.clientId !== callerClientId) return { active: false };
    const usable =
      refresh.revokedAt === null &&
      refresh.usedAt === null &&
      refresh.expiresAt > now &&
      family.revokedAt === null;
    if (!usable) return { active: false };
    return {
      active: true,
      scope: family.scope.join(' '),
      client_id: family.clientId,
      token_type: family.dpopJkt !== null ? 'DPoP' : 'Bearer',
      exp: Math.floor(refresh.expiresAt / 1000),
      iat: Math.floor(refresh.issuedAt / 1000),
      sub: family.userId,
      aud: family.clientId,
      iss: config.issuer,
      ...(family.dpopJkt !== null ? { cnf: { jkt: family.dpopJkt } } : {}),
    };
  }

  // Unknown, expired and malformed tokens are all simply inactive.
  void tokens;
  return { active: false };
}

function revoke(
  token: string,
  hint: string | undefined,
  callerClientId: string,
  store: Store,
  tokens: TokenService,
  now: number,
): void {
  const tokenHash = sha256Base64Url(token);

  const revokeAccess = (): boolean => {
    const record = store.getAccessToken(tokenHash);
    if (!record || record.clientId !== callerClientId) return false;
    tokens.revokeAccessToken(token, now, 'client_revocation');
    return true;
  };
  const revokeRefresh = (): boolean => {
    const record = store.getRefreshToken(tokenHash);
    if (!record) return false;
    const family = store.getFamily(record.familyId);
    if (!family || family.clientId !== callerClientId) return false;
    tokens.revokeRefreshToken(token, now, 'client_revocation');
    return true;
  };

  // RFC 7009 §2.1: the hint only orders the lookup; both types are searched.
  if (hint === 'access_token') {
    if (!revokeAccess()) revokeRefresh();
    return;
  }
  if (hint === 'refresh_token') {
    if (!revokeRefresh()) revokeAccess();
    return;
  }
  if (!revokeAccess()) revokeRefresh();
}
