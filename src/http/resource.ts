import { Router, type NextFunction, type Request, type Response } from 'express';
import type { Store } from '../db/store.ts';
import type { ServerConfig } from '../config.ts';
import { normalizeHtu, verifyDpopProof, DpopError } from '../oauth/dpop.ts';
import type { TokenService } from '../oauth/tokens.ts';
import { OAuthError } from '../util/errors.ts';

/**
 * A minimal DPoP-protected resource endpoint, included so the `ath` half of
 * RFC 9449 is exercised end to end rather than only described. A real
 * deployment would put this in each resource server; here it doubles as a
 * reference implementation of §7.
 *
 *   GET /userinfo
 *   Authorization: DPoP <access token>
 *   DPoP: <proof with ath>
 */
export function resourceRouter(store: Store, config: ServerConfig, tokens: TokenService): Router {
  const router = Router();

  router.get('/userinfo', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const authorization = req.get('authorization');
      const match = /^DPoP\s+(\S+)\s*$/i.exec(authorization ?? '');
      if (!match) {
        challenge(res, 'invalid_token', 'a DPoP-bound access token is required');
        return;
      }
      const accessToken = match[1] ?? '';
      const proofHeader = req.headers.dpop;
      if (typeof proofHeader !== 'string' || proofHeader === '') {
        challenge(res, 'invalid_dpop_proof', 'a DPoP proof is required');
        return;
      }

      const host = req.get('host');
      if (!host) throw new OAuthError(400, 'invalid_request', 'Host header is required');
      const pathname = (req.originalUrl || req.path || '/').split(/[?#]/)[0] || '/';
      const uri = normalizeHtu(`${req.protocol}://${host}${pathname}`);
      if (uri === null) throw new OAuthError(400, 'invalid_request', 'request URI could not be determined');

      const now = Date.now();
      let jkt: string;
      try {
        const proof = await verifyDpopProof(proofHeader, {
          method: req.method,
          uri,
          accessToken,
          iatToleranceSeconds: config.dpopIatToleranceSeconds,
          futureSkewSeconds: config.dpopIatFutureSkewSeconds,
          now,
        });
        jkt = proof.jkt;
        if (!store.recordDpopJti(proof.jkt, proof.jti, now, now + config.dpopJtiRetentionSeconds * 1000)) {
          challenge(res, 'invalid_dpop_proof', 'DPoP proof jti has already been used');
          return;
        }
      } catch (error) {
        if (error instanceof DpopError) {
          challenge(res, error.code, error.message);
          return;
        }
        throw error;
      }

      // The key in the proof must be the key the token is bound to.
      const record = tokens.validateAccessToken(accessToken, now, jkt);
      if (!record) {
        challenge(res, 'invalid_token', 'the access token is invalid, expired or bound to another key');
        return;
      }

      const user = store.getUser(record.userId);
      if (!user) {
        challenge(res, 'invalid_token', 'the token subject no longer exists');
        return;
      }

      const body: Record<string, unknown> = { sub: user.id };
      if (record.scope.includes('profile')) {
        body.name = user.displayName;
        body.preferred_username = user.username;
      }
      if (record.scope.includes('email')) {
        body.email = `${user.username}@example.com`;
        body.email_verified = true;
      }
      res.set('Cache-Control', 'no-store');
      res.status(200).json(body);
    } catch (error) {
      next(error);
    }
  });

  return router;
}

function challenge(res: Response, error: string, description: string): void {
  res.set(
    'WWW-Authenticate',
    `DPoP realm="resource", error="${error}", error_description="${description.replace(/"/g, "'")}", algs="ES256 ES384 RS256 PS256 EdDSA"`,
  );
  res.set('Cache-Control', 'no-store');
  res.status(401).json({ error, error_description: description });
}
