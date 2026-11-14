import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import type { Store } from './db/store.ts';
import type { ServerConfig } from './config.ts';
import { TokenService } from './oauth/tokens.ts';
import { makeDummyHash } from './oauth/clientAuth.ts';
import { noStore, sendOAuthError } from './http/util.ts';
import { sessionMiddleware } from './http/session.ts';
import { authorizeRouter } from './http/authorize.ts';
import { tokenRouter } from './http/token.ts';
import { tokenManagementRouter } from './http/tokenManagement.ts';
import { registerRouter } from './http/register.ts';
import { loginRouter } from './http/login.ts';
import { adminRouter } from './http/admin.ts';
import { resourceRouter } from './http/resource.ts';
import { authorizationServerMetadata, pruneUndefined } from './http/metadata.ts';
import { OAuthError } from './util/errors.ts';

export interface AppDependencies {
  store: Store;
  config: ServerConfig;
}

export function createApp({ store, config }: AppDependencies): Express {
  const app = express();
  const tokens = new TokenService(store, config);
  const dummyHash = makeDummyHash(config);

  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);

  // All token-endpoint traffic is form-encoded; registration is JSON.
  app.use(express.urlencoded({ extended: false, limit: config.maxFormBodyBytes, parameterLimit: 100 }));
  app.use(express.json({ limit: config.maxFormBodyBytes }));

  // A small set of hardening headers; no inline script is used anywhere, so
  // a strict CSP is safe.
  app.use((_req: Request, res: Response, next: NextFunction) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('X-Frame-Options', 'DENY');
    res.set('Referrer-Policy', 'no-referrer');
    res.set(
      'Content-Security-Policy',
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    );
    next();
  });

  app.use(sessionMiddleware(store));

  // Discovery (RFC 8414), both at the well-known location and at /metadata.
  const metadata = pruneUndefined(authorizationServerMetadata(config));
  app.get('/.well-known/oauth-authorization-server', (_req, res) => {
    res.status(200).json(metadata);
  });
  app.get('/metadata', (_req, res) => {
    res.status(200).json(metadata);
  });

  // Token, introspection and revocation responses must never be cached.
  app.use('/token', noStore);
  app.use('/introspect', noStore);
  app.use('/revoke', noStore);

  app.use(authorizeRouter(store, config));
  app.use(tokenRouter(store, config, tokens, dummyHash));
  app.use(tokenManagementRouter(store, config, tokens, dummyHash));
  app.use(registerRouter(store, config));
  app.use(resourceRouter(store, config, tokens));
  app.use(loginRouter(store, config));
  if (config.adminEnabled) {
    app.use(adminRouter(store, config));
  }

  app.get('/', (_req: Request, res: Response) => {
    res.redirect(302, config.adminEnabled ? '/admin' : '/login');
  });

  app.get('/healthz', (_req: Request, res: Response) => {
    res.status(200).json({ status: 'ok' });
  });

  app.use((_req: Request, res: Response) => {
    res.status(404).type('text/plain').send('Not found');
  });

  // Central error handler: OAuth-aware errors become protocol responses,
  // everything else is a generic 500 with no internal detail leaked.
  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (error instanceof OAuthError) {
      sendOAuthError(res, error);
      return;
    }
    const status = typeof error === 'object' && error !== null && 'status' in error
      ? Number((error as { status: unknown }).status)
      : 500;
    if (status === 413) {
      res.status(413).json({ error: 'invalid_request', error_description: 'request body is too large' });
      return;
    }
    if (status >= 400 && status < 500) {
      res.status(status).json({ error: 'invalid_request', error_description: 'malformed request' });
      return;
    }
    config.logger.error('unhandled_error', {
      message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    res.status(500).json({ error: 'server_error', error_description: 'an unexpected error occurred' });
  });

  return app;
}
