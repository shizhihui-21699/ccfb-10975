import { Router, type Request, type Response } from 'express';
import type { Store } from '../db/store.ts';
import type { ServerConfig } from '../config.ts';
import { createRegisteredClient, DEFAULT_SCOPES } from '../oauth/clients.ts';
import { RegistrationError } from '../util/errors.ts';
import { normalizeRegistrationMetadata } from '../oauth/registration.ts';
import { escapeHtml, sendRegistrationError } from '../http/util.ts';

/**
 * RFC 7591 dynamic client registration.
 *
 * This deployment has no initial access token / software statement, so the
 * endpoint is either disabled or restricted to loopback callers by the
 * operator (see `registrationEnabled`).
 */
export function registerRouter(store: Store, config: ServerConfig): Router {
  const router = Router();

  router.post('/register', (req: Request, res: Response) => {
    if (!config.registrationEnabled) {
      res.status(404).json({ error: 'not_found', error_description: 'dynamic client registration is disabled' });
      return;
    }

    try {
      const contentType = req.get('content-type') ?? '';
      if (!contentType.toLowerCase().includes('application/json')) {
        throw new RegistrationError(415, 'invalid_client_metadata', 'registration requires application/json');
      }

      const raw: unknown = req.body;
      if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
        throw new RegistrationError(400, 'invalid_client_metadata', 'request body must be a JSON object');
      }
      const body = raw as Record<string, unknown>;

      const registration = normalizeRegistrationMetadata(body, {
        defaultScopes: DEFAULT_SCOPES,
        requireDpopByDefault: true,
      });

      const now = Date.now();
      const requestedId = typeof body.client_id === 'string' ? body.client_id : undefined;
      if (requestedId !== undefined && !/^[A-Za-z0-9._~-]{4,128}$/.test(requestedId)) {
        throw new RegistrationError(
          400,
          'invalid_client_metadata',
          'client_id must be 4-128 characters of [A-Za-z0-9._~-]',
        );
      }
      if (requestedId !== undefined && store.getClient(requestedId)) {
        throw new RegistrationError(400, 'invalid_client_metadata', 'client_id is already in use');
      }

      const { client, plaintextSecret } = createRegisteredClient(store, config, registration, requestedId, now);
      store.recordAudit('client_registered', now, {
        clientId: client.id,
        extra: {
          tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
          redirectUris: client.redirectUris,
        },
      });

      // RFC 7591 §3.2.1: 201 Created with the issued metadata.
      const response: Record<string, unknown> = {
        client_id: client.id,
        client_id_issued_at: Math.floor(client.createdAt / 1000),
        client_name: client.name,
        redirect_uris: client.redirectUris,
        grant_types: client.grantTypes,
        response_types: client.responseTypes,
        token_endpoint_auth_method: client.tokenEndpointAuthMethod,
        scope: client.scopes.join(' '),
      };
      if (plaintextSecret !== null) {
        response.client_secret = plaintextSecret;
        response.client_secret_expires_at = 0;
      }

      res.status(201).location(`/admin/clients/${encodeURIComponent(client.id)}`).json(response);
    } catch (error) {
      if (error instanceof RegistrationError) {
        sendRegistrationError(res, error);
        return;
      }
      throw error;
    }
  });

  return router;
}

/** Result page shared by dynamic registration and the admin "create client" form. */
export function renderRegistrationResult(clientId: string, secret: string | null): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Client registered</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;line-height:1.5}
code{background:#f4f4f4;padding:.2rem .4rem;border-radius:4px;word-break:break-all}
.warn{border-left:4px solid #b00020;padding:.75rem 1rem;background:#fff5f5}
</style></head><body>
<h1>Client registered</h1>
<div class="warn">The client secret below is shown once and cannot be retrieved later.</div>
<p>Client ID: <code>${escapeHtml(clientId)}</code></p>
${secret !== null ? `<p>Client secret: <code>${escapeHtml(secret)}</code></p>` : '<p>This is a public client; no secret was issued.</p>'}
<p><a href="/admin/clients/${encodeURIComponent(clientId)}">View client</a> · <a href="/admin">Back to admin</a></p>
</body></html>`;
}
