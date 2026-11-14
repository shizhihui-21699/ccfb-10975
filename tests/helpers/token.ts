import type { TestServer } from './server.ts';
import { DpopKey } from './dpop.ts';

export interface TokenResponse {
  status: number;
  headers: Headers;
  body: Record<string, unknown>;
}

export interface ClientAuth {
  /** Use client_secret_basic with this secret. */
  secret?: string;
  /** Send client_id/client_secret as form fields. */
  post?: boolean;
  /** Send no authentication at all (public client). */
  none?: boolean;
}

function basicAuth(clientId: string, secret: string): string {
  const encoded = `${encodeURIComponent(clientId)}:${encodeURIComponent(secret)}`;
  return `Basic ${Buffer.from(encoded, 'utf8').toString('base64')}`;
}

/**
 * POSTs the token endpoint. The DPoP proof is generated for the exact URI
 * (`/token`), so each key gets a fresh proof (and thus a fresh jti).
 */
export async function tokenRequest(
  server: TestServer,
  params: {
    form: Record<string, string>;
    clientId?: string;
    auth?: ClientAuth;
    dpopKey?: DpopKey;
    dpopProof?: string;
    headers?: Record<string, string>;
  },
): Promise<TokenResponse> {
  const headers = new Headers({ 'content-type': 'application/x-www-form-urlencoded' });
  for (const [key, value] of Object.entries(params.headers ?? {})) headers.set(key, value);

  const form = new URLSearchParams(params.form);
  const auth = params.auth ?? {};

  if (auth.none) {
    if (params.clientId !== undefined) form.set('client_id', params.clientId);
  } else if (auth.post) {
    if (params.clientId !== undefined) form.set('client_id', params.clientId);
    if (auth.secret !== undefined) form.set('client_secret', auth.secret);
  } else if (auth.secret !== undefined) {
    headers.set('authorization', basicAuth(params.clientId ?? '', auth.secret));
  }

  const uri = `${server.baseUrl}/token`;
  if (params.dpopProof !== undefined) {
    headers.set('dpop', params.dpopProof);
  } else if (params.dpopKey !== undefined) {
    headers.set('dpop', await params.dpopKey.proof({ uri, method: 'POST' }));
  }

  const response = await fetch(uri, { method: 'POST', headers, body: form.toString() });
  const text = await response.text();
  let body: Record<string, unknown> = {};
  if (text !== '') {
    try {
      body = JSON.parse(text) as Record<string, unknown>;
    } catch {
      body = { raw: text };
    }
  }
  return { status: response.status, headers: response.headers, body };
}

/** Introspection/revocation share the same client-auth shape. */
export async function managementRequest(
  server: TestServer,
  endpoint: '/introspect' | '/revoke',
  params: { form: Record<string, string>; clientId?: string; auth?: ClientAuth },
): Promise<{ status: number; body: Record<string, unknown>; headers: Headers }> {
  const headers = new Headers({ 'content-type': 'application/x-www-form-urlencoded' });
  const form = new URLSearchParams(params.form);
  const auth = params.auth ?? {};

  if (auth.none) {
    if (params.clientId !== undefined) form.set('client_id', params.clientId);
  } else if (auth.post) {
    if (params.clientId !== undefined) form.set('client_id', params.clientId);
    if (auth.secret !== undefined) form.set('client_secret', auth.secret);
  } else if (auth.secret !== undefined) {
    headers.set('authorization', basicAuth(params.clientId ?? '', auth.secret));
  }

  const response = await fetch(`${server.baseUrl}${endpoint}`, {
    method: 'POST',
    headers,
    body: form.toString(),
  });
  const text = await response.text();
  let body: Record<string, unknown> = {};
  if (text !== '') {
    try {
      body = JSON.parse(text) as Record<string, unknown>;
    } catch {
      body = { raw: text };
    }
  }
  return { status: response.status, body, headers: response.headers };
}
