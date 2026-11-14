import type { NextFunction, Request, Response } from 'express';
import { OAuthError, RegistrationError } from '../util/errors.ts';

/** RFC 6749 §5.1 requires token responses never be cached. */
export function noStore(_req: Request, res: Response, next: NextFunction): void {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
  next();
}

/** Numeric `expires` / `timestamp` fields must be integers or the request is malformed. */
export function parseFormBody(req: Request): Record<string, string> {
  const body: unknown = req.body;
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return {};
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(body as Record<string, unknown>)) {
    if (typeof value === 'string') out[key] = value;
  }
  return out;
}

/**
 * RFC 6749 §3.1: request parameters must not appear twice. Express's
 * urlencoded parser collapses duplicates, so this inspects the raw body.
 */
export function rejectDuplicateParameters(req: Request): void {
  const raw: unknown = req.body;
  if (raw === null || typeof raw !== 'object') return;
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    if (Array.isArray(value)) {
      throw new OAuthError(400, 'invalid_request', `parameter ${key} must not be repeated`);
    }
  }
}

export function sendOAuthError(res: Response, error: OAuthError): void {
  for (const [header, value] of Object.entries(error.headers)) {
    res.set(header, value);
  }
  res.status(error.status).json(error.toResponseBody());
}

export function sendRegistrationError(res: Response, error: RegistrationError): void {
  res.status(error.status).json({ error: error.error, error_description: error.description });
}

/** Maps an unknown thrown value onto an OAuth error, defaulting to server_error. */
export function asOAuthError(error: unknown): OAuthError {
  if (error instanceof OAuthError) return error;
  return new OAuthError(500, 'server_error', 'an unexpected error occurred');
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Builds an authorization response URI. Existing query parameters on the
 * registered redirect URI are preserved (RFC 6749 §3.1.2), and `state` is
 * echoed when present.
 */
export function buildRedirectUri(
  redirectUri: string,
  params: Record<string, string | null | undefined>,
): string {
  const url = new URL(redirectUri);
  for (const [key, value] of Object.entries(params)) {
    if (value === null || value === undefined) continue;
    url.searchParams.set(key, value);
  }
  return url.toString();
}
