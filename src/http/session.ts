import type { NextFunction, Request, Response } from 'express';
import type { Store } from '../db/store.ts';
import type { UserRecord } from '../types.ts';
import { sha256Base64Url, timingSafeEqualString } from '../util/crypto.ts';

declare module 'express-serve-static-core' {
  interface Request {
    user?: UserRecord;
  }
}

export const SESSION_COOKIE = 'oauth_session';

export function readCookie(req: Request, name: string): string | null {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const trimmed = part.trim();
    const separator = trimmed.indexOf('=');
    if (separator === -1) continue;
    if (trimmed.slice(0, separator) === name) {
      return decodeURIComponent(trimmed.slice(separator + 1));
    }
  }
  return null;
}

export function sessionCookieOptions(secure: boolean): {
  httpOnly: true;
  sameSite: 'lax';
  secure: boolean;
  path: string;
  maxAge: number;
} {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure,
    path: '/',
    maxAge: 8 * 60 * 60 * 1000,
  };
}

/**
 * Attaches `req.user` when a valid session cookie is presented. Never rejects;
 * endpoints decide whether authentication is required.
 */
export function sessionMiddleware(store: Store) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const cookie = readCookie(req, SESSION_COOKIE);
    if (!cookie) {
      next();
      return;
    }
    const idHash = sha256Base64Url(cookie);
    const session = store.getSession(idHash);
    if (!session || session.expiresAt <= Date.now()) {
      next();
      return;
    }
    const user = store.getUser(session.userId);
    if (user) {
      req.user = user;
      store.touchSession(idHash, Date.now());
    }
    next();
  };
}

export function requireUser(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.redirect('/login');
    return;
  }
  next();
}

export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.redirect('/login');
    return;
  }
  if (req.user.role !== 'admin') {
    res.status(403).send('Access denied: administrator privileges required');
    return;
  }
  next();
}

/**
 * Basic CSRF defence for state-changing browser forms: the form carries a
 * per-session nonce, and the session cookie is SameSite=Lax. The nonce is
 * derived from the session digest so no extra storage is needed.
 */
export function csrfTokenFor(sessionCookieValue: string, secret: string): string {
  return sha256Base64Url(`${sessionCookieValue}:${secret}`);
}

export function verifyCsrf(req: Request, secret: string): boolean {
  const submitted = parseBodyField(req, 'csrf_token');
  if (typeof submitted !== 'string' || submitted === '') return false;
  const cookie = readCookie(req, SESSION_COOKIE);
  if (!cookie) return false;
  return timingSafeEqualString(csrfTokenFor(cookie, secret), submitted);
}

function parseBodyField(req: Request, field: string): unknown {
  const body: unknown = req.body;
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return undefined;
  return (body as Record<string, unknown>)[field];
}
