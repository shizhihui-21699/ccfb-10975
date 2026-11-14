import { Router, type Request, type Response } from 'express';
import type { Store } from '../db/store.ts';
import type { ServerConfig } from '../config.ts';
import { createSession, verifyPassword, verifyPasswordForUnknownUser } from '../oauth/clients.ts';
import { escapeHtml } from '../http/util.ts';
import {
  readCookie,
  SESSION_COOKIE,
  sessionCookieOptions,
} from '../http/session.ts';
import { sha256Base64Url } from '../util/crypto.ts';

const SESSION_TTL_SECONDS = 8 * 60 * 60;

export function loginRouter(store: Store, config: ServerConfig): Router {
  const router = Router();
  router.get('/login', (req: Request, res: Response) => {
    const next = typeof req.query.next === 'string' ? req.query.next : '';
    if (req.user) {
      res.redirect(next === '' ? '/' : safeNextPath(next));
      return;
    }
    res.status(200).type('html').send(renderLoginPage(next, null));
  });

  router.post('/login', (req: Request, res: Response) => {
    const body = req.body as Record<string, unknown>;
    const username = typeof body.username === 'string' ? body.username : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const next = typeof body.next === 'string' ? body.next : '';

    // Uniform failure message: never reveal whether the username exists.
    const failure = (): void => {
      res.status(401).type('html').send(renderLoginPage(next, 'Invalid username or password'));
    };

    const user = store.getUserByUsername(username);
    if (!user) {
      verifyPasswordForUnknownUser(password, config);
      failure();
      return;
    }
    if (!verifyPassword(user, password, config)) {
      failure();
      return;
    }

    const now = Date.now();
    const session = createSession(now, SESSION_TTL_SECONDS);
    store.insertSession({
      idHash: session.idHash,
      userId: user.id,
      createdAt: now,
      expiresAt: session.expiresAt,
      lastSeenAt: now,
    });
    store.recordAudit('login_succeeded', now, { userId: user.id });

    const secure = config.baseUrl.startsWith('https://');
    res.cookie(SESSION_COOKIE, session.sessionId, sessionCookieOptions(secure));
    res.redirect(302, next === '' ? '/' : safeNextPath(next));
  });

  router.post('/logout', (req: Request, res: Response) => {
    const cookie = readCookie(req, SESSION_COOKIE);
    if (cookie) store.deleteSession(sha256Base64Url(cookie));
    res.clearCookie(SESSION_COOKIE, { path: '/' });
    res.redirect(302, '/login');
  });

  return router;
}

/** Only allow same-site absolute paths as a post-login redirect target. */
export function safeNextPath(next: string): string {
  if (!next.startsWith('/') || next.startsWith('//') || next.includes('\\')) return '/';
  if (next.startsWith('/login')) return '/';
  return next;
}

function renderLoginPage(next: string, error: string | null): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign in</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;max-width:26rem;margin:5rem auto;padding:0 1rem;color:#111}
h1{font-size:1.4rem;margin-bottom:1.5rem}
label{display:block;font-size:.9rem;margin:.9rem 0 .3rem;color:#333}
input{width:100%;box-sizing:border-box;padding:.6rem .7rem;font-size:1rem;border:1px solid #bbb;border-radius:8px}
button{margin-top:1.4rem;width:100%;font-size:1rem;padding:.7rem;border-radius:8px;border:0;background:#14532d;color:#fff;cursor:pointer}
.err{background:#fff5f5;border-left:4px solid #b00020;padding:.6rem .8rem;margin-bottom:1rem;font-size:.9rem}
</style></head><body>
<h1>Sign in</h1>
${error ? `<div class="err">${escapeHtml(error)}</div>` : ''}
<form method="post" action="/login">
  <input type="hidden" name="next" value="${escapeHtml(next)}">
  <label for="username">Username</label>
  <input id="username" name="username" autocomplete="username" required autofocus>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Sign in</button>
</form>
</body></html>`;
}
