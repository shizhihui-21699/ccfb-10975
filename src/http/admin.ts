import { Router, type NextFunction, type Request, type Response } from 'express';
import type { Store } from '../db/store.ts';
import type { ServerConfig } from '../config.ts';
import type { TokenFamilyRecord } from '../types.ts';
import { escapeHtml } from '../http/util.ts';
import { csrfTokenFor, readCookie, SESSION_COOKIE, verifyCsrf } from '../http/session.ts';
import { ensureSessionSecret } from '../http/csrf.ts';
import { normalizeRegistrationMetadata } from '../oauth/registration.ts';
import { RegistrationError } from '../util/errors.ts';
import { createRegisteredClient } from '../oauth/clients.ts';
import { renderRegistrationResult } from '../http/register.ts';
import { requireAdmin } from '../http/session.ts';

const PAGE_STYLE = `
body{font-family:system-ui,-apple-system,sans-serif;margin:0;color:#111;background:#fafafa}
header{background:#111;color:#fff;padding:.9rem 1.5rem;display:flex;justify-content:space-between;align-items:center}
header a{color:#fff;text-decoration:none} header nav a{margin-left:1.25rem;font-size:.9rem;opacity:.85}
main{max-width:64rem;margin:2rem auto;padding:0 1.5rem}
h1{font-size:1.5rem;margin:0 0 1.25rem} h2{font-size:1.1rem;margin:2rem 0 .75rem}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e5e5e5;border-radius:8px;overflow:hidden;font-size:.9rem}
th,td{text-align:left;padding:.6rem .8rem;border-bottom:1px solid #eee;vertical-align:top}
th{background:#f4f4f4;font-weight:600;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em;color:#555}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.82rem;word-break:break-all}
.pill{display:inline-block;padding:.12rem .5rem;border-radius:999px;font-size:.75rem;font-weight:600}
.ok{background:#dcfce7;color:#14532d}.bad{background:#fee2e2;color:#991b1b}
.muted{color:#666;font-size:.85rem}
form.inline{display:inline}
button{font:inherit;font-size:.82rem;padding:.3rem .7rem;border-radius:6px;border:1px solid #bbb;background:#fff;cursor:pointer}
button.danger{border-color:#b00020;color:#b00020}
.card{background:#fff;border:1px solid #e5e5e5;border-radius:10px;padding:1.25rem;margin-bottom:1.5rem}
label{display:block;font-size:.85rem;font-weight:600;margin:.9rem 0 .3rem}
input,select,textarea{width:100%;box-sizing:border-box;padding:.5rem .6rem;font-size:.9rem;border:1px solid #bbb;border-radius:7px;font-family:inherit}
textarea{min-height:4rem}
`;

function layout(title: string, body: string, user: string | null): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${escapeHtml(title)} · OAuth Admin</title>
<style>${PAGE_STYLE}</style></head><body>
<header><a href="/admin"><strong>OAuth Authorization Server</strong></a>
<nav><a href="/admin">Clients</a><a href="/admin/tokens">Tokens</a><a href="/admin/audit">Audit</a>
${user ? `<span class="muted" style="margin-left:1.25rem">Signed in as ${escapeHtml(user)}</span>
<form class="inline" method="post" action="/logout" style="margin-left:1.25rem"><button>Sign out</button></form>` : ''}
</nav></header>
<main>${body}</main></body></html>`;
}

function statusPill(active: boolean, onText = 'active', offText = 'revoked'): string {
  return `<span class="pill ${active ? 'ok' : 'bad'}">${active ? onText : offText}</span>`;
}

function formatTime(ms: number): string {
  return new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}

export function adminRouter(store: Store, config: ServerConfig): Router {
  const router = Router();
  const secret = ensureSessionSecret(config);

  router.use('/admin', requireAdmin);

  router.get('/admin', (req: Request, res: Response) => {
    const clients = store.listClients();
    const now = Date.now();
    const stats = {
      clients: clients.length,
      activeAccess: store.countActiveAccessTokens(now),
      activeRefresh: store.countActiveRefreshTokens(now),
      families: store.listFamilies().filter((f) => f.revokedAt === null).length,
    };
    const csrf = csrfTokenFor(readCookie(req, SESSION_COOKIE) ?? '', secret);

    const rows = clients
      .map((client) => {
        const active = !client.disabled;
        return `<tr>
<td><a href="/admin/clients/${encodeURIComponent(client.id)}">${escapeHtml(client.name)}</a><br><span class="mono muted">${escapeHtml(client.id)}</span></td>
<td class="mono">${escapeHtml(client.tokenEndpointAuthMethod)}</td>
<td>${client.redirectUris.map((uri) => escapeHtml(uri)).join('<br>')}</td>
<td>${escapeHtml(client.grantTypes.join(' '))}</td>
<td>${client.requireDpop ? statusPill(true, 'required', '') : statusPill(false, 'n/a', 'optional')}</td>
<td>${statusPill(active, 'enabled', 'disabled')}</td>
</tr>`;
      })
      .join('\n');

    res.status(200).type('html').send(
      layout(
        'Clients',
        `<h1>Overview</h1>
<div class="card"><table><tr>
<th>Clients</th><th>Active access tokens</th><th>Active refresh tokens</th><th>Live token families</th></tr>
<tr><td>${stats.clients}</td><td>${stats.activeAccess}</td><td>${stats.activeRefresh}</td><td>${stats.families}</td></tr></table></div>

<h2>Registered clients</h2>
<table><thead><tr><th>Client</th><th>Auth method</th><th>Redirect URIs</th><th>Grant types</th><th>DPoP</th><th>Status</th></tr></thead>
<tbody>${rows || '<tr><td colspan="6" class="muted">No clients registered</td></tr>'}</tbody></table>

<h2>Register a client</h2>
<div class="card">
<form method="post" action="/admin/clients">
  <input type="hidden" name="csrf_token" value="${escapeHtml(csrf)}">
  <label for="client_name">Client name</label>
  <input id="client_name" name="client_name" required maxlength="200">
  <label for="redirect_uris">Redirect URIs (one per line)</label>
  <textarea id="redirect_uris" name="redirect_uris" required placeholder="https://app.example.com/callback&#10;http://localhost:3000/callback"></textarea>
  <label for="token_endpoint_auth_method">Client type</label>
  <select id="token_endpoint_auth_method" name="token_endpoint_auth_method">
    <option value="client_secret_basic">Confidential (client_secret_basic)</option>
    <option value="client_secret_post">Confidential (client_secret_post)</option>
    <option value="none">Public (PKCE + DPoP only)</option>
  </select>
  <label for="scope">Scopes</label>
  <input id="scope" name="scope" value="openid profile email offline_access">
  <label><input type="checkbox" name="require_dpop" value="true" checked style="width:auto"> Require DPoP for every token request</label>
  <p><button type="submit">Create client</button></p>
</form>
</div>`,
        req.user?.username ?? null,
      ),
    );
  });

  router.post('/admin/clients', (req: Request, res: Response) => {
    const body = req.body as Record<string, unknown>;
    if (!verifyCsrf(req, secret)) {
      res.status(400).send(layout('Error', '<p>Form expired. Reload and try again.</p>', req.user?.username ?? null));
      return;
    }

    const redirectUris = typeof body.redirect_uris === 'string'
      ? body.redirect_uris.split(/\r?\n|\s+/).map((v) => v.trim()).filter(Boolean)
      : [];

    try {
      const registration = normalizeRegistrationMetadata(
        {
          client_name: body.client_name,
          redirect_uris: redirectUris,
          token_endpoint_auth_method: body.token_endpoint_auth_method,
          scope: body.scope,
          require_dpop: body.require_dpop === 'true' ? true : undefined,
        },
        { defaultScopes: ['openid', 'profile', 'email', 'offline_access'], requireDpopByDefault: true },
      );
      const now = Date.now();
      const { client, plaintextSecret } = createRegisteredClient(store, config, registration, undefined, now);
      store.recordAudit('client_registered', now, {
        clientId: client.id,
        userId: req.user?.id ?? null,
        extra: { via: 'admin_ui' },
      });
      res.status(201).type('html').send(
        layout('Client created', renderRegistrationResult(client.id, plaintextSecret), req.user?.username ?? null),
      );
    } catch (error) {
      if (error instanceof RegistrationError) {
        res.status(error.status).type('html').send(
          layout('Error', `<p class="pill bad">${escapeHtml(error.error)}</p><p>${escapeHtml(error.description)}</p><p><a href="/admin">Back</a></p>`, req.user?.username ?? null),
        );
        return;
      }
      throw error;
    }
  });

  router.get('/admin/clients/:id', (req: Request, res: Response, next: NextFunction) => {
    const rawId = req.params.id;
    const client = store.getClient(typeof rawId === 'string' ? rawId : '');
    if (!client) {
      next();
      return;
    }
    const now = Date.now();
    const families = store.listFamilies().filter((f) => f.clientId === client.id);
    const refresh = store.listRefreshTokens().filter((rt) => families.some((f) => f.id === rt.familyId));
    const access = store.listAccessTokens().filter((at) => at.clientId === client.id);

    res.status(200).type('html').send(
      layout(
        client.name,
        `<h1>${escapeHtml(client.name)}</h1>
<p class="muted mono">${escapeHtml(client.id)}</p>
<div class="card">
<table>
<tr><th>Auth method</th><td class="mono">${escapeHtml(client.tokenEndpointAuthMethod)}</td></tr>
<tr><th>Scopes</th><td class="mono">${escapeHtml(client.scopes.join(' '))}</td></tr>
<tr><th>Grant types</th><td class="mono">${escapeHtml(client.grantTypes.join(' '))}</td></tr>
<tr><th>Requires DPoP</th><td>${client.requireDpop ? 'yes' : 'no'}</td></tr>
<tr><th>Status</th><td>${client.disabled ? statusPill(false, 'enabled', 'disabled') : statusPill(true, 'enabled', 'disabled')}</td></tr>
<tr><th>Created</th><td>${formatTime(client.createdAt)}</td></tr>
</table>
</div>

<h2>Redirect URIs</h2>
<table><thead><tr><th>URI</th></tr></thead><tbody>
${client.redirectUris.map((uri) => `<tr><td class="mono">${escapeHtml(uri)}</td></tr>`).join('')}
</tbody></table>

<h2>Token families (${families.length})</h2>
<table><thead><tr><th>Family</th><th>Scope</th><th>Created</th><th>Status</th></tr></thead><tbody>
${families
  .map(
    (family) => `<tr><td class="mono">${escapeHtml(family.id.slice(0, 8))}…</td>
<td class="mono">${escapeHtml(family.scope.join(' '))}</td>
<td>${formatTime(family.createdAt)}</td>
<td>${family.revokedAt === null ? statusPill(true, 'live', 'revoked') : `<span class="pill bad" title="${escapeHtml(family.revokedReason ?? '')}">revoked</span> <span class="muted">${escapeHtml(family.revokedReason ?? '')}</span>`}</td></tr>`,
  )
  .join('') || '<tr><td colspan="4" class="muted">none</td></tr>'}
</tbody></table>

<h2>Refresh tokens (${refresh.length})</h2>
<table><thead><tr><th>Generation</th><th>Issued</th><th>Expires</th><th>State</th></tr></thead><tbody>
${refresh
  .map(
    (rt) => `<tr><td>${rt.generation}</td><td>${formatTime(rt.issuedAt)}</td><td>${formatTime(rt.expiresAt)}</td>
<td>${rt.revokedAt !== null ? 'revoked' : rt.usedAt !== null ? 'used (rotated)' : rt.expiresAt <= now ? 'expired' : 'live'}</td></tr>`,
  )
  .join('') || '<tr><td colspan="4" class="muted">none</td></tr>'}
</tbody></table>

<h2>Access tokens (${access.length})</h2>
<table><thead><tr><th>JTI</th><th>Scope</th><th>Issued</th><th>Expires</th><th>DPoP key</th><th>State</th></tr></thead><tbody>
${access
  .map(
    (at) => `<tr><td class="mono">${escapeHtml(at.jti.slice(0, 8))}…</td><td class="mono">${escapeHtml(at.scope.join(' '))}</td>
<td>${formatTime(at.issuedAt)}</td><td>${formatTime(at.expiresAt)}</td>
<td class="mono">${at.dpopJkt ? `${escapeHtml(at.dpopJkt.slice(0, 10))}…` : '—'}</td>
<td>${at.revokedAt !== null ? 'revoked' : at.expiresAt <= now ? 'expired' : 'live'}</td></tr>`,
  )
  .join('') || '<tr><td colspan="6" class="muted">none</td></tr>'}
</tbody></table>

<p><a href="/admin">← All clients</a></p>`,
        req.user?.username ?? null,
      ),
    );
  });

  router.get('/admin/tokens', (req: Request, res: Response) => {
    const now = Date.now();
    const families: TokenFamilyRecord[] = store.listFamilies();
    const refresh = store.listRefreshTokens();
    const access = store.listAccessTokens();
    const replays = store.listReplayMarkers();

    const familyRows = families
      .map((family) => {
        const live = family.revokedAt === null;
        return `<tr><td class="mono">${escapeHtml(family.id.slice(0, 12))}…</td>
<td class="mono">${escapeHtml(family.clientId)}</td><td class="mono">${escapeHtml(family.scope.join(' '))}</td>
<td>${live ? statusPill(true, 'live', 'revoked') : `${statusPill(false, 'live', 'revoked')} <span class="muted">${escapeHtml(family.revokedReason ?? '')}</span>`}</td></tr>`;
      })
      .join('');

    const replayRows = replays
      .map(
        (marker) => `<tr><td class="mono">${escapeHtml(marker.tokenHash.slice(0, 16))}…</td><td>${escapeHtml(marker.tokenType)}</td>
<td class="mono">${marker.familyId ? escapeHtml(marker.familyId.slice(0, 12)) + '…' : '—'}</td><td>${formatTime(marker.detectedAt)}</td></tr>`,
      )
      .join('');

    res.status(200).type('html').send(
      layout(
        'Active tokens',
        `<h1>Active tokens</h1>
<div class="card"><table><tr><th>Active access tokens</th><th>Active refresh tokens</th></tr>
<tr><td>${access.filter((a) => a.revokedAt === null && a.expiresAt > now).length}</td>
<td>${refresh.filter((r) => r.revokedAt === null && r.usedAt === null && r.expiresAt > now).length}</td></tr></table></div>

<h2>Token families (${families.length})</h2>
<table><thead><tr><th>Family</th><th>Client</th><th>Scope</th><th>Status</th></tr></thead><tbody>
${familyRows || '<tr><td colspan="4" class="muted">none</td></tr>'}</tbody></table>

<h2>Replay detections (${replays.length})</h2>
<table><thead><tr><th>Token digest</th><th>Type</th><th>Family</th><th>Detected</th></tr></thead><tbody>
${replayRows || '<tr><td colspan="4" class="muted">No replays detected</td></tr>'}</tbody></table>`,
        req.user?.username ?? null,
      ),
    );
  });

  router.get('/admin/audit', (req: Request, res: Response) => {
    const events = store.listAuditEvents(200);
    res.status(200).type('html').send(
      layout(
        'Audit log',
        `<h1>Audit log</h1>
<table><thead><tr><th>Time</th><th>Event</th><th>Client</th><th>User</th><th>Detail</th></tr></thead><tbody>
${events
  .map(
    (event) => `<tr><td>${formatTime(event.ts)}</td><td class="mono">${escapeHtml(event.event)}</td>
<td class="mono">${escapeHtml(event.clientId ?? '—')}</td><td class="mono">${escapeHtml(event.userId ?? '—')}</td>
<td class="mono">${escapeHtml(event.detail ? JSON.stringify(event.detail) : '—')}</td></tr>`,
  )
  .join('') || '<tr><td colspan="5" class="muted">No events</td></tr>'}
</tbody></table>`,
        req.user?.username ?? null,
      ),
    );
  });

  return router;
}
