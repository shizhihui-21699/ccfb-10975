import { DatabaseSync } from 'node:sqlite';
import { SCHEMA_SQL } from './schema.ts';
import type {
  AccessTokenRecord,
  AuditEventRecord,
  AuthorizationCodeRecord,
  AuthorizationRequestParams,
  ClientRecord,
  Millis,
  PendingAuthorizationRecord,
  RefreshTokenRecord,
  SessionRecord,
  TokenEndpointAuthMethod,
  TokenFamilyRecord,
  UserRecord,
} from '../types.ts';

type Row = Record<string, unknown>;

function str(v: unknown): string {
  if (typeof v === 'string') return v;
  throw new TypeError(`expected string, got ${typeof v}`);
}

function nullableStr(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  if (typeof v === 'string') return v;
  throw new TypeError(`expected string|null, got ${typeof v}`);
}

function num(v: unknown): number {
  if (typeof v === 'number') return v;
  if (typeof v === 'bigint') return Number(v);
  throw new TypeError(`expected number, got ${typeof v}`);
}

function nullableNum(v: unknown): number | null {
  if (v === null || v === undefined) return null;
  return num(v);
}

function bool(v: unknown): boolean {
  return num(v) !== 0;
}

function jsonArray(v: unknown): string[] {
  const parsed: unknown = JSON.parse(str(v));
  if (!Array.isArray(parsed)) throw new TypeError('expected JSON array');
  return parsed.map((item) => {
    if (typeof item !== 'string') throw new TypeError('expected JSON array of strings');
    return item;
  });
}

function jsonObject(v: unknown): Record<string, unknown> | null {
  const parsed: unknown = JSON.parse(str(v));
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new TypeError('expected JSON object');
  }
  return parsed as Record<string, unknown>;
}

function toClient(row: Row): ClientRecord {
  return {
    id: str(row.id),
    name: str(row.name),
    secretHash: nullableStr(row.secret_hash),
    redirectUris: jsonArray(row.redirect_uris),
    grantTypes: jsonArray(row.grant_types),
    responseTypes: jsonArray(row.response_types),
    scopes: jsonArray(row.scopes),
    tokenEndpointAuthMethod: str(row.token_endpoint_auth_method) as TokenEndpointAuthMethod,
    requireDpop: bool(row.require_dpop),
    disabled: bool(row.disabled),
    createdAt: num(row.created_at),
    updatedAt: num(row.updated_at),
  };
}

function toUser(row: Row): UserRecord {
  return {
    id: str(row.id),
    username: str(row.username),
    passwordHash: str(row.password_hash),
    displayName: str(row.display_name),
    role: str(row.role) === 'admin' ? 'admin' : 'user',
    createdAt: num(row.created_at),
  };
}

function toSession(row: Row): SessionRecord {
  return {
    idHash: str(row.id_hash),
    userId: str(row.user_id),
    createdAt: num(row.created_at),
    expiresAt: num(row.expires_at),
    lastSeenAt: num(row.last_seen_at),
  };
}

function toPendingAuthorization(row: Row): PendingAuthorizationRecord {
  const params = jsonObject(row.params);
  if (!params) throw new TypeError('pending authorization params must be an object');
  return {
    id: str(row.id),
    userId: str(row.user_id),
    clientId: str(row.client_id),
    params: params as unknown as AuthorizationRequestParams,
    createdAt: num(row.created_at),
    expiresAt: num(row.expires_at),
  };
}

function toAuthorizationCode(row: Row): AuthorizationCodeRecord {
  const method = str(row.code_challenge_method);
  if (method !== 'S256') throw new TypeError(`unsupported stored challenge method ${method}`);
  return {
    codeHash: str(row.code_hash),
    clientId: str(row.client_id),
    userId: str(row.user_id),
    redirectUri: str(row.redirect_uri),
    scope: jsonArray(row.scope),
    codeChallenge: str(row.code_challenge),
    codeChallengeMethod: 'S256',
    nonce: nullableStr(row.nonce),
    dpopJkt: nullableStr(row.dpop_jkt),
    issuedAt: num(row.issued_at),
    expiresAt: num(row.expires_at),
    consumedAt: nullableNum(row.consumed_at),
    familyId: nullableStr(row.family_id),
    failedAt: nullableNum(row.failed_at),
  };
}

function toFamily(row: Row): TokenFamilyRecord {
  return {
    id: str(row.id),
    clientId: str(row.client_id),
    userId: str(row.user_id),
    scope: jsonArray(row.scope),
    dpopJkt: nullableStr(row.dpop_jkt),
    createdAt: num(row.created_at),
    revokedAt: nullableNum(row.revoked_at),
    revokedReason: nullableStr(row.revoked_reason),
  };
}

function toRefreshToken(row: Row): RefreshTokenRecord {
  return {
    tokenHash: str(row.token_hash),
    familyId: str(row.family_id),
    generation: num(row.generation),
    issuedAt: num(row.issued_at),
    expiresAt: num(row.expires_at),
    usedAt: nullableNum(row.used_at),
    revokedAt: nullableNum(row.revoked_at),
    replacedByHash: nullableStr(row.replaced_by_hash),
  };
}

function toAccessToken(row: Row): AccessTokenRecord {
  return {
    tokenHash: str(row.token_hash),
    familyId: nullableStr(row.family_id),
    clientId: str(row.client_id),
    userId: str(row.user_id),
    scope: jsonArray(row.scope),
    issuedAt: num(row.issued_at),
    expiresAt: num(row.expires_at),
    revokedAt: nullableNum(row.revoked_at),
    dpopJkt: nullableStr(row.dpop_jkt),
    jti: str(row.jti),
  };
}

function toAuditEvent(row: Row): AuditEventRecord {
  return {
    id: num(row.id),
    ts: num(row.ts),
    event: str(row.event),
    clientId: nullableStr(row.client_id),
    userId: nullableStr(row.user_id),
    detail: row.detail === null || row.detail === undefined ? null : jsonObject(row.detail),
  };
}

export interface NewClientInput {
  id: string;
  name: string;
  secretHash: string | null;
  redirectUris: string[];
  grantTypes: string[];
  responseTypes: string[];
  scopes: string[];
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  requireDpop: boolean;
}

export interface NewFamilyInput {
  id: string;
  clientId: string;
  userId: string;
  scope: string[];
  dpopJkt: string | null;
  createdAt: Millis;
}

export interface NewRefreshTokenInput {
  tokenHash: string;
  familyId: string;
  generation: number;
  issuedAt: Millis;
  expiresAt: Millis;
}

export interface NewAccessTokenInput {
  tokenHash: string;
  familyId: string | null;
  clientId: string;
  userId: string;
  scope: string[];
  issuedAt: Millis;
  expiresAt: Millis;
  dpopJkt: string | null;
  jti: string;
}

export class Store {
  readonly db: DatabaseSync;
  private txDepth = 0;

  constructor(filename: string) {
    this.db = new DatabaseSync(filename);
    this.db.exec(SCHEMA_SQL);
  }

  close(): void {
    this.db.close();
  }

  /** Runs `fn` inside a write transaction; rolls back on any thrown error. */
  transaction<T>(fn: () => T): T {
    if (this.txDepth > 0) {
      // Already inside a transaction: reuse it (SQLite has no nested BEGIN).
      this.txDepth += 1;
      try {
        return fn();
      } finally {
        this.txDepth -= 1;
      }
    }
    this.db.exec('BEGIN IMMEDIATE');
    this.txDepth = 1;
    try {
      const result = fn();
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        // A failed rollback is not more interesting than the original error.
      }
      throw error;
    } finally {
      this.txDepth = 0;
    }
  }

  // ---------------------------------------------------------------- clients

  insertClient(input: NewClientInput, now: Millis): ClientRecord {
    this.db
      .prepare(
        `INSERT INTO clients (id, name, secret_hash, redirect_uris, grant_types, response_types,
                              scopes, token_endpoint_auth_method, require_dpop, disabled,
                              created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
      )
      .run(
        input.id,
        input.name,
        input.secretHash,
        JSON.stringify(input.redirectUris),
        JSON.stringify(input.grantTypes),
        JSON.stringify(input.responseTypes),
        JSON.stringify(input.scopes),
        input.tokenEndpointAuthMethod,
        input.requireDpop ? 1 : 0,
        now,
        now,
      );
    const row = this.db.prepare('SELECT * FROM clients WHERE id = ?').get(input.id);
    if (!row) throw new Error('insertClient: row vanished');
    return toClient(row);
  }

  getClient(id: string): ClientRecord | null {
    const row = this.db.prepare('SELECT * FROM clients WHERE id = ?').get(id);
    return row ? toClient(row) : null;
  }

  listClients(): ClientRecord[] {
    return this.db
      .prepare('SELECT * FROM clients ORDER BY created_at DESC')
      .all()
      .map((row) => toClient(row));
  }

  updateClient(id: string, patch: Partial<NewClientInput> & { disabled?: boolean }, now: Millis): void {
    const sets: string[] = ['updated_at = ?'];
    const values: Array<string | number | null> = [now];
    if (patch.name !== undefined) {
      sets.push('name = ?');
      values.push(patch.name);
    }
    if (patch.secretHash !== undefined) {
      sets.push('secret_hash = ?');
      values.push(patch.secretHash);
    }
    if (patch.redirectUris !== undefined) {
      sets.push('redirect_uris = ?');
      values.push(JSON.stringify(patch.redirectUris));
    }
    if (patch.grantTypes !== undefined) {
      sets.push('grant_types = ?');
      values.push(JSON.stringify(patch.grantTypes));
    }
    if (patch.responseTypes !== undefined) {
      sets.push('response_types = ?');
      values.push(JSON.stringify(patch.responseTypes));
    }
    if (patch.scopes !== undefined) {
      sets.push('scopes = ?');
      values.push(JSON.stringify(patch.scopes));
    }
    if (patch.tokenEndpointAuthMethod !== undefined) {
      sets.push('token_endpoint_auth_method = ?');
      values.push(patch.tokenEndpointAuthMethod);
    }
    if (patch.requireDpop !== undefined) {
      sets.push('require_dpop = ?');
      values.push(patch.requireDpop ? 1 : 0);
    }
    if (patch.disabled !== undefined) {
      sets.push('disabled = ?');
      values.push(patch.disabled ? 1 : 0);
    }
    this.db.prepare(`UPDATE clients SET ${sets.join(', ')} WHERE id = ?`).run(...values, id);
  }

  deleteClient(id: string): void {
    this.db.prepare('DELETE FROM clients WHERE id = ?').run(id);
  }

  // ------------------------------------------------------------------ users

  insertUser(input: Omit<UserRecord, 'createdAt'>, now: Millis): UserRecord {
    this.db
      .prepare('INSERT INTO users (id, username, password_hash, display_name, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(input.id, input.username, input.passwordHash, input.displayName, input.role, now);
    const row = this.db.prepare('SELECT * FROM users WHERE id = ?').get(input.id);
    if (!row) throw new Error('insertUser: row vanished');
    return toUser(row);
  }

  getUser(id: string): UserRecord | null {
    const row = this.db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    return row ? toUser(row) : null;
  }

  getUserByUsername(username: string): UserRecord | null {
    const row = this.db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    return row ? toUser(row) : null;
  }

  countUsers(): number {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM users').get();
    return num(row?.n ?? 0);
  }

  // --------------------------------------------------------------- sessions

  insertSession(session: SessionRecord): void {
    this.db
      .prepare('INSERT INTO sessions (id_hash, user_id, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?)')
      .run(session.idHash, session.userId, session.createdAt, session.expiresAt, session.lastSeenAt);
  }

  getSession(idHash: string): SessionRecord | null {
    const row = this.db.prepare('SELECT * FROM sessions WHERE id_hash = ?').get(idHash);
    return row ? toSession(row) : null;
  }

  touchSession(idHash: string, now: Millis): void {
    this.db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?').run(now, idHash);
  }

  deleteSession(idHash: string): void {
    this.db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(idHash);
  }

  deleteUserSessions(userId: string): void {
    this.db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
  }

  // --------------------------------------------------- pending authorizations

  insertPendingAuthorization(pending: PendingAuthorizationRecord): void {
    this.db
      .prepare('INSERT INTO pending_authorizations (id, user_id, client_id, params, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(pending.id, pending.userId, pending.clientId, JSON.stringify(pending.params), pending.createdAt, pending.expiresAt);
  }

  getPendingAuthorization(id: string): PendingAuthorizationRecord | null {
    const row = this.db.prepare('SELECT * FROM pending_authorizations WHERE id = ?').get(id);
    return row ? toPendingAuthorization(row) : null;
  }

  deletePendingAuthorization(id: string): void {
    this.db.prepare('DELETE FROM pending_authorizations WHERE id = ?').run(id);
  }

  // ------------------------------------------------------ authorization codes

  insertAuthorizationCode(code: AuthorizationCodeRecord): void {
    this.db
      .prepare(
        `INSERT INTO authorization_codes (code_hash, client_id, user_id, redirect_uri, scope,
                                           code_challenge, code_challenge_method, nonce, dpop_jkt,
                                           issued_at, expires_at, consumed_at, family_id, failed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)`,
      )
      .run(
        code.codeHash,
        code.clientId,
        code.userId,
        code.redirectUri,
        JSON.stringify(code.scope),
        code.codeChallenge,
        code.codeChallengeMethod,
        code.nonce,
        code.dpopJkt,
        code.issuedAt,
        code.expiresAt,
      );
  }

  getAuthorizationCode(codeHash: string): AuthorizationCodeRecord | null {
    const row = this.db.prepare('SELECT * FROM authorization_codes WHERE code_hash = ?').get(codeHash);
    return row ? toAuthorizationCode(row) : null;
  }

  /**
   * Atomically consumes an authorization code. Returns false when another
   * request already consumed it (a concurrent redemption), so callers can
   * detect replay.
   */
  markCodeConsumed(codeHash: string, now: Millis, familyId: string): boolean {
    const result = this.db
      .prepare(
        `UPDATE authorization_codes SET consumed_at = ?, family_id = ?
          WHERE code_hash = ? AND consumed_at IS NULL AND failed_at IS NULL`,
      )
      .run(now, familyId, codeHash);
    return Number(result.changes) === 1;
  }

  markCodeFailed(codeHash: string, now: Millis): void {
    this.db.prepare('UPDATE authorization_codes SET failed_at = ? WHERE code_hash = ?').run(now, codeHash);
  }

  /** Deletes codes past their lifetime so a stolen code cannot be replayed later. */
  deleteExpiredAuthorizationCodes(now: Millis): number {
    const result = this.db.prepare('DELETE FROM authorization_codes WHERE expires_at < ?').run(now);
    return Number(result.changes);
  }

  // ----------------------------------------------------------- token families

  insertFamily(input: NewFamilyInput): TokenFamilyRecord {
    this.db
      .prepare('INSERT INTO token_families (id, client_id, user_id, scope, dpop_jkt, created_at, revoked_at, revoked_reason) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)')
      .run(input.id, input.clientId, input.userId, JSON.stringify(input.scope), input.dpopJkt, input.createdAt);
    const row = this.db.prepare('SELECT * FROM token_families WHERE id = ?').get(input.id);
    if (!row) throw new Error('insertFamily: row vanished');
    return toFamily(row);
  }

  getFamily(id: string): TokenFamilyRecord | null {
    const row = this.db.prepare('SELECT * FROM token_families WHERE id = ?').get(id);
    return row ? toFamily(row) : null;
  }

  listFamilies(): TokenFamilyRecord[] {
    return this.db.prepare('SELECT * FROM token_families ORDER BY created_at DESC').all().map(toFamily);
  }

  /**
   * Revokes the entire family: every outstanding refresh token and access
   * token issued from it. Idempotent — revoking an already-revoked family
   * keeps the original reason and timestamp.
   */
  revokeFamily(familyId: string, now: Millis, reason: string): boolean {
    return this.transaction(() => {
      const family = this.getFamily(familyId);
      if (!family) return false;
      const newlyRevoked = family.revokedAt === null;
      if (newlyRevoked) {
        this.db
          .prepare('UPDATE token_families SET revoked_at = ?, revoked_reason = ? WHERE id = ? AND revoked_at IS NULL')
          .run(now, reason, familyId);
      }
      this.db
        .prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL')
        .run(now, familyId);
      this.db
        .prepare('UPDATE access_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL')
        .run(now, familyId);
      return newlyRevoked;
    });
  }

  // --------------------------------------------------------- refresh tokens

  insertRefreshToken(token: NewRefreshTokenInput): void {
    this.db
      .prepare('INSERT INTO refresh_tokens (token_hash, family_id, generation, issued_at, expires_at, used_at, revoked_at, replaced_by_hash) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL)')
      .run(token.tokenHash, token.familyId, token.generation, token.issuedAt, token.expiresAt);
  }

  getRefreshToken(tokenHash: string): RefreshTokenRecord | null {
    const row = this.db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(tokenHash);
    return row ? toRefreshToken(row) : null;
  }

  /**
   * Atomically marks a refresh token used and links it to its successor.
   * Returns false if it was already used or revoked (i.e. this call lost a
   * race or is a replay).
   */
  consumeRefreshToken(tokenHash: string, now: Millis, replacedByHash: string): boolean {
    const result = this.db
      .prepare(
        `UPDATE refresh_tokens SET used_at = ?, replaced_by_hash = ?
          WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL`,
      )
      .run(now, replacedByHash, tokenHash);
    return Number(result.changes) === 1;
  }

  revokeRefreshToken(tokenHash: string, now: Millis): boolean {
    const result = this.db
      .prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL')
      .run(now, tokenHash);
    return Number(result.changes) === 1;
  }

  listRefreshTokens(): RefreshTokenRecord[] {
    return this.db
      .prepare('SELECT * FROM refresh_tokens ORDER BY issued_at DESC')
      .all()
      .map(toRefreshToken);
  }

  countActiveRefreshTokens(now: Millis): number {
    const row = this.db
      .prepare(
        `SELECT COUNT(*) AS n FROM refresh_tokens r
         JOIN token_families f ON f.id = r.family_id
         WHERE r.used_at IS NULL AND r.revoked_at IS NULL AND r.expires_at > ? AND f.revoked_at IS NULL`,
      )
      .get(now);
    return num(row?.n ?? 0);
  }

  // ---------------------------------------------------------- access tokens

  insertAccessToken(token: NewAccessTokenInput): void {
    this.db
      .prepare(
        `INSERT INTO access_tokens (token_hash, family_id, client_id, user_id, scope, issued_at, expires_at, revoked_at, dpop_jkt, jti)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
      )
      .run(
        token.tokenHash,
        token.familyId,
        token.clientId,
        token.userId,
        JSON.stringify(token.scope),
        token.issuedAt,
        token.expiresAt,
        token.dpopJkt,
        token.jti,
      );
  }

  getAccessToken(tokenHash: string): AccessTokenRecord | null {
    const row = this.db.prepare('SELECT * FROM access_tokens WHERE token_hash = ?').get(tokenHash);
    return row ? toAccessToken(row) : null;
  }

  revokeAccessToken(tokenHash: string, now: Millis): boolean {
    const result = this.db
      .prepare('UPDATE access_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL')
      .run(now, tokenHash);
    return Number(result.changes) === 1;
  }

  listAccessTokens(): AccessTokenRecord[] {
    return this.db.prepare('SELECT * FROM access_tokens ORDER BY issued_at DESC').all().map(toAccessToken);
  }

  countActiveAccessTokens(now: Millis): number {
    const row = this.db
      .prepare('SELECT COUNT(*) AS n FROM access_tokens WHERE revoked_at IS NULL AND expires_at > ?')
      .get(now);
    return num(row?.n ?? 0);
  }

  // -------------------------------------------------------------- dpop jti

  /**
   * Records a DPoP `jti` for a key. Returns false when the same (jkt, jti)
   * pair was already seen inside the retention window — i.e. a replay.
   * Implemented as a single INSERT ... ON CONFLICT statement so the check-and-set
   * is atomic.
   */
  recordDpopJti(jkt: string, jti: string, now: Millis, expiresAt: Millis): boolean {
    const result = this.db
      .prepare(
        `INSERT INTO dpop_jti (jkt, jti, seen_at, expires_at) VALUES (?, ?, ?, ?)
         ON CONFLICT (jkt, jti) DO NOTHING`,
      )
      .run(jkt, jti, now, expiresAt);
    return Number(result.changes) === 1;
  }

  pruneDpopJti(now: Millis): number {
    const result = this.db.prepare('DELETE FROM dpop_jti WHERE expires_at < ?').run(now);
    return Number(result.changes);
  }

  // --------------------------------------------------------- replay markers

  recordReplay(
    tokenHash: string,
    tokenType: 'refresh_token' | 'authorization_code',
    familyId: string | null,
    now: Millis,
    detail: Record<string, unknown>,
  ): void {
    this.db
      .prepare(
        `INSERT INTO replay_markers (token_hash, token_type, family_id, detected_at, detail) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (token_hash) DO UPDATE SET detected_at = excluded.detected_at, detail = excluded.detail`,
      )
      .run(tokenHash, tokenType, familyId, now, JSON.stringify(detail));
  }

  getReplayMarker(tokenHash: string): { tokenType: string; familyId: string | null; detectedAt: Millis } | null {
    const row = this.db.prepare('SELECT * FROM replay_markers WHERE token_hash = ?').get(tokenHash);
    if (!row) return null;
    return {
      tokenType: str(row.token_type),
      familyId: nullableStr(row.family_id),
      detectedAt: num(row.detected_at),
    };
  }

  listReplayMarkers(): Array<{ tokenHash: string; tokenType: string; familyId: string | null; detectedAt: Millis }> {
    return this.db
      .prepare('SELECT * FROM replay_markers ORDER BY detected_at DESC')
      .all()
      .map((row) => ({
        tokenHash: str(row.token_hash),
        tokenType: str(row.token_type),
        familyId: nullableStr(row.family_id),
        detectedAt: num(row.detected_at),
      }));
  }

  pruneReplayMarkers(now: Millis, ttlMillis: number): number {
    const result = this.db.prepare('DELETE FROM replay_markers WHERE detected_at < ?').run(now - ttlMillis);
    return Number(result.changes);
  }

  // -------------------------------------------------------------- audit log

  recordAudit(
    event: string,
    now: Millis,
    detail: { clientId?: string | null; userId?: string | null; extra?: Record<string, unknown> },
  ): void {
    this.db
      .prepare('INSERT INTO audit_events (ts, event, client_id, user_id, detail) VALUES (?, ?, ?, ?, ?)')
      .run(now, event, detail.clientId ?? null, detail.userId ?? null, detail.extra ? JSON.stringify(detail.extra) : null);
  }

  listAuditEvents(limit = 100): AuditEventRecord[] {
    return this.db
      .prepare('SELECT * FROM audit_events ORDER BY id DESC LIMIT ?')
      .all(Math.max(1, Math.min(1000, limit)))
      .map(toAuditEvent);
  }

  // ---------------------------------------------------------------- cleanup

  /** Removes rows that can no longer affect any security decision. */
  cleanup(now: Millis, replayMarkerTtlMillis: number): void {
    this.pruneDpopJti(now);
    this.pruneReplayMarkers(now, replayMarkerTtlMillis);
    this.deleteExpiredAuthorizationCodes(now);
    this.db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
    this.db.prepare('DELETE FROM pending_authorizations WHERE expires_at < ?').run(now);
    this.db.prepare("DELETE FROM refresh_tokens WHERE expires_at < ? AND used_at IS NULL").run(now);
    this.db.prepare('DELETE FROM access_tokens WHERE expires_at < ?').run(now);
  }
}
