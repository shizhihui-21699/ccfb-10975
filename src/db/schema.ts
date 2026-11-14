/**
 * SQLite schema. Timestamps are integer milliseconds since the epoch.
 *
 * Secrets (authorization codes, access tokens, refresh tokens, session ids)
 * are stored only as SHA-256 digests: a database leak does not yield tokens
 * that can be replayed.
 */
export const SCHEMA_SQL = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS clients (
  id                          TEXT PRIMARY KEY,
  name                        TEXT NOT NULL,
  secret_hash                 TEXT,
  redirect_uris               TEXT NOT NULL,
  grant_types                 TEXT NOT NULL,
  response_types              TEXT NOT NULL,
  scopes                      TEXT NOT NULL,
  token_endpoint_auth_method  TEXT NOT NULL,
  require_dpop                INTEGER NOT NULL DEFAULT 0,
  disabled                    INTEGER NOT NULL DEFAULT 0,
  created_at                  INTEGER NOT NULL,
  updated_at                  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  display_name  TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'user',
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id_hash      TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS pending_authorizations (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id  TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  params     TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS authorization_codes (
  code_hash             TEXT PRIMARY KEY,
  client_id             TEXT NOT NULL,
  user_id               TEXT NOT NULL,
  redirect_uri          TEXT NOT NULL,
  scope                 TEXT NOT NULL,
  code_challenge        TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  nonce                 TEXT,
  dpop_jkt              TEXT,
  issued_at             INTEGER NOT NULL,
  expires_at            INTEGER NOT NULL,
  consumed_at           INTEGER,
  family_id             TEXT,
  failed_at             INTEGER
);
CREATE INDEX IF NOT EXISTS idx_codes_expires ON authorization_codes(expires_at);

CREATE TABLE IF NOT EXISTS token_families (
  id             TEXT PRIMARY KEY,
  client_id      TEXT NOT NULL,
  user_id        TEXT NOT NULL,
  scope          TEXT NOT NULL,
  dpop_jkt       TEXT,
  created_at     INTEGER NOT NULL,
  revoked_at     INTEGER,
  revoked_reason TEXT
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash      TEXT PRIMARY KEY,
  family_id       TEXT NOT NULL REFERENCES token_families(id) ON DELETE CASCADE,
  generation      INTEGER NOT NULL,
  issued_at       INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  used_at         INTEGER,
  revoked_at      INTEGER,
  replaced_by_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_expires ON refresh_tokens(expires_at);

CREATE TABLE IF NOT EXISTS access_tokens (
  token_hash TEXT PRIMARY KEY,
  family_id  TEXT,
  client_id  TEXT NOT NULL,
  user_id    TEXT NOT NULL,
  scope      TEXT NOT NULL,
  issued_at  INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  dpop_jkt   TEXT,
  jti        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_access_family ON access_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_access_expires ON access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_access_jti ON access_tokens(jti);

CREATE TABLE IF NOT EXISTS dpop_jti (
  jkt        TEXT NOT NULL,
  jti        TEXT NOT NULL,
  seen_at    INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (jkt, jti)
);
CREATE INDEX IF NOT EXISTS idx_dpop_jti_expires ON dpop_jti(expires_at);

CREATE TABLE IF NOT EXISTS replay_markers (
  token_hash  TEXT PRIMARY KEY,
  token_type  TEXT NOT NULL,
  family_id   TEXT,
  detected_at INTEGER NOT NULL,
  detail      TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        INTEGER NOT NULL,
  event     TEXT NOT NULL,
  client_id TEXT,
  user_id   TEXT,
  detail    TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
`;
