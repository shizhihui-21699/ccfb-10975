import type { ServerConfig } from '../config.ts';
import type { Store } from '../db/store.ts';
import type { AccessTokenRecord, RefreshTokenRecord } from '../types.ts';
import { OAuthError, invalidGrant } from '../util/errors.ts';
import { newId, randomToken, sha256Base64Url } from '../util/crypto.ts';

export interface IssuedTokens {
  accessToken: string;
  /** Absent when the client is not allowed a refresh token. */
  refreshToken: string | null;
  expiresIn: number;
  scope: string[];
  dpopJkt: string | null;
  /** Opaque identifier for auditing/admin display; never sent to clients. */
  jti: string;
}

export class TokenService {
  private readonly store: Store;
  private readonly config: ServerConfig;

  constructor(store: Store, config: ServerConfig) {
    this.store = store;
    this.config = config;
  }

  /**
   * Issues an access token (and optionally a refresh token) for a new
   * authorization-code exchange, creating the token family under the
   * caller-supplied id so the code can be consumed in the same transaction.
   *
   * `refreshBindingJkt` is the key a public client's refresh token is bound
   * to (RFC 9449 §5); `accessTokenJkt` is the key the access token is bound
   * to, which is simply the proof key whenever one was presented.
   */
  issueNewFamily(params: {
    familyId: string;
    clientId: string;
    userId: string;
    scope: string[];
    /** Key the issued access token is bound to (any client with a proof). */
    accessTokenJkt: string | null;
    /** Key a public client's refresh token is bound to; null for confidential clients. */
    refreshBindingJkt: string | null;
    withRefreshToken: boolean;
    now: number;
  }): IssuedTokens {
    const { familyId, clientId, userId, scope, accessTokenJkt, refreshBindingJkt, withRefreshToken, now } = params;
    return this.store.transaction(() => {
      // The family row is created even for access-only issuance so the token
      // can be introspected and revoked uniformly.
      this.store.insertFamily({ id: familyId, clientId, userId, scope, dpopJkt: refreshBindingJkt, createdAt: now });
      const { token: accessToken, jti } = this.issueAccessToken({
        familyId,
        clientId,
        userId,
        scope,
        dpopJkt: accessTokenJkt,
        now,
      });

      const refreshToken = withRefreshToken ? this.issueRefreshToken(familyId, 1, now) : null;

      return {
        accessToken,
        refreshToken,
        expiresIn: this.config.accessTokenTtlSeconds,
        scope,
        dpopJkt: accessTokenJkt,
        jti,
      };
    });
  }

  private issueAccessToken(params: {
    familyId: string;
    clientId: string;
    userId: string;
    scope: string[];
    dpopJkt: string | null;
    now: number;
  }): { token: string; jti: string } {
    const token = randomToken(32);
    const jti = newId();
    this.store.insertAccessToken({
      tokenHash: sha256Base64Url(token),
      familyId: params.familyId,
      clientId: params.clientId,
      userId: params.userId,
      scope: params.scope,
      issuedAt: params.now,
      expiresAt: params.now + this.config.accessTokenTtlSeconds * 1000,
      dpopJkt: params.dpopJkt,
      jti,
    });
    return { token, jti };
  }

  private issueRefreshToken(familyId: string, generation: number, now: number): string {
    const token = randomToken(32);
    this.store.insertRefreshToken({
      tokenHash: sha256Base64Url(token),
      familyId,
      generation,
      issuedAt: now,
      expiresAt: now + this.config.refreshTokenTtlSeconds * 1000,
    });
    return token;
  }

  /**
   * Rotates a refresh token: the presented token is consumed, a fresh refresh
   * token is bound to the same family, and a new access token is issued.
   *
   * Replay detection: if the presented token was already used (or the family
   * is already revoked), the whole family is revoked and `invalid_grant` is
   * returned. The old token is recorded as a replay so a repeat offender is
   * caught even after the family rows are cleaned up.
   *
   * Security-relevant revocation happens in its own committed transaction
   * *before* the error is raised: a rolled-back revocation would leave the
   * attacker's stolen family alive, which is the exact failure this feature
   * exists to prevent.
   */
  rotateRefreshToken(params: {
    refreshToken: string;
    clientId: string;
    /** Thumbprint of the DPoP proof presented with this request, if any. */
    dpopJkt: string | null;
    /**
     * True for a public client. RFC 9449 §5 binds a public client's refresh
     * token to its proof key; confidential clients are already constrained by
     * client authentication, so a key change must not kill the family.
     */
    senderConstrainedByKey: boolean;
    requestedScope: string[] | null;
    now: number;
  }): IssuedTokens & { familyId: string } {
    const { refreshToken, clientId, dpopJkt, senderConstrainedByKey, requestedScope, now } = params;
    const tokenHash = sha256Base64Url(refreshToken);

    const record = this.store.getRefreshToken(tokenHash);
    if (!record) throw invalidGrant('refresh token is unknown or expired');

    const family = this.store.getFamily(record.familyId);
    if (!family) throw invalidGrant('refresh token is unknown or expired');

    if (family.clientId !== clientId) {
      // Should be impossible with a correctly hashed lookup, but never let a
      // token cross client boundaries.
      this.store.revokeFamily(family.id, now, 'client_mismatch');
      throw invalidGrant('refresh token was issued to another client');
    }

    if (family.revokedAt !== null) {
      this.store.transaction(() => {
        this.store.recordReplay(tokenHash, 'refresh_token', family.id, now, {
          reason: 'family_already_revoked',
          revokedReason: family.revokedReason,
        });
        this.store.recordAudit('refresh_replay', now, {
          clientId,
          userId: family.userId,
          extra: { familyId: family.id, revokedReason: family.revokedReason },
        });
      });
      throw invalidGrant('refresh token has been revoked');
    }

    if (record.revokedAt !== null) {
      this.store.revokeFamily(family.id, now, 'refresh_token_revoked');
      this.store.transaction(() => {
        this.store.recordReplay(tokenHash, 'refresh_token', family.id, now, { reason: 'token_revoked' });
        this.store.recordAudit('refresh_replay', now, {
          clientId,
          userId: family.userId,
          extra: { familyId: family.id, reason: 'token_revoked' },
        });
      });
      throw invalidGrant('refresh token has been revoked');
    }

    // A used token presented again is a replay: someone holds a copy.
    if (record.usedAt !== null) {
      this.store.revokeFamily(family.id, now, 'refresh_token_replay');
      this.store.transaction(() => {
        this.store.recordReplay(tokenHash, 'refresh_token', family.id, now, {
          reason: 'token_replayed',
          replacedByHash: record.replacedByHash,
        });
        this.store.recordAudit('refresh_replay', now, {
          clientId,
          userId: family.userId,
          extra: { familyId: family.id, generation: record.generation },
        });
      });
      throw invalidGrant('refresh token has already been used; the token family has been revoked');
    }

    if (record.expiresAt <= now) {
      throw invalidGrant('refresh token has expired');
    }

    // DPoP binding (RFC 9449 §5): a refresh token bound to a key can only be
    // rotated with a proof from that same key.
    if (senderConstrainedByKey && family.dpopJkt !== null && family.dpopJkt !== dpopJkt) {
      this.store.revokeFamily(family.id, now, 'dpop_key_mismatch');
      this.store.transaction(() => {
        this.store.recordAudit('dpop_binding_mismatch', now, {
          clientId,
          userId: family.userId,
          extra: { familyId: family.id },
        });
      });
      throw invalidGrant('refresh token is bound to a different DPoP key');
    }

    let scope = family.scope;
    if (requestedScope !== null) {
      // RFC 6749 §6: the requested scope must not include any scope not
      // originally granted, and if omitted is equal to the original.
      const notGranted = requestedScope.filter((s) => !family.scope.includes(s));
      if (notGranted.length > 0) {
        throw new OAuthError(400, 'invalid_scope', 'requested scope exceeds the original grant');
      }
      scope = requestedScope;
    }

    // The atomic consume below is what makes concurrent reuse impossible:
    // only one caller can flip `used_at`, and the loser is treated as a
    // replay (it means one of the two presentations is illegitimate).
    const nextRefreshToken = randomToken(32);
    const nextHash = sha256Base64Url(nextRefreshToken);
    const consumed = this.store.transaction(() =>
      this.store.consumeRefreshToken(tokenHash, now, nextHash),
    );
    if (!consumed) {
      this.store.revokeFamily(family.id, now, 'refresh_token_race');
      this.store.transaction(() => {
        this.store.recordReplay(tokenHash, 'refresh_token', family.id, now, { reason: 'concurrent_use' });
        this.store.recordAudit('refresh_replay', now, {
          clientId,
          userId: family.userId,
          extra: { familyId: family.id, reason: 'concurrent_use' },
        });
      });
      throw invalidGrant('refresh token was used concurrently; the token family has been revoked');
    }

    return this.store.transaction(() => {
      this.store.insertRefreshToken({
        tokenHash: nextHash,
        familyId: family.id,
        generation: record.generation + 1,
        issuedAt: now,
        expiresAt: now + this.config.refreshTokenTtlSeconds * 1000,
      });

      // A proof presented now governs the new access token's binding. For a
      // key-bound (public client) family the two are already equal.
      const accessTokenJkt = dpopJkt ?? family.dpopJkt;
      const { token: accessToken, jti } = this.issueAccessToken({
        familyId: family.id,
        clientId,
        userId: family.userId,
        scope,
        dpopJkt: accessTokenJkt,
        now,
      });

      return {
        accessToken,
        refreshToken: nextRefreshToken,
        expiresIn: this.config.accessTokenTtlSeconds,
        scope,
        dpopJkt: accessTokenJkt,
        jti,
        familyId: family.id,
      };
    });
  }

  /**
   * Looks up an access token, enforcing expiry, revocation and (when
   * requested) the DPoP key binding. Returns null when the token is not
   * usable.
   */
  validateAccessToken(
    token: string,
    now: number,
    expectedJkt?: string,
  ): AccessTokenRecord | null {
    const record = this.store.getAccessToken(sha256Base64Url(token));
    if (!record) return null;
    if (record.revokedAt !== null) return null;
    if (record.expiresAt <= now) return null;
    if (record.dpopJkt !== null) {
      if (expectedJkt === undefined || expectedJkt !== record.dpopJkt) return null;
    }
    return record;
  }

  /** Revokes an access token; returns true when it existed. */
  revokeAccessToken(token: string, now: number, reason: string): boolean {
    const tokenHash = sha256Base64Url(token);
    const record = this.store.getAccessToken(tokenHash);
    if (!record) return false;
    this.store.revokeAccessToken(tokenHash, now);
    this.store.recordAudit('access_token_revoked', now, {
      clientId: record.clientId,
      userId: record.userId,
      extra: { reason, jti: record.jti },
    });
    return true;
  }

  /**
   * Revokes a refresh token and, per RFC 7009 §2.1, all tokens derived from
   * the same authorization grant. Returns true when the token existed.
   */
  revokeRefreshToken(token: string, now: number, reason: string): boolean {
    const tokenHash = sha256Base64Url(token);
    const record: RefreshTokenRecord | null = this.store.getRefreshToken(tokenHash);
    if (!record) return false;
    this.store.revokeFamily(record.familyId, now, reason);
    this.store.recordAudit('refresh_token_revoked', now, {
      clientId: this.store.getFamily(record.familyId)?.clientId ?? null,
      extra: { familyId: record.familyId },
    });
    return true;
  }

 /**
   * Records a replayed authorization code. A code is single-use; if it was
   * already consumed, any tokens issued from it are revoked (RFC 6749 §4.1.2
   * recommends revocation for exactly this case).
   */
  handleAuthorizationCodeReplay(codeHash: string, now: number, detail: Record<string, unknown>): void {
    const code = this.store.getAuthorizationCode(codeHash);
    if (!code) return;
    if (code.familyId !== null) {
      this.store.revokeFamily(code.familyId, now, 'authorization_code_replay');
    }
    this.store.recordReplay(codeHash, 'authorization_code', code.familyId, now, detail);
    this.store.recordAudit('authorization_code_replay', now, {
      clientId: code.clientId,
      userId: code.userId,
      extra: detail,
    });
  }
}
