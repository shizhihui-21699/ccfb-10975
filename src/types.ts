/** Milliseconds since the epoch. */
export type Millis = number;

export type TokenEndpointAuthMethod = 'none' | 'client_secret_basic' | 'client_secret_post';

export interface ClientRecord {
  id: string;
  name: string;
  secretHash: string | null;
  redirectUris: string[];
  grantTypes: string[];
  responseTypes: string[];
  scopes: string[];
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  /** When true the client must present a DPoP proof at the token endpoint. */
  requireDpop: boolean;
  disabled: boolean;
  createdAt: Millis;
  updatedAt: Millis;
}

export interface UserRecord {
  id: string;
  username: string;
  passwordHash: string;
  displayName: string;
  role: 'user' | 'admin';
  createdAt: Millis;
}

export interface SessionRecord {
  idHash: string;
  userId: string;
  createdAt: Millis;
  expiresAt: Millis;
  lastSeenAt: Millis;
}

export interface PendingAuthorizationRecord {
  id: string;
  userId: string;
  clientId: string;
  params: AuthorizationRequestParams;
  createdAt: Millis;
  expiresAt: Millis;
}

export interface AuthorizationRequestParams {
  clientId: string;
  redirectUri: string;
  scope: string[];
  state: string | null;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  nonce: string | null;
  dpopJkt: string | null;
}

export interface AuthorizationCodeRecord {
  codeHash: string;
  clientId: string;
  userId: string;
  redirectUri: string;
  scope: string[];
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  nonce: string | null;
  dpopJkt: string | null;
  issuedAt: Millis;
  expiresAt: Millis;
  consumedAt: Millis | null;
  /** Family created by the successful redemption, if any. */
  familyId: string | null;
  /** Set when PKCE verification failed; the code is dead from then on. */
  failedAt: Millis | null;
}

export interface TokenFamilyRecord {
  id: string;
  clientId: string;
  userId: string;
  scope: string[];
  dpopJkt: string | null;
  createdAt: Millis;
  revokedAt: Millis | null;
  revokedReason: string | null;
}

export interface RefreshTokenRecord {
  tokenHash: string;
  familyId: string;
  generation: number;
  issuedAt: Millis;
  expiresAt: Millis;
  usedAt: Millis | null;
  revokedAt: Millis | null;
  replacedByHash: string | null;
}

export interface AccessTokenRecord {
  tokenHash: string;
  familyId: string | null;
  clientId: string;
  userId: string;
  scope: string[];
  issuedAt: Millis;
  expiresAt: Millis;
  revokedAt: Millis | null;
  dpopJkt: string | null;
  jti: string;
}

export interface AuditEventRecord {
  id: number;
  ts: Millis;
  event: string;
  clientId: string | null;
  userId: string | null;
  detail: Record<string, unknown> | null;
}
