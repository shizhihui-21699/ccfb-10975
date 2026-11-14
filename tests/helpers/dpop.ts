import { generateKeyPair, exportJWK, SignJWT, calculateJwkThumbprint, type JWK } from 'jose';
import { createHash, randomUUID } from 'node:crypto';

/**
 * A DPoP client key with helpers to mint proofs. Each instance is one key;
 * use separate instances to exercise key-binding failures.
 */
export class DpopKey {
  readonly privateKey: CryptoKey;
  readonly publicJwk: JWK;

  private constructor(privateKey: CryptoKey, publicJwk: JWK) {
    this.privateKey = privateKey;
    this.publicJwk = publicJwk;
  }

  static async generate(): Promise<DpopKey> {
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    const publicJwk = await exportJWK(publicKey);
    // Only the required members go into the proof header.
    return new DpopKey(privateKey, { kty: 'EC', crv: 'P-256', x: publicJwk.x, y: publicJwk.y });
  }

  async thumbprint(): Promise<string> {
    return calculateJwkThumbprint(this.publicJwk, 'sha256');
  }

  /**
   * Mints a proof. Defaults produce a valid proof for POST <uri>; override any
   * claim or header to exercise the negative paths.
   */
  async proof(options: {
    method?: string;
    uri: string;
    accessToken?: string;
    jti?: string;
    iat?: number;
    /** Shifts iat by this many seconds from now, for clock-skew tests. */
    iatOffsetSeconds?: number;
    header?: Record<string, unknown>;
    payload?: Record<string, unknown>;
    /** Use a different key to sign than the one embedded in the header. */
    signingKey?: CryptoKey;
    omit?: Array<'jti' | 'htm' | 'htu' | 'iat' | 'ath'>;
  }): Promise<string> {
    const omit = new Set(options.omit ?? []);
    const nowSeconds = Math.floor(Date.now() / 1000);
    const iat = options.iat ?? nowSeconds + (options.iatOffsetSeconds ?? 0);

    const payload: Record<string, unknown> = {
      ...(omit.has('jti') ? {} : { jti: options.jti ?? randomUUID() }),
      ...(omit.has('htm') ? {} : { htm: options.method ?? 'POST' }),
      ...(omit.has('htu') ? {} : { htu: options.uri }),
      ...(omit.has('iat') ? {} : { iat }),
      ...(options.accessToken !== undefined && !omit.has('ath')
        ? { ath: await ath(options.accessToken) }
        : {}),
      ...(options.payload ?? {}),
    };

    const header: Record<string, unknown> = {
      typ: 'dpop+jwt',
      alg: 'ES256',
      jwk: this.publicJwk,
      ...(options.header ?? {}),
    };

    return new SignJWT(payload)
      .setProtectedHeader(header as never)
      .sign(options.signingKey ?? this.privateKey);
  }
}

export async function ath(accessToken: string): Promise<string> {
  return createHash('sha256').update(accessToken, 'ascii').digest('base64url');
}

/** Deterministic PKCE pair for tests. */
export function pkcePair(verifier = 'test-verifier-0123456789-0123456789-0123456789-abcd'): {
  verifier: string;
  challenge: string;
} {
  return {
    verifier,
    challenge: createHash('sha256').update(verifier, 'ascii').digest('base64url'),
  };
}
