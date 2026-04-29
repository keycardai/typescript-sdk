import { jest } from '@jest/globals';
import { TokenVerifier } from './tokenVerifier.js';
import { JWTSigner, type JWTClaims } from '../jwt/signer.js';
import type { OAuthKeyring, PrivateKeyring } from '../keyring.js';

const RS256_PRIVATE_JWK = {
  kty: 'RSA',
  n: 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
  e: 'AQAB',
  d: 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
  p: '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
  q: 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
  dp: 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
  dq: 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
  qi: 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
};

const RS256_PUBLIC_JWK = { kty: 'RSA', n: RS256_PRIVATE_JWK.n, e: RS256_PRIVATE_JWK.e };

const ISSUER = 'https://auth.example.com';
const KID = 'test-key-1';

async function importPrivateKey(): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    RS256_PRIVATE_JWK,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['sign'],
  );
}

async function importPublicKey(): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    RS256_PUBLIC_JWK,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['verify'],
  );
}

function makeKeyring(publicKey: CryptoKey): OAuthKeyring {
  return {
    key: jest.fn<(issuer: string, kid: string) => Promise<CryptoKey>>().mockResolvedValue(publicKey),
  };
}

async function signWith(claims: JWTClaims, privateKey: CryptoKey, kid = KID, issuer = ISSUER): Promise<string> {
  const privateKeyring: PrivateKeyring = {
    key: jest.fn<() => Promise<{ key: CryptoKey; kid: string; issuer: string }>>().mockResolvedValue({
      key: privateKey,
      kid,
      issuer,
    }),
  };
  return new JWTSigner(privateKeyring).sign(claims);
}

describe('TokenVerifier', () => {
  const nowSec = () => Math.floor(Date.now() / 1000);

  it('rejects construction without an issuer', () => {
    expect(() => new TokenVerifier({ issuer: '' })).toThrow(/issuer is required/);
  });

  it('verifies a valid token and returns AccessToken', async () => {
    const [pub, priv] = await Promise.all([importPublicKey(), importPrivateKey()]);
    const claims: JWTClaims = {
      iss: ISSUER,
      client_id: 'service-x',
      scope: 'read write',
      exp: nowSec() + 60,
      aud: 'https://api.example.com',
      resource: 'https://api.example.com',
    };
    const token = await signWith(claims, priv);
    const verifier = new TokenVerifier({
      issuer: ISSUER,
      keyring: makeKeyring(pub),
      audience: 'https://api.example.com',
    });
    const result = await verifier.verifyToken(token);
    expect(result).not.toBeNull();
    expect(result!.token).toBe(token);
    expect(result!.clientId).toBe('service-x');
    expect(result!.scopes).toEqual(['read', 'write']);
    expect(result!.expiresAt).toBe(claims.exp);
    expect(result!.resource).toBe('https://api.example.com');
  });

  it('returns null on invalid signature', async () => {
    const [pub, priv] = await Promise.all([importPublicKey(), importPrivateKey()]);
    const validClaims: JWTClaims = {
      iss: ISSUER,
      client_id: 'service-x',
      scope: 'read',
      exp: nowSec() + 60,
    };
    const token = await signWith(validClaims, priv);
    const tampered = `${token.slice(0, -8)}deadbeef`;
    const verifier = new TokenVerifier({ issuer: ISSUER, keyring: makeKeyring(pub) });
    expect(await verifier.verifyToken(tampered)).toBeNull();
  });

  it('returns null when required scopes are missing', async () => {
    const [pub, priv] = await Promise.all([importPublicKey(), importPrivateKey()]);
    const token = await signWith(
      {
        iss: ISSUER,
        client_id: 'service-x',
        scope: 'read',
        exp: nowSec() + 60,
      },
      priv,
    );
    const verifier = new TokenVerifier({
      issuer: ISSUER,
      keyring: makeKeyring(pub),
      requiredScopes: ['admin'],
    });
    expect(await verifier.verifyToken(token)).toBeNull();
  });

  it('verifyTokenForZone accepts a zone-scoped issuer', async () => {
    const [pub, priv] = await Promise.all([importPublicKey(), importPrivateKey()]);
    const zoneIssuer = 'https://zone-a.auth.example.com';
    const token = await signWith(
      {
        iss: zoneIssuer,
        client_id: 'service-x',
        scope: 'read',
        exp: nowSec() + 60,
      },
      priv,
      KID,
      zoneIssuer,
    );
    const verifier = new TokenVerifier({
      issuer: ISSUER,
      keyring: makeKeyring(pub),
      enableMultiZone: true,
    });
    const result = await verifier.verifyTokenForZone(token, 'zone-a');
    expect(result).not.toBeNull();
    expect(result!.clientId).toBe('service-x');
  });

  it('verifyTokenForZone rejects bare-host issuer when multi-zone is enabled', async () => {
    const [pub, priv] = await Promise.all([importPublicKey(), importPrivateKey()]);
    const token = await signWith(
      {
        iss: ISSUER,
        client_id: 'service-x',
        exp: nowSec() + 60,
      },
      priv,
    );
    const verifier = new TokenVerifier({
      issuer: ISSUER,
      keyring: makeKeyring(pub),
      enableMultiZone: true,
    });
    expect(await verifier.verifyTokenForZone(token, 'zone-a')).toBeNull();
  });

  it('audience as a per-zone dict picks the matching entry', async () => {
    const [pub, priv] = await Promise.all([importPublicKey(), importPrivateKey()]);
    const zoneIssuer = 'https://zone-a.auth.example.com';
    const token = await signWith(
      {
        iss: zoneIssuer,
        client_id: 'service-x',
        exp: nowSec() + 60,
        aud: 'https://api-a.example.com',
      },
      priv,
      KID,
      zoneIssuer,
    );
    const verifier = new TokenVerifier({
      issuer: ISSUER,
      keyring: makeKeyring(pub),
      enableMultiZone: true,
      audience: {
        'zone-a': 'https://api-a.example.com',
        'zone-b': 'https://api-b.example.com',
      },
    });
    expect(await verifier.verifyTokenForZone(token, 'zone-a')).not.toBeNull();
  });

  it('audience as a per-zone dict rejects when zone is unknown', async () => {
    const [pub, priv] = await Promise.all([importPublicKey(), importPrivateKey()]);
    const zoneIssuer = 'https://zone-c.auth.example.com';
    const token = await signWith(
      {
        iss: zoneIssuer,
        client_id: 'service-x',
        exp: nowSec() + 60,
        aud: 'https://api-c.example.com',
      },
      priv,
      KID,
      zoneIssuer,
    );
    const verifier = new TokenVerifier({
      issuer: ISSUER,
      keyring: makeKeyring(pub),
      enableMultiZone: true,
      audience: {
        'zone-a': 'https://api-a.example.com',
      },
    });
    expect(await verifier.verifyTokenForZone(token, 'zone-c')).toBeNull();
  });

  it('clearCache flushes the underlying keyring after a key rotation', async () => {
    const [pub, priv] = await Promise.all([importPublicKey(), importPrivateKey()]);
    const keyring = makeKeyring(pub) as OAuthKeyring & { clear: jest.Mock };
    keyring.clear = jest.fn();
    const verifier = new TokenVerifier({ issuer: ISSUER, keyring });
    const token = await signWith(
      { iss: ISSUER, client_id: 'service-x', exp: nowSec() + 60 },
      priv,
    );
    expect(await verifier.verifyToken(token)).not.toBeNull();
    verifier.clearCache();
    expect(keyring.clear).toHaveBeenCalledTimes(1);
  });

  it('clearCache is a no-op when the keyring does not expose clear()', () => {
    const verifier = new TokenVerifier({
      issuer: ISSUER,
      keyring: { key: jest.fn() },
    });
    expect(() => verifier.clearCache()).not.toThrow();
  });
});
