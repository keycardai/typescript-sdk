import { jest } from '@jest/globals';
import { JWTVerifier } from './verifier.js';
import { JWTSigner, type JWTClaims } from './signer.js';
import { InvalidTokenError } from '../errors.js';
import type { OAuthKeyring, PrivateKeyring } from '../keyring.js';

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
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

const RS256_PUBLIC_JWK = {
  kty: 'RSA',
  n: RS256_PRIVATE_JWK.n,
  e: RS256_PRIVATE_JWK.e,
};

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

function makeKeyring(publicKey: CryptoKey): { keyring: OAuthKeyring; keyFn: jest.Mock } {
  const keyFn = jest.fn<(issuer: string, kid: string) => Promise<CryptoKey>>()
    .mockResolvedValue(publicKey);
  return { keyring: { key: keyFn }, keyFn: keyFn as unknown as jest.Mock };
}

async function signWith(claims: JWTClaims, privateKey: CryptoKey, kid = KID): Promise<string> {
  const privateKeyring: PrivateKeyring = {
    key: jest.fn<() => Promise<{ key: CryptoKey; kid: string; issuer: string }>>()
      .mockResolvedValue({ key: privateKey, kid, issuer: ISSUER }),
  };
  const signer = new JWTSigner(privateKeyring);
  return signer.sign(claims);
}

function base64url(input: string): string {
  return Buffer.from(input, 'utf-8').toString('base64url');
}

function forgeUnverifiedJWT(header: object, payload: object): string {
  return `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}.signature`;
}

describe('JWTVerifier', () => {
  const nowSec = () => Math.floor(Date.now() / 1000);

  it('rejects construction without issuers', () => {
    const keyring: OAuthKeyring = { key: jest.fn() };
    expect(() => new JWTVerifier(keyring, { issuers: [] as string[] })).toThrow(
      /at least one trusted issuer/,
    );
    expect(
      () => new JWTVerifier(keyring, undefined as unknown as { issuers: string }),
    ).toThrow(/at least one trusted issuer/);
  });

  it('rejects algorithms the signature step cannot verify', () => {
    const keyring: OAuthKeyring = { key: jest.fn() };
    expect(
      () => new JWTVerifier(keyring, { issuers: ISSUER, algorithms: ['RS256', 'ES256'] }),
    ).toThrow(/does not implement signature verification for "ES256"/);
    expect(
      () => new JWTVerifier(keyring, { issuers: ISSUER, algorithms: ['HS256'] }),
    ).toThrow(/does not implement signature verification for "HS256"/);
  });

  it('accepts a well-formed token with matching issuer and exp', async () => {
    const [privateKey, publicKey] = await Promise.all([importPrivateKey(), importPublicKey()]);
    const { keyring, keyFn } = makeKeyring(publicKey);
    const token = await signWith(
      { client_id: 'client-42', exp: nowSec() + 3600 },
      privateKey,
    );
    const verifier = new JWTVerifier(keyring, { issuers: ISSUER });

    const claims = await verifier.verify(token);

    expect(claims.iss).toBe(ISSUER);
    expect(claims.client_id).toBe('client-42');
    expect(keyFn).toHaveBeenCalledWith(ISSUER, KID);
  });

  it('rejects a token whose iss is not in the issuer allowlist WITHOUT any key lookup', async () => {
    const [privateKey, publicKey] = await Promise.all([importPrivateKey(), importPublicKey()]);
    const { keyring, keyFn } = makeKeyring(publicKey);
    // Signer defaults iss to ISSUER; the verifier is configured to only trust a different one.
    const token = await signWith(
      { client_id: 'client-42', exp: nowSec() + 3600 },
      privateKey,
    );
    const verifier = new JWTVerifier(keyring, { issuers: 'https://other-issuer.example.com' });

    await expect(verifier.verify(token)).rejects.toThrow(InvalidTokenError);
    await expect(verifier.verify(token)).rejects.toThrow(/Untrusted issuer/);
    expect(keyFn).not.toHaveBeenCalled();
  });

  it('rejects tokens with alg "none"', async () => {
    const { keyring } = makeKeyring(await importPublicKey());
    const forged = forgeUnverifiedJWT(
      { alg: 'none', kid: KID },
      { iss: ISSUER, client_id: 'c', exp: nowSec() + 3600 },
    );
    const verifier = new JWTVerifier(keyring, { issuers: ISSUER });

    await expect(verifier.verify(forged)).rejects.toThrow(/Unsupported JWT algorithm/);
  });

  it('rejects tokens with an alg outside the allowlist', async () => {
    const { keyring } = makeKeyring(await importPublicKey());
    const forged = forgeUnverifiedJWT(
      { alg: 'HS256', kid: KID },
      { iss: ISSUER, client_id: 'c', exp: nowSec() + 3600 },
    );
    const verifier = new JWTVerifier(keyring, { issuers: ISSUER });

    await expect(verifier.verify(forged)).rejects.toThrow(/Unsupported JWT algorithm: HS256/);
  });

  it('rejects expired tokens', async () => {
    const [privateKey, publicKey] = await Promise.all([importPrivateKey(), importPublicKey()]);
    const { keyring } = makeKeyring(publicKey);
    const token = await signWith(
      { client_id: 'c', exp: nowSec() - 10 },
      privateKey,
    );
    const verifier = new JWTVerifier(keyring, { issuers: ISSUER });

    await expect(verifier.verify(token)).rejects.toThrow(/Token expired/);
  });

  it('rejects tokens whose nbf is in the future', async () => {
    const [privateKey, publicKey] = await Promise.all([importPrivateKey(), importPublicKey()]);
    const { keyring } = makeKeyring(publicKey);
    const token = await signWith(
      { client_id: 'c', exp: nowSec() + 3600, nbf: nowSec() + 600 },
      privateKey,
    );
    const verifier = new JWTVerifier(keyring, { issuers: ISSUER });

    await expect(verifier.verify(token)).rejects.toThrow(/Token not yet valid/);
  });

  it('rejects tokens whose exp is NaN', async () => {
    const { keyring } = makeKeyring(await importPublicKey());
    const forged = forgeUnverifiedJWT(
      { alg: 'RS256', kid: KID },
      { iss: ISSUER, client_id: 'c', exp: NaN },
    );
    const verifier = new JWTVerifier(keyring, { issuers: ISSUER });
    await expect(verifier.verify(forged)).rejects.toThrow(/missing expiration/);
  });

  it('rejects tokens whose nbf is NaN', async () => {
    const { keyring } = makeKeyring(await importPublicKey());
    const forged = forgeUnverifiedJWT(
      { alg: 'RS256', kid: KID },
      { iss: ISSUER, client_id: 'c', exp: nowSec() + 3600, nbf: NaN },
    );
    const verifier = new JWTVerifier(keyring, { issuers: ISSUER });
    await expect(verifier.verify(forged)).rejects.toThrow(/invalid not-before/);
  });

  it('rejects tokens missing exp', async () => {
    const [privateKey, publicKey] = await Promise.all([importPrivateKey(), importPublicKey()]);
    const { keyring } = makeKeyring(publicKey);
    const token = await signWith({ client_id: 'c' }, privateKey);
    const verifier = new JWTVerifier(keyring, { issuers: ISSUER });

    await expect(verifier.verify(token)).rejects.toThrow(/missing expiration/);
  });

  it('rejects tokens missing client_id', async () => {
    const [privateKey, publicKey] = await Promise.all([importPrivateKey(), importPublicKey()]);
    const { keyring } = makeKeyring(publicKey);
    const token = await signWith({ exp: nowSec() + 3600 }, privateKey);
    const verifier = new JWTVerifier(keyring, { issuers: ISSUER });

    await expect(verifier.verify(token)).rejects.toThrow(/missing client_id/);
  });

  it('enforces audience when configured', async () => {
    const [privateKey, publicKey] = await Promise.all([importPrivateKey(), importPublicKey()]);
    const { keyring } = makeKeyring(publicKey);

    const verifier = new JWTVerifier(keyring, {
      issuers: ISSUER,
      audiences: 'https://api.example.com',
    });

    const wrongAud = await signWith(
      { client_id: 'c', exp: nowSec() + 3600, aud: 'https://other-api.example.com' },
      privateKey,
    );
    await expect(verifier.verify(wrongAud)).rejects.toThrow(/Audience mismatch/);

    const missingAud = await signWith(
      { client_id: 'c', exp: nowSec() + 3600 },
      privateKey,
    );
    await expect(verifier.verify(missingAud)).rejects.toThrow(/missing audience/);

    const matchingAud = await signWith(
      { client_id: 'c', exp: nowSec() + 3600, aud: 'https://api.example.com' },
      privateKey,
    );
    await expect(verifier.verify(matchingAud)).resolves.toMatchObject({
      aud: 'https://api.example.com',
    });

    const arrayAud = await signWith(
      { client_id: 'c', exp: nowSec() + 3600, aud: ['https://api.example.com', 'other'] },
      privateKey,
    );
    await expect(verifier.verify(arrayAud)).resolves.toMatchObject({
      aud: ['https://api.example.com', 'other'],
    });
  });

  it('treats `audiences: []` as unconfigured (no audience check)', async () => {
    const [privateKey, publicKey] = await Promise.all([importPrivateKey(), importPublicKey()]);
    const { keyring } = makeKeyring(publicKey);

    const verifier = new JWTVerifier(keyring, {
      issuers: ISSUER,
      audiences: [],
    });

    // Missing aud is fine when audiences is unconfigured.
    const missingAud = await signWith(
      { client_id: 'c', exp: nowSec() + 3600 },
      privateKey,
    );
    await expect(verifier.verify(missingAud)).resolves.toBeDefined();

    // Any aud is accepted when audiences is unconfigured.
    const arbitraryAud = await signWith(
      { client_id: 'c', exp: nowSec() + 3600, aud: 'whatever-you-want' },
      privateKey,
    );
    await expect(verifier.verify(arbitraryAud)).resolves.toBeDefined();
  });

  it('supports an audience list', async () => {
    const [privateKey, publicKey] = await Promise.all([importPrivateKey(), importPublicKey()]);
    const { keyring } = makeKeyring(publicKey);
    const verifier = new JWTVerifier(keyring, {
      issuers: ISSUER,
      audiences: ['https://api.example.com', 'https://admin.example.com'],
    });

    const token = await signWith(
      { client_id: 'c', exp: nowSec() + 3600, aud: 'https://admin.example.com' },
      privateKey,
    );
    await expect(verifier.verify(token)).resolves.toBeDefined();
  });

  it('accepts tokens from any issuer in a multi-issuer allowlist', async () => {
    const [privateKey, publicKey] = await Promise.all([importPrivateKey(), importPublicKey()]);
    const { keyring, keyFn } = makeKeyring(publicKey);
    const OTHER_ISSUER = 'https://zone-b.keycard.cloud';

    const verifier = new JWTVerifier(keyring, {
      issuers: [ISSUER, OTHER_ISSUER],
    });

    // Token from the first issuer.
    const t1 = await signWith(
      { client_id: 'c', exp: nowSec() + 3600 },
      privateKey,
    );
    await expect(verifier.verify(t1)).resolves.toMatchObject({ iss: ISSUER });
    expect(keyFn).toHaveBeenCalledWith(ISSUER, KID);

    // Token from the second issuer — we sign with a PrivateKeyring that
    // advertises OTHER_ISSUER so the signer sets iss accordingly.
    const otherPrivateKeyring: PrivateKeyring = {
      key: jest.fn<() => Promise<{ key: CryptoKey; kid: string; issuer: string }>>()
        .mockResolvedValue({ key: privateKey, kid: KID, issuer: OTHER_ISSUER }),
    };
    const otherSigner = new JWTSigner(otherPrivateKeyring);
    const t2 = await otherSigner.sign({ client_id: 'c', exp: nowSec() + 3600 });
    await expect(verifier.verify(t2)).resolves.toMatchObject({ iss: OTHER_ISSUER });
    expect(keyFn).toHaveBeenLastCalledWith(OTHER_ISSUER, KID);
  });

  it('requires exact-string issuer match (trailing slash matters)', async () => {
    const [privateKey, publicKey] = await Promise.all([importPrivateKey(), importPublicKey()]);
    const { keyring, keyFn } = makeKeyring(publicKey);
    const verifier = new JWTVerifier(keyring, {
      issuers: 'https://auth.example.com/', // trailing slash
    });
    // Signer issues with no trailing slash (ISSUER === 'https://auth.example.com').
    const token = await signWith(
      { client_id: 'c', exp: nowSec() + 3600 },
      privateKey,
    );
    await expect(verifier.verify(token)).rejects.toThrow(/Untrusted issuer/);
    expect(keyFn).not.toHaveBeenCalled();
  });

  it('rejects malformed tokens without calling the keyring', async () => {
    const { keyring, keyFn } = makeKeyring(await importPublicKey());
    const verifier = new JWTVerifier(keyring, { issuers: ISSUER });

    await expect(verifier.verify('only.two')).rejects.toThrow(/Malformed JWT/);
    await expect(verifier.verify('not a jwt at all')).rejects.toThrow(/Malformed JWT/);
    expect(keyFn).not.toHaveBeenCalled();
  });

  it('rejects signatures produced by a different key', async () => {
    // Sign with the RS256 private key but give the verifier a different public key.
    const privateKey = await importPrivateKey();
    const { privateKey: otherPriv, publicKey: otherPub } = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
      true,
      ['sign', 'verify'],
    ) as CryptoKeyPair;
    void otherPriv;

    const { keyring } = makeKeyring(otherPub);
    const token = await signWith(
      { client_id: 'c', exp: nowSec() + 3600 },
      privateKey,
    );
    const verifier = new JWTVerifier(keyring, { issuers: ISSUER });

    await expect(verifier.verify(token)).rejects.toThrow(/Invalid signature/);
  });
});
