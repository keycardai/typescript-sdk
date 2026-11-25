import { jest } from '@jest/globals';
import { JWTSigner } from '@keycardai/oauth/jwt/signer';
import { JWTOAuthTokenVerifier } from './jwt.js';
import { JSONWebTokenSigner } from '../../../client/auth/signers/jwt.js'

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
const RFC7515_RS256_PRIVATE_KEY = {
  kty: "RSA",
  n: "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
  e: "AQAB",
  d: "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
  p: "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
  q: "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
  dp: "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
  dq: "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
  qi: "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
}

const RFC7515_RS256_PUBLIC_KEY = {
  kty: "RSA",
  n: "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
  e: "AQAB"
}


describe('JSON Web Token Verifier', () => {

  it('should verify JWS using RSASSA-PKCS1-v1_5 SHA-256', async () => {
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      RFC7515_RS256_PRIVATE_KEY,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
      },
      true,
      ['sign']
    );
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      RFC7515_RS256_PUBLIC_KEY,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
      },
      true,
      ['verify']
    );
    const mockPrivateKeyring = {
      key: jest.fn().mockResolvedValue({ issuer: 'https://auth.example.com', kid: 'RjEwOwOA', key: privateKey }),
    };
    const mockKeyring = {
      key: jest.fn().mockResolvedValue(publicKey),
    };

    const now = Date.now();
    const signer = new JSONWebTokenSigner(mockPrivateKeyring);
    const token = await signer.signToken({
      userId: 'user-1',
      clientId: 's6BhdRkqt3',
      resource: new URL('https://api.example.com'),
      scopes: [ 'profile', 'reademail' ],
      issuedAt: Math.floor(now / 1000),
      expiresAt: Math.floor(now / 1000) + 3600, // Token expires in an hour
    });

    const verifier = new JWTOAuthTokenVerifier(mockKeyring, {
      issuers: 'https://auth.example.com',
    });
    const authInfo = await verifier.verifyAccessToken(token);

    expect(mockKeyring.key).toHaveBeenCalledWith('https://auth.example.com', 'RjEwOwOA');
    expect(authInfo).toStrictEqual({
      token,
      clientId: 's6BhdRkqt3',
      resource: new URL('https://api.example.com'),
      scopes: ['profile', 'reademail'],
      aud: ['https://api.example.com/'],
      expiresAt: Math.floor(now / 1000) + 3600
    });
  });

  it.each([
    { row: '4a', aud: ['resource-a', 'resource-b'], act: { sub: 'actor', act: { sub: 'previous' } }, expected: ['resource-a', 'resource-b'] },
    { row: '4b', aud: 'resource-a', act: undefined, expected: ['resource-a'] },
  ])('row $row: exposes the verified audiences and actor chain', async ({ aud, act, expected }) => {
    const { privateKey, publicKey } = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      false,
      ['sign', 'verify'],
    );
    const issuer = 'https://auth.example.com';
    const now = Math.floor(Date.now() / 1000);
    const signer = new JWTSigner({ key: async () => ({ issuer, kid: 'caller-key', key: privateKey }) });
    const token = await signer.sign({ iss: issuer, sub: 'caller', client_id: 'client', iat: now, exp: now + 60, aud, act });
    const verifier = new JWTOAuthTokenVerifier({ key: async () => publicKey }, { issuers: issuer, audiences: 'resource-a' });

    const caller = await verifier.verifyAccessToken(token);

    expect(caller.aud).toEqual(expected);
    expect(caller.act).toEqual(act);
  });

  describe('missing-audience warning', () => {
    const keyring = { key: jest.fn() };
    let warn: ReturnType<typeof jest.spyOn>;
    beforeEach(() => {
      warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    });
    afterEach(() => {
      warn.mockRestore();
    });

    it('warns exactly once at construction when audiences is omitted', () => {
      new JWTOAuthTokenVerifier(keyring, { issuers: 'https://auth.example.com' });
      expect(warn).toHaveBeenCalledTimes(1);
      expect(String(warn.mock.calls[0][0])).toMatch(/set audiences/);
    });

    it('row 8e: rejects an empty audience list without warning', () => {
      expect(() => new JWTOAuthTokenVerifier(keyring, { issuers: 'https://auth.example.com', audiences: [] }))
        .toThrow(/audiences must not be an empty list/);
      expect(warn).not.toHaveBeenCalled();
    });

    it('does not warn with a string audience', () => {
      new JWTOAuthTokenVerifier(keyring, {
        issuers: 'https://auth.example.com',
        audiences: 'https://api.example.com',
      });
      expect(warn).not.toHaveBeenCalled();
    });

    it('does not warn with an array of audiences', () => {
      new JWTOAuthTokenVerifier(keyring, {
        issuers: 'https://auth.example.com',
        audiences: ['https://api.example.com', 'https://api.example.com/mcp'],
      });
      expect(warn).not.toHaveBeenCalled();
    });
  });

});
