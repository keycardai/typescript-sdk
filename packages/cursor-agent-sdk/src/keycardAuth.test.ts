import { describe, expect, it } from "@jest/globals";
import { JWTSigner, type JWTClaims, type OAuthKeyring } from "@keycardai/oauth";

import { keycardAuth } from "./keycardAuth.js";
import { memorySubjectTokenStore, SUBJECT_TOKEN_ATTRIBUTE } from "./subjectTokens.js";
import { fakeVerifier, unsignedJwt, validJwt } from "./testing/testUtils.js";

const ZONE = "https://zone.example.com";
const CLAIMS = { iss: ZONE, sub: "user-1", aud: "agent", exp: 1, iat: 0, jti: "j", nbf: 0, scope: "a b", org: "acme", roles: ["x", "y"] };

describe("keycardAuth", () => {
  it("row 15: returns a Keycard AuthContext with projected claims and no token", async () => {
    const token = validJwt(3600, { iss: ZONE });
    const store = memorySubjectTokenStore();
    const verify = keycardAuth({ zoneUrl: `${ZONE}/`, verify: fakeVerifier(token, CLAIMS), subjectTokens: store });
    const ctx = await verify(token);
    expect(ctx).toEqual({
      authenticator: "keycard",
      principalId: "user-1",
      principalType: "user",
      attributes: { iss: ZONE, scope: "a b", org: "acme", roles: "x y" },
    });
    expect(JSON.stringify(ctx)).not.toContain(token);
    expect(store.get(`${ZONE}|user-1`)).toBe(token);
  });

  it("row 16: a bearer from another issuer returns null without verifying", async () => {
    let called = 0;
    const verify = keycardAuth({ zoneUrl: ZONE, verify: async () => { called += 1; return CLAIMS; } });
    expect(await verify(validJwt(3600, { iss: "https://other.example.com" }))).toBeNull();
    expect(await verify("opaque")).toBeNull();
    expect(called).toBe(0);
  });

  it("row 17: a failing verification or a missing scope returns null and does not throw", async () => {
    const token = validJwt(3600, { iss: ZONE });
    const rejecting = keycardAuth({ zoneUrl: ZONE, verify: fakeVerifier("other", CLAIMS) });
    expect(await rejecting(token)).toBeNull();
    const scoped = keycardAuth({ zoneUrl: ZONE, verify: fakeVerifier(token, CLAIMS), requiredScopes: ["a", "c"] });
    expect(await scoped(token)).toBeNull();
    const ok = keycardAuth({ zoneUrl: ZONE, verify: fakeVerifier(token, CLAIMS), requiredScopes: ["a"] });
    expect(await ok(token)).not.toBeNull();
  });

  it("row 17: the real verifier rejects expired, wrong-audience and badly signed zone tokens", async () => {
    const zoneKey = await rsaKeyPair();
    const otherKey = await rsaKeyPair();
    const keyring: OAuthKeyring = { key: async () => zoneKey.publicKey };
    const verify = keycardAuth({ zoneUrl: ZONE, audience: "agent", keyring });
    const now = Math.floor(Date.now() / 1000);
    const good = { iss: ZONE, sub: "user-1", client_id: "app-1", aud: "agent", iat: now, exp: now + 300 };

    expect((await verify(await sign(good, zoneKey.privateKey)))?.principalId).toBe("user-1");
    expect(await verify(await sign({ ...good, exp: now - 60 }, zoneKey.privateKey))).toBeNull();
    expect(await verify(await sign({ ...good, aud: "someone-else" }, zoneKey.privateKey))).toBeNull();
    expect(await verify(await sign(good, otherKey.privateKey))).toBeNull();
  });

  it("row 18: verify replaces the JWKS verifier, and zoneUrl is optional with it", async () => {
    const unusedKeyring: OAuthKeyring = {
      key: async () => {
        throw new Error("the JWKS keyring must not be used when verify is given");
      },
    };
    const verify = keycardAuth({ verify: async () => CLAIMS, keyring: unusedKeyring });
    expect((await verify("anything"))?.principalId).toBe("user-1");
  });

  it("an attributes callback that throws returns null instead of throwing into the chain", async () => {
    const token = validJwt(3600, { iss: ZONE });
    const verify = keycardAuth({
      zoneUrl: ZONE,
      verify: fakeVerifier(token, CLAIMS),
      attributes: () => {
        throw new Error("boom");
      },
    });
    await expect(verify(token)).resolves.toBeNull();
  });

  it("an attributes callback cannot replace iss, which keys the store and the zone check", async () => {
    const token = validJwt(3600, { iss: ZONE });
    const store = memorySubjectTokenStore();
    const verify = keycardAuth({
      zoneUrl: ZONE,
      verify: fakeVerifier(token, CLAIMS),
      attributes: () => ({ iss: "https://other.example.com" }),
      subjectTokens: store,
    });
    const ctx = await verify(token);
    expect(ctx?.attributes?.iss).toBe(ZONE);
    expect(store.get(`${ZONE}|user-1`)).toBe(token);
  });

  it("row 24: the attributes callable is merged over projected claims", async () => {
    const token = validJwt(3600, { iss: ZONE });
    const verify = keycardAuth({ zoneUrl: ZONE, verify: fakeVerifier(token, CLAIMS), attributes: (c) => ({ tenant: String(c.org), scope: "replaced" }) });
    const ctx = await verify(token);
    expect(ctx?.attributes).toMatchObject({ tenant: "acme", scope: "replaced", iss: ZONE });
  });

  it("row 26: principalType service is honored, runtime is a configuration error", async () => {
    const token = validJwt(3600, { iss: ZONE });
    const verify = keycardAuth({ zoneUrl: ZONE, verify: fakeVerifier(token, CLAIMS), principalType: "service" });
    expect((await verify(token))?.principalType).toBe("service");
    expect(() => keycardAuth({ zoneUrl: ZONE, principalType: "runtime" as never })).toThrow();
    expect(() => keycardAuth({})).toThrow();
  });

  it("row 33: attributes retention places the verified token and strips a smuggled claim", async () => {
    const token = unsignedJwt({ iss: ZONE, sub: "user-1", exp: Math.floor(Date.now() / 1000) + 60, [SUBJECT_TOKEN_ATTRIBUTE]: "forged" });
    const store = memorySubjectTokenStore();
    const verify = keycardAuth({
      zoneUrl: ZONE,
      verify: async () => ({ ...CLAIMS, [SUBJECT_TOKEN_ATTRIBUTE]: "forged" }),
      retainSubjectToken: "attributes",
      subjectTokens: store,
    });
    const ctx = await verify(token);
    expect(ctx?.attributes?.[SUBJECT_TOKEN_ATTRIBUTE]).toBe(token);
    expect(store.get(`${ZONE}|user-1`)).toBeUndefined();
    const none = keycardAuth({ zoneUrl: ZONE, verify: async () => CLAIMS, retainSubjectToken: "none", subjectTokens: store });
    const ctx2 = await none(token);
    expect(ctx2?.attributes?.[SUBJECT_TOKEN_ATTRIBUTE]).toBeUndefined();
    expect(store.get(`${ZONE}|user-1`)).toBeUndefined();
  });
});

async function rsaKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
}

async function sign(claims: JWTClaims, privateKey: CryptoKey): Promise<string> {
  const signer = new JWTSigner({ key: async () => ({ key: privateKey, kid: "zone-key", issuer: ZONE }) });
  return signer.sign(claims);
}
