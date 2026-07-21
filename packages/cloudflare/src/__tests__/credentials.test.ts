import { describe, it, expect } from "@jest/globals";
import { generateKeyPairSync } from "node:crypto";
import { WorkersWebIdentity } from "../credentials.js";

function generateRsaPem(type: "pkcs1" | "pkcs8"): string {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type, format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return privateKey;
}

describe("WorkersWebIdentity key import", () => {
  it("imports a PKCS#8 PEM and exposes the public JWKS", async () => {
    const identity = new WorkersWebIdentity(generateRsaPem("pkcs8"), "test-key");

    const jwks = await identity.getPublicJwks();

    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({
      kty: "RSA",
      kid: "test-key",
      alg: "RS256",
      use: "sig",
    });
    expect(typeof jwks.keys[0].n).toBe("string");
    expect(typeof jwks.keys[0].e).toBe("string");
  });

  it("rejects a PKCS#1 PEM with a clear conversion message", async () => {
    const identity = new WorkersWebIdentity(generateRsaPem("pkcs1"));

    await expect(identity.getPublicJwks()).rejects.toThrow(
      /PKCS#1 format .*"BEGIN RSA PRIVATE KEY".*openssl pkcs8 -topk8 -nocrypt/s,
    );
  });

  it("rejects an encrypted PKCS#8 PEM with a clear decryption message", async () => {
    const encryptedPem =
      "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----";
    const identity = new WorkersWebIdentity(encryptedPem);

    await expect(identity.getPublicJwks()).rejects.toThrow(
      /encrypted PKCS#8 .*"BEGIN ENCRYPTED PRIVATE KEY".*openssl pkcs8 -topk8 -nocrypt/s,
    );
  });

  it("rejects a PKCS#1 PEM from prepareTokenExchangeRequest too", async () => {
    const identity = new WorkersWebIdentity(generateRsaPem("pkcs1"));

    await expect(
      identity.prepareTokenExchangeRequest("subject-token", "https://api.example.com"),
    ).rejects.toThrow(/PKCS#1 format/);
  });
});
