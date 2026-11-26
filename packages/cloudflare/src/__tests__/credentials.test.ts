import { describe, it, expect } from "@jest/globals";
import { generateKeyPairSync } from "node:crypto";
import { providesClientAuthentication } from "@keycardai/oauth/credentials";
import { ConfigurationError } from "@keycardai/oauth/errors";
import { WorkersClientSecret, WorkersWebIdentity } from "../credentials.js";

const ISSUER = "https://zone.example.test";
const DEVICE_ENDPOINT = `${ISSUER}/oauth/device`;
const TOKEN_ENDPOINT = `${ISSUER}/oauth/token`;
const JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
function generateRsaPem(type: "pkcs1" | "pkcs8"): string {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type, format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return privateKey;
}

function readClaims(assertion: string) {
  return JSON.parse(Buffer.from(assertion.split(".")[1], "base64url").toString());
}

describe("WorkersClientSecret", () => {
  it("row 7: provides a Basic header and no form fields", async () => {
    const credential = new WorkersClientSecret("client", "secret");

    expect(providesClientAuthentication(credential)).toBe(true);
    await expect(credential.clientAuthentication(ISSUER, DEVICE_ENDPOINT)).resolves.toEqual({
      headers: { Authorization: `Basic ${btoa("client:secret")}` },
      form: {},
    });
  });

  it("row 8: encodes the client ID and secret before constructing the Basic header", async () => {
    const credential = new WorkersClientSecret("ua:client", "a b+%41");

    await expect(credential.clientAuthentication(ISSUER, TOKEN_ENDPOINT)).resolves.toEqual({
      headers: { Authorization: `Basic ${btoa("ua%3Aclient:a%20b%2B%2541")}` },
      form: {},
    });
  });
});

describe("WorkersWebIdentity client assertions", () => {
  it("row 4: keeps the key ID fallback for token exchange without a client ID", async () => {
    const credential = new WorkersWebIdentity(generateRsaPem("pkcs8"), "legacy-key");

    const request = await credential.prepareTokenExchangeRequest("subject-token", "https://api.example.test", {
      tokenEndpoint: TOKEN_ENDPOINT,
    });

    expect(readClaims(request.clientAssertion!)).toMatchObject({
      iss: "legacy-key",
      sub: "legacy-key",
      aud: TOKEN_ENDPOINT,
    });
  });

  it("row 4: treats an empty client ID as missing for token exchange and client authentication", async () => {
    const credential = new WorkersWebIdentity(generateRsaPem("pkcs8"), { keyId: "legacy-key", clientId: "" });

    const request = await credential.prepareTokenExchangeRequest("subject-token", "https://api.example.test", {
      tokenEndpoint: TOKEN_ENDPOINT,
    });

    expect(readClaims(request.clientAssertion!)).toMatchObject({
      iss: "legacy-key",
      sub: "legacy-key",
      aud: TOKEN_ENDPOINT,
    });
    expect(() => credential.checkClientAuthentication()).toThrow(ConfigurationError);
    await expect(credential.clientAuthentication(ISSUER, TOKEN_ENDPOINT)).rejects.toThrow(ConfigurationError);
  });

  it("row 4: requires the token endpoint rather than using the client ID as the audience", async () => {
    const credential = new WorkersWebIdentity(generateRsaPem("pkcs8"), { clientId: "client-abc" });

    await expect(credential.prepareTokenExchangeRequest("subject-token", "https://api.example.test")).rejects.toThrow(
      ConfigurationError,
    );
  });

  it("row 10: uses the resource client ID ahead of the configured client ID in token exchange", async () => {
    const credential = new WorkersWebIdentity(generateRsaPem("pkcs8"), { clientId: "client-abc" });

    const request = await credential.prepareTokenExchangeRequest("subject-token", "https://api.example.test", {
      authInfo: { resource_client_id: "resource-client" },
      tokenEndpoint: TOKEN_ENDPOINT,
    });

    expect(readClaims(request.clientAssertion!)).toMatchObject({
      iss: "resource-client",
      sub: "resource-client",
      aud: TOKEN_ENDPOINT,
    });
  });

  it("row 7: provides a fresh JWT assertion for the supplied endpoint, with no headers", async () => {
    const credential = new WorkersWebIdentity(generateRsaPem("pkcs8"), {
      clientId: "client-abc",
      keyId: "test-key",
    });

    expect(providesClientAuthentication(credential)).toBe(true);
    expect(() => credential.checkClientAuthentication()).not.toThrow();
    const auth = await credential.clientAuthentication(ISSUER, DEVICE_ENDPOINT);
    const tokenAuth = await credential.clientAuthentication(ISSUER, TOKEN_ENDPOINT);

    expect(auth.headers).toEqual({});
    expect(auth.form).toEqual({
      client_assertion_type: JWT_BEARER,
      client_assertion: expect.any(String),
    });
    const [header] = auth.form.client_assertion.split(".");
    expect(JSON.parse(Buffer.from(header, "base64url").toString())).toMatchObject({
      alg: "RS256",
      kid: "test-key",
    });
    const claims = readClaims(auth.form.client_assertion);
    const tokenClaims = readClaims(tokenAuth.form.client_assertion);
    expect(claims).toMatchObject({
      iss: "client-abc",
      sub: "client-abc",
      aud: DEVICE_ENDPOINT,
      jti: expect.any(String),
      iat: expect.any(Number),
      exp: claims.iat + 300,
    });
    expect(tokenClaims).toMatchObject({ aud: TOKEN_ENDPOINT, jti: expect.any(String) });
    expect(tokenClaims.jti).not.toBe(claims.jti);
  });

  it("row 8: reports missing client ID as a configuration error before importing the key", async () => {
    const credential = new WorkersWebIdentity("not-a-pem", "legacy-key");

    expect(() => credential.checkClientAuthentication()).toThrow(ConfigurationError);
    await expect(credential.clientAuthentication(ISSUER, DEVICE_ENDPOINT)).rejects.toThrow(ConfigurationError);
  });
});

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
