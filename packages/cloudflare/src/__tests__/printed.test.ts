import { describe, expect, it } from "@jest/globals";
import { generateKeyPairSync } from "node:crypto";
import { inspect } from "node:util";
import { WorkersClientSecret, WorkersWebIdentity } from "../credentials.js";

const RESOURCE = "https://api.example.com";
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

function pkcs8Pem(): string {
  return generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  }).privateKey;
}

// Each case builds a value the way the credential returns it and names the
// secret values in it. util.inspect is what console.log uses. breakLength
// keeps the expected strings on one line.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Built = any;

describe("printed forms leave out secrets", () => {
  it.each<{ name: string; build: () => Promise<Built>; secrets: (v: Built) => string[]; want: string }>([
    {
      name: "WorkersClientSecret getAuth",
      build: async () => new WorkersClientSecret("client-id", "client-secret").getAuth(),
      secrets: () => ["client-secret"],
      want: "ClientAuth { clientId: 'client-id' }",
    },
    {
      name: "WorkersClientSecret token exchange request",
      build: () => new WorkersClientSecret("client-id", "client-secret").prepareTokenExchangeRequest("subject-token", RESOURCE),
      secrets: () => ["subject-token"],
      want: `TokenExchangeRequest { resource: '${RESOURCE}', subjectTokenType: '${ACCESS_TOKEN_TYPE}' }`,
    },
    {
      name: "WorkersWebIdentity token exchange request",
      build: () =>
        new WorkersWebIdentity(pkcs8Pem(), "test-key").prepareTokenExchangeRequest("subject-token", RESOURCE, {
          tokenEndpoint: "https://zone.example.com/oauth/2/token",
        }),
      secrets: (v) => ["subject-token", v.clientAssertion],
      want:
        `TokenExchangeRequest { resource: '${RESOURCE}', subjectTokenType: '${ACCESS_TOKEN_TYPE}', ` +
        "clientAssertionType: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' }",
    },
  ])("$name", async ({ build, secrets, want }) => {
    const value = await build();
    const outputs = [inspect(value, { breakLength: Infinity }), inspect({ nested: value }, { breakLength: Infinity })];

    expect(outputs).toEqual([want, `{ nested: ${want} }`]);
    for (const secret of secrets(value)) {
      expect(secret).toBeTruthy();
      for (const output of outputs) expect(output).not.toContain(secret);
      expect(JSON.stringify(value)).toContain(secret);
    }
  });
});
