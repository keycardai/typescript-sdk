import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ConfigurationError, CredentialDiscoveryError, discoverCredential } from "../index.js";
import type { CredentialDiscoveryReason, CredentialEnvironment, CredentialType } from "../index.js";
import {
  ClientSecret,
  DEFAULT_FILE_TOKEN_ENV_VARS,
  WebIdentity,
  WorkloadIdentity,
  WorkloadIdentityConfigurationError,
} from "./index.js";

const clientEnv = { KEYCARD_CLIENT_ID: "test-app", KEYCARD_CLIENT_SECRET: "test-secret" };
const tokenVar = "KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE";
const selector = "KEYCARD_APPLICATION_CREDENTIAL_TYPE";
const storageVar = "KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR";

function expectDiscoveryError(
  env: CredentialEnvironment,
  reason: CredentialDiscoveryReason,
  resolvable: readonly CredentialType[],
  message?: string,
): void {
  expect(() => discoverCredential({ env })).toThrow(expect.objectContaining({
    constructor: CredentialDiscoveryError,
    reason,
    resolvable,
    ...(message === undefined ? {} : { message: expect.stringContaining(message) }),
  }));
}

describe("discoverCredential (credential-discovery.md v3)", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "keycard-credential-discovery-"));
  });

  afterEach(() => {
    jest.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
  });

  function tokenFile(name = "projected-token", contents = "test-token"): string {
    const path = join(dir, name);
    writeFileSync(path, contents);
    return path;
  }

  it("row 1: builds a ClientSecret from the client id and secret", () => {
    const credential = discoverCredential({ env: clientEnv });
    expect(credential).toBeInstanceOf(ClientSecret);
    expect(credential.getAuth()).toEqual({ clientId: "test-app", clientSecret: "test-secret" });
  });

  it("row 2: each token-file variable builds a WorkloadIdentity without a client id", async () => {
    for (const name of DEFAULT_FILE_TOKEN_ENV_VARS) {
      const credential = discoverCredential({ env: { [name]: tokenFile(name, name) } });
      expect(credential).toBeInstanceOf(WorkloadIdentity);
      expect((credential as WorkloadIdentity).clientId).toBeUndefined();
      await expect(credential.prepareTokenExchangeRequest("subject", "resource"))
        .resolves.toMatchObject({ clientAssertion: name });
    }
  });

  it("row 3: rejects an environment without credentials", () => {
    expectDiscoveryError({}, "absent", [], "No Keycard application credential");
  });

  it("row 4: rejects a client secret without an id", () => {
    expectDiscoveryError({ KEYCARD_CLIENT_SECRET: "test-secret" }, "incomplete", [], "KEYCARD_CLIENT_ID");
  });

  it("row 5: reports ambiguity between client secret and workload identity", () => {
    expectDiscoveryError(
      { ...clientEnv, [tokenVar]: tokenFile() },
      "ambiguous",
      ["client_secret", "workload_identity"],
      selector,
    );
  });

  it("row 6: selects among all three configured types and accepts the workload identity alias", () => {
    const env = { ...clientEnv, [tokenVar]: tokenFile(), [storageVar]: dir };
    for (const [type, credentialClass] of [
      ["client_secret", ClientSecret],
      ["workload_identity", WorkloadIdentity],
      ["eks_workload_identity", WorkloadIdentity],
      ["web_identity", WebIdentity],
    ] as const) {
      const credential = discoverCredential({ env: { ...env, [selector]: type } });
      expect(credential).toBeInstanceOf(credentialClass);
      if (credential instanceof WorkloadIdentity) {
        expect(credential.clientId).toBe(clientEnv.KEYCARD_CLIENT_ID);
      }
    }
  });

  it("row 7: lists the canonical credential types for an unknown selector", () => {
    expectDiscoveryError(
      { [selector]: "unknown" },
      "unknown_type",
      [],
      "client_secret, workload_identity, web_identity",
    );
  });

  it("row 8: rejects an unknown selector even with a valid client secret", () => {
    expectDiscoveryError({ ...clientEnv, [selector]: "unknown" }, "unknown_type", ["client_secret"]);
  });

  it("row 9: cannot select client_secret without the secret", () => {
    expectDiscoveryError(
      { KEYCARD_CLIENT_ID: "test-app", [selector]: "client_secret" },
      "not_satisfiable",
      [],
      "KEYCARD_CLIENT_SECRET",
    );
  });

  it("row 10: cannot select workload_identity without a token file", () => {
    expectDiscoveryError({ [selector]: "workload_identity" }, "not_satisfiable", [], tokenVar);
  });

  it("row 11: attaches a client id to workload identity without a secret", async () => {
    const credential = discoverCredential({
      env: { KEYCARD_CLIENT_ID: "test-app", [tokenVar]: tokenFile() },
    });
    expect(credential).toBeInstanceOf(WorkloadIdentity);
    expect((credential as WorkloadIdentity).clientId).toBe("test-app");
    await expect(credential.prepareTokenExchangeRequest("subject", "resource"))
      .resolves.toMatchObject({ clientAssertion: "test-token", clientId: "test-app" });
  });

  it("row 12: treats a client id alone as absent", () => {
    expectDiscoveryError({ KEYCARD_CLIENT_ID: "test-app" }, "absent", []);
  });

  it("row 13: uses the first token file in discovery order with the alias", async () => {
    const credential = discoverCredential({
      env: {
        AWS_WEB_IDENTITY_TOKEN_FILE: tokenFile("aws", "aws-token"),
        [tokenVar]: tokenFile("keycard", "keycard-token"),
        [selector]: "eks_workload_identity",
      },
    });
    expect(credential).toBeInstanceOf(WorkloadIdentity);
    await expect(credential.prepareTokenExchangeRequest("subject", "resource"))
      .resolves.toMatchObject({ clientAssertion: "keycard-token" });
  });

  it("row 14: delegates missing and empty token-file validation", () => {
    for (const path of [join(dir, "missing"), tokenFile("empty", "")]) {
      expect(() => discoverCredential({ env: { [tokenVar]: path } }))
        .toThrow(WorkloadIdentityConfigurationError);
    }
  });

  it("row 15: uses the explicit mapping instead of the process environment", () => {
    jest.replaceProperty(process, "env", {
      ...process.env,
      KEYCARD_CLIENT_ID: "process-id",
      KEYCARD_CLIENT_SECRET: "process-secret",
      [selector]: "unknown",
      [tokenVar]: join(dir, "not-used"),
    });
    const credential = discoverCredential({ env: clientEnv });
    expect(credential).toBeInstanceOf(ClientSecret);
    expect(credential.getAuth()).toEqual({ clientId: "test-app", clientSecret: "test-secret" });
  });

  it("row 16: stores the WebIdentity key under the supplied server name", async () => {
    const credential = discoverCredential({ env: { [storageVar]: dir }, webIdentityServerName: "payments-api" });
    expect(credential).toBeInstanceOf(WebIdentity);
    const identity = credential as WebIdentity;
    await identity.bootstrap();
    expect(identity.getPublicJwks().keys).toEqual([expect.objectContaining({ kid: "payments-api" })]);
    expect(existsSync(join(dir, "payments-api.pem"))).toBe(true);
  });

  it("row 17: builds a WebIdentity without a server name", () => {
    expect(discoverCredential({ env: { [storageVar]: dir } })).toBeInstanceOf(WebIdentity);
  });

  it("row 18: reports ambiguity between client secret and web identity", () => {
    expectDiscoveryError({ ...clientEnv, [storageVar]: dir }, "ambiguous", ["client_secret", "web_identity"], selector);
  });

  it("row 19: reports ambiguity between workload identity and web identity", () => {
    expectDiscoveryError(
      { [tokenVar]: tokenFile(), [storageVar]: dir },
      "ambiguous",
      ["workload_identity", "web_identity"],
      selector,
    );
  });

  it("row 20: uses WebIdentity's default storage directory for the web_identity selector", async () => {
    const cwd = process.cwd();
    process.chdir(dir);
    try {
      const credential = discoverCredential({
        env: { [selector]: "web_identity" },
        webIdentityServerName: "payments-api",
      });
      expect(credential).toBeInstanceOf(WebIdentity);
      await (credential as WebIdentity).bootstrap();
      expect(existsSync(join(dir, "server_keys", "payments-api.pem"))).toBe(true);
    } finally {
      process.chdir(cwd);
    }
  });

  it("row 21: builds a WebIdentity from the explicit directory despite process credentials", async () => {
    jest.replaceProperty(process, "env", { ...process.env, ...clientEnv });
    const credential = discoverCredential({ env: { [storageVar]: dir }, webIdentityServerName: "named-server" });
    expect(credential).toBeInstanceOf(WebIdentity);
    await (credential as WebIdentity).bootstrap();
    expect(existsSync(join(dir, "named-server.pem"))).toBe(true);
  });

  it("row 22: reports an absent configuration error with no resolvable types for an empty mapping", () => {
    expectDiscoveryError({}, "absent", []);
    expect(() => discoverCredential({ env: {} })).toThrow(ConfigurationError);
  });

  it("row 23: attaches the client id to inferred and explicitly selected WebIdentity credentials", async () => {
    const cwd = process.cwd();
    process.chdir(dir);
    try {
      for (const selection of [{ [storageVar]: dir }, { [selector]: "web_identity" }]) {
        const credential = discoverCredential({
          env: { ...selection, KEYCARD_CLIENT_ID: "test-app" },
        });
        expect(credential).toBeInstanceOf(WebIdentity);
        const endpoint = "https://issuer.example/token";
        const auth = await (credential as WebIdentity).clientAuthentication("https://issuer.example", endpoint);
        const [, payload] = auth.form.client_assertion.split(".");
        expect(JSON.parse(Buffer.from(payload, "base64url").toString("utf-8")))
          .toMatchObject({ iss: "test-app", sub: "test-app" });
      }
    } finally {
      process.chdir(cwd);
    }
  });

  it("row 24: discovers inferred and explicitly selected WebIdentity credentials with an unset or empty id", () => {
    for (const selection of [{ [storageVar]: dir }, { [selector]: "web_identity" }]) {
      for (const clientId of [{}, { KEYCARD_CLIENT_ID: "" }]) {
        const credential = discoverCredential({ env: { ...selection, ...clientId } });
        expect(credential).toBeInstanceOf(WebIdentity);
        expect(() => (credential as WebIdentity).checkClientAuthentication())
          .toThrow("WebIdentity: clientId is required for client authentication");
      }
    }
  });

  it("treats empty variables as unset", async () => {
    const credential = discoverCredential({
      env: {
        KEYCARD_CLIENT_ID: "",
        KEYCARD_CLIENT_SECRET: "",
        [selector]: "",
        [storageVar]: "",
        [tokenVar]: "",
        AZURE_FEDERATED_TOKEN_FILE: tokenFile(),
      },
    });
    expect(credential).toBeInstanceOf(WorkloadIdentity);
    expect((credential as WorkloadIdentity).clientId).toBeUndefined();
    await expect(credential.prepareTokenExchangeRequest("subject", "resource"))
      .resolves.toMatchObject({ clientAssertion: "test-token" });
  });

  it("ignores a dangling secret when workload identity is explicitly selected", () => {
    const env = { KEYCARD_CLIENT_SECRET: "test-secret", [tokenVar]: tokenFile() };
    expectDiscoveryError(env, "incomplete", ["workload_identity"]);
    expect(discoverCredential({ env: { ...env, [selector]: "workload_identity" } }))
      .toBeInstanceOf(WorkloadIdentity);
  });

  it("reads the process environment on each call when no mapping is supplied", () => {
    const replacement = jest.replaceProperty(process, "env", {});
    expect(() => discoverCredential()).toThrow(CredentialDiscoveryError);
    replacement.replaceValue(clientEnv);
    expect(discoverCredential().getAuth()).toEqual({ clientId: "test-app", clientSecret: "test-secret" });
  });
});
