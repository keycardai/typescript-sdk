import { jest } from "@jest/globals";
import { ClientSecret } from "./credentials.js";

describe("ClientSecret", () => {
  it("should return auth credentials", () => {
    const cred = new ClientSecret("my-client-id", "my-client-secret");
    const auth = cred.getAuth();

    expect(auth).toEqual({ clientId: "my-client-id", clientSecret: "my-client-secret" });
  });

  it("should prepare token exchange request", async () => {
    const cred = new ClientSecret("my-client-id", "my-client-secret");
    const request = await cred.prepareTokenExchangeRequest(
      "user-access-token",
      "https://api.github.com",
    );

    expect(request.subjectToken).toBe("user-access-token");
    expect(request.resource).toBe("https://api.github.com");
    expect(request.subjectTokenType).toBe("urn:ietf:params:oauth:token-type:access_token");
    expect(request.clientAssertion).toBeUndefined();
  });
});

describe("EKSWorkloadIdentity", () => {
  it("should throw when no token file path can be found", async () => {
    const { EKSWorkloadIdentity } = await import("./credentials.js");
    const { EKSWorkloadIdentityConfigurationError } = await import("./errors.js");

    // Clear any env vars that might exist
    const savedEnvs: Record<string, string | undefined> = {};
    for (const envName of [
      "KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE",
      "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
      "AWS_WEB_IDENTITY_TOKEN_FILE",
    ]) {
      savedEnvs[envName] = process.env[envName];
      delete process.env[envName];
    }

    try {
      expect(() => new EKSWorkloadIdentity()).toThrow(EKSWorkloadIdentityConfigurationError);
    } finally {
      // Restore env vars
      for (const [key, value] of Object.entries(savedEnvs)) {
        if (value !== undefined) {
          process.env[key] = value;
        }
      }
    }
  });
});
