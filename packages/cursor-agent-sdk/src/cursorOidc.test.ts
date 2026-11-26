import { describe, expect, it, jest } from "@jest/globals";
import {
  WorkloadIdentity,
  WorkloadIdentityConfigurationError,
  WorkloadIdentityRuntimeError,
} from "@keycardai/oauth/server";

import {
  CursorDeploymentTokenSource,
  WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT,
  type CursorOidcToken,
} from "./cursorOidc.js";

const ZONE = "https://zone.example.com";
const RESOURCE = "https://calendar.example.com";

function futureDate(secondsAhead = 300): Date {
  return new Date(Date.now() + secondsAhead * 1000);
}

describe("CursorDeploymentTokenSource", () => {
  it("workload-identity row 17: calls getOidcToken on every request and returns each opaque JWT", async () => {
    const tokens = ["cursor-jwt-first", "cursor-jwt-second"];
    const getOidcToken = jest.fn(async (_audience: string): Promise<CursorOidcToken> => ({
      token: tokens.shift()!,
      expiresAt: futureDate(300),
    }));

    const source = new CursorDeploymentTokenSource({ audience: ZONE, getOidcToken });
    const credential = new WorkloadIdentity(source, { clientId: "cred-v2-1" });

    expect(getOidcToken).not.toHaveBeenCalled();

    const first = await credential.prepareTokenExchangeRequest("subject-1", RESOURCE);
    const second = await credential.prepareTokenExchangeRequest("subject-2", RESOURCE);

    expect(getOidcToken).toHaveBeenCalledTimes(2);
    expect(getOidcToken).toHaveBeenNthCalledWith(1, ZONE);
    expect(getOidcToken).toHaveBeenNthCalledWith(2, ZONE);
    expect(first.clientAssertion).toBe("cursor-jwt-first");
    expect(first.clientId).toBe("cred-v2-1");
    expect(second.clientAssertion).toBe("cursor-jwt-second");
    expect(second.clientId).toBe("cred-v2-1");
  });

  it("workload-identity row 18: missing helper raises WorkloadIdentityConfigurationError on first fetch", async () => {
    const loadSdk = jest.fn(async () => ({}));
    const source = new CursorDeploymentTokenSource({ audience: ZONE, loadSdk });
    const credential = new WorkloadIdentity(source, { clientId: "cred-v2-1" });

    expect(loadSdk).not.toHaveBeenCalled();

    let caught: unknown;
    try {
      await credential.prepareTokenExchangeRequest("subject-1", RESOURCE);
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(WorkloadIdentityConfigurationError);
    expect((caught as WorkloadIdentityConfigurationError).source).toBe(
      WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT,
    );
    expect((caught as Error).message).toMatch(/getOidcToken/);
    expect(loadSdk).toHaveBeenCalledTimes(1);
  });

  it("workload-identity row 18: SDK load failure raises WorkloadIdentityConfigurationError with cause", async () => {
    const cause = new Error("Cannot find package '@grok/agent-sdk'");
    const source = new CursorDeploymentTokenSource({
      audience: ZONE,
      loadSdk: async () => {
        throw cause;
      },
    });

    let caught: unknown;
    try {
      await source.identityToken();
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(WorkloadIdentityConfigurationError);
    expect((caught as WorkloadIdentityConfigurationError).source).toBe(
      WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT,
    );
    expect((caught as WorkloadIdentityConfigurationError).cause).toBe(cause);
  });

  it("workload-identity row 18: undeclared audience error raises WorkloadIdentityConfigurationError", async () => {
    const oidcError = Object.assign(new Error("OIDC mint failed with HTTP 400: audience not allowed"), {
      name: "OidcTokenError",
      code: "failed",
      status: 400,
      reason: "audience_not_allowed",
    });
    const source = new CursorDeploymentTokenSource({
      audience: ZONE,
      getOidcToken: async () => {
        throw oidcError;
      },
    });
    const credential = new WorkloadIdentity(source, { clientId: "cred-v2-1" });

    let caught: unknown;
    try {
      await credential.prepareTokenExchangeRequest("subject-1", RESOURCE);
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(WorkloadIdentityConfigurationError);
    expect((caught as WorkloadIdentityConfigurationError).source).toBe(
      WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT,
    );
    expect((caught as WorkloadIdentityConfigurationError).cause).toBe(oidcError);
    expect((caught as Error).message).toMatch(/hosting\.oidc\.audiences/);
  });

  it("workload-identity row 18: blank audience raises WorkloadIdentityConfigurationError at construction", () => {
    for (const audience of ["", "   "]) {
      let caught: unknown;
      try {
        new CursorDeploymentTokenSource({ audience });
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(WorkloadIdentityConfigurationError);
      expect((caught as WorkloadIdentityConfigurationError).source).toBe(
        WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT,
      );
    }
  });

  it("workload-identity row 19: token at or after expiresAt raises WorkloadIdentityRuntimeError", async () => {
    const nowMs = 1_700_000_000_000;
    for (const expiresAt of [new Date(nowMs), new Date(nowMs - 1000)]) {
      const source = new CursorDeploymentTokenSource({
        audience: ZONE,
        now: () => nowMs,
        getOidcToken: async () => ({
          token: "expired-cursor-jwt",
          expiresAt,
        }),
      });
      const credential = new WorkloadIdentity(source, { clientId: "cred-v2-1" });

      let caught: unknown;
      try {
        await credential.prepareTokenExchangeRequest("subject-1", RESOURCE);
      } catch (error) {
        caught = error;
      }

      expect(caught).toBeInstanceOf(WorkloadIdentityRuntimeError);
      expect((caught as WorkloadIdentityRuntimeError).source).toBe(
        WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT,
      );
    }
  });

  it("workload-identity row 19: transport or runtime helper failures raise WorkloadIdentityRuntimeError with cause", async () => {
    const cause = Object.assign(new Error("OIDC mint timed out"), {
      name: "OidcTokenError",
      code: "timeout",
    });
    const source = new CursorDeploymentTokenSource({
      audience: ZONE,
      getOidcToken: async () => {
        throw cause;
      },
    });

    let caught: unknown;
    try {
      await source.identityToken();
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(WorkloadIdentityRuntimeError);
    expect((caught as WorkloadIdentityRuntimeError).source).toBe(
      WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT,
    );
    expect((caught as WorkloadIdentityRuntimeError).cause).toBe(cause);
  });
});
