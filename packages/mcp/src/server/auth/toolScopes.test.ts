import { InsufficientScopeError } from "@keycardai/oauth/errors";
import type { AuthInfo } from "../../shared/auth.js";
import { missingToolScopes, requireToolScopes, type ToolAuthContext } from "./toolScopes.js";

function contextWithScopes(scopes: string[]): ToolAuthContext {
  const authInfo: AuthInfo = {
    token: "test-token",
    clientId: "client-123",
    scopes,
  };
  return { http: { authInfo } };
}

describe("Tool scope checks", () => {

  describe("missingToolScopes", () => {

    it("should return an empty list when all required scopes are granted", () => {
      const ctx = contextWithScopes(["read", "write", "admin"]);
      expect(missingToolScopes(ctx, ["read", "write"])).toStrictEqual([]);
    });

    it("should return only the scopes the token does not carry", () => {
      const ctx = contextWithScopes(["read"]);
      expect(missingToolScopes(ctx, ["read", "write", "admin"])).toStrictEqual(["write", "admin"]);
    });

    it("should report all required scopes missing without auth info", () => {
      expect(missingToolScopes({}, ["read", "write"])).toStrictEqual(["read", "write"]);
      expect(missingToolScopes({ http: {} }, ["read"])).toStrictEqual(["read"]);
    });

    it("should return an empty list for empty requirements", () => {
      expect(missingToolScopes({}, [])).toStrictEqual([]);
      expect(missingToolScopes(contextWithScopes([]), [])).toStrictEqual([]);
    });

  });

  describe("requireToolScopes", () => {

    it("should return the auth info when all required scopes are granted", () => {
      const ctx = contextWithScopes(["read", "write"]);
      const authInfo = requireToolScopes(ctx, ["read"]);
      expect(authInfo).toBe(ctx.http?.authInfo);
    });

    it("should throw insufficient_scope listing the missing scopes", () => {
      const ctx = contextWithScopes(["read"]);
      let thrown: unknown;
      try {
        requireToolScopes(ctx, ["read", "write", "admin"]);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(InsufficientScopeError);
      expect(String(thrown)).toContain("write admin");
    });

    it("should throw insufficient_scope for unauthenticated calls", () => {
      expect(() => requireToolScopes({}, [])).toThrow(InsufficientScopeError);
      expect(() => requireToolScopes({ http: {} }, ["read"])).toThrow(InsufficientScopeError);
    });

  });

});
