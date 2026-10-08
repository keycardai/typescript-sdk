import { describe, expect, it } from "@jest/globals";
import { InsufficientScopeError } from "@keycardai/oauth";
import type { SessionAuthContext } from "eve/context";

import { missingToolScopes, requireToolScopes } from "./toolScopes.js";

const ZONE = "https://zone.example.com";

function principal(
  scope: string | readonly string[] | undefined,
  overrides: Partial<SessionAuthContext> = {},
): SessionAuthContext {
  return {
    attributes: scope === undefined ? {} : { scope },
    authenticator: "keycard",
    issuer: ZONE,
    principalId: "user-1",
    principalType: "user",
    subject: "user-1",
    ...overrides,
  };
}

function ctx(current: SessionAuthContext | null) {
  return { session: { auth: { current } } };
}

describe("tool scopes", () => {
  it("row 40: a Keycard principal carrying the scope passes", () => {
    const current = principal("read write");
    expect(missingToolScopes(ctx(current), ["write"])).toEqual([]);
    expect(requireToolScopes(ctx(current), ["write"])).toBe(current);
  });

  it("row 41: a missing scope is listed and thrown", () => {
    const c = ctx(principal("read"));
    expect(missingToolScopes(c, ["read", "write"])).toEqual(["write"]);
    expect(() => requireToolScopes(c, ["read", "write"])).toThrow(InsufficientScopeError);
    expect(() => requireToolScopes(c, ["read", "write"])).toThrow(
      "Tool call requires additional scopes: write",
    );
  });

  it("row 42: string and list forms grant the same scopes", () => {
    expect(missingToolScopes(ctx(principal("read write")), ["read", "write"])).toEqual([]);
    expect(missingToolScopes(ctx(principal(["read", "write"])), ["read", "write"])).toEqual([]);
    expect(missingToolScopes(ctx(principal(undefined)), ["read"])).toEqual(["read"]);
  });

  it("row 43: an unauthenticated turn is missing every scope", () => {
    expect(missingToolScopes(ctx(null), ["read", "write"])).toEqual(["read", "write"]);
    expect(() => requireToolScopes(ctx(null), ["read"])).toThrow(InsufficientScopeError);
    expect(() => requireToolScopes(ctx(null), ["read"])).toThrow(
      "not authenticated by Keycard",
    );
  });

  it("row 44: a scope attribute from a non-Keycard principal is ignored", () => {
    const other = principal("read write", {
      authenticator: "oidc",
      issuer: "https://idp.example.com",
    });
    expect(missingToolScopes(ctx(other), ["read"])).toEqual(["read"]);
    expect(() => requireToolScopes(ctx(other), ["read"])).toThrow(InsufficientScopeError);
  });

  it("row 44: zoneUrl pins the issuer, trailing slash tolerated", () => {
    const c = ctx(principal("read"));
    expect(missingToolScopes(c, ["read"], { zoneUrl: `${ZONE}/` })).toEqual([]);
    expect(missingToolScopes(c, ["read"], { zoneUrl: "https://other.example.com" })).toEqual([
      "read",
    ]);
  });
});
