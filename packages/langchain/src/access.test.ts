import { describe, expect, it } from "@jest/globals";
import { AuthProviderConfigurationError } from "@keycardai/oauth";
import { Access } from "./access.js";
import { keycardIdentitySchema } from "./identity.js";

describe("Access factories", () => {
  it("builds the identity for each pattern", () => {
    expect(Access.asSelf()).toEqual({ asSelf: true });
    expect(Access.onBehalfOf("caller-token")).toEqual({ subjectToken: "caller-token" });
    expect(Access.impersonate("user@example.com")).toEqual({
      userIdentifier: "user@example.com",
    });
  });

  it("produces values the context schema accepts", () => {
    for (const identity of [
      Access.asSelf(),
      Access.onBehalfOf("caller-token"),
      Access.impersonate("user@example.com"),
    ]) {
      expect(keycardIdentitySchema.parse(identity)).toEqual(identity);
    }
  });

  it("rejects an empty or whitespace-only subject token", () => {
    for (const value of ["", "   ", "\t\n"]) {
      expect(() => Access.onBehalfOf(value)).toThrow(AuthProviderConfigurationError);
    }
  });

  it("rejects an empty or whitespace-only user identifier", () => {
    for (const value of ["", "   ", "\t\n"]) {
      expect(() => Access.impersonate(value)).toThrow(AuthProviderConfigurationError);
    }
  });

  it("cannot be instantiated: it is a namespace of factories, not a type", () => {
    expect(() => new (Access as unknown as new () => unknown)()).toThrow(TypeError);
    expect(Object.isFrozen(Access)).toBe(true);
  });
});
