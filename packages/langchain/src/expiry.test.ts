import { describe, expect, it } from "@jest/globals";
import { subjectTokenExpired } from "./expiry.js";
import { jwtWithExp } from "./testUtils.js";

const now = () => Math.floor(Date.now() / 1000);

describe("subjectTokenExpired", () => {
  it("detects an elapsed exp without verifying the signature", () => {
    expect(subjectTokenExpired(jwtWithExp(now() - 60))).toBe(true);
  });

  it("leaves an unexpired token alone", () => {
    expect(subjectTokenExpired(jwtWithExp(now() + 3600))).toBe(false);
  });

  it("leaves opaque, malformed, and exp-less tokens for the zone to judge", () => {
    const encode = (value: object) =>
      Buffer.from(JSON.stringify(value)).toString("base64url");
    expect(subjectTokenExpired("opaque-token")).toBe(false);
    expect(subjectTokenExpired("not.a.jwt")).toBe(false);
    expect(subjectTokenExpired(`x.${encode({ sub: "user" })}.y`)).toBe(false);
    expect(subjectTokenExpired(`x.${encode({ exp: "soon" })}.y`)).toBe(false);
    expect(subjectTokenExpired(`x.${encode([1, 2])}.y`)).toBe(false);
  });
});
