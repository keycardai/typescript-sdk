import { describe, expect, it } from "@jest/globals";
import { createRequire } from "node:module";

import * as pkg from "./index.js";

describe("package surface", () => {
  it("row 22: exports the verifier, the factories, headersFor and the errors, with no runtime SDK import", () => {
    expect(typeof pkg.keycardAuth).toBe("function");
    expect(Object.isFrozen(pkg.Keycard)).toBe(true);
    expect(pkg.Keycard.asSelf).toBe(pkg.asSelf);
    expect(pkg.Keycard.onBehalfOf).toBe(pkg.onBehalfOf);
    expect(pkg.Keycard.impersonate).toBe(pkg.impersonate);
    expect(typeof pkg.headersFor).toBe("function");
    expect(pkg.ConnectionAuthError.name).toBe("ConnectionAuthError");
    expect(pkg.FailureReason.PRINCIPAL_REQUIRED).toBe("principal_required");
    const require = createRequire(import.meta.url);
    const sdkRoot = require.resolve("@grok/agent-sdk/package.json");
    expect(Object.keys(require.cache).some((p) => p.startsWith(sdkRoot.replace("package.json", "")))).toBe(false);
  });
});
