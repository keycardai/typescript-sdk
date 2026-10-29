import { describe, expect, it } from "@jest/globals";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

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
    // Every import of the SDK in the package's source is type-only, so the
    // compiled package never loads it at runtime.
    const src = dirname(fileURLToPath(import.meta.url));
    const sources = readdirSync(src, { recursive: true, encoding: "utf8" })
      .filter((file) => file.endsWith(".ts") && !file.endsWith(".test.ts"));
    const sdkImports = sources.flatMap((file) =>
      [...readFileSync(join(src, file), "utf8").matchAll(/^(?:import|export)\b[^;]*?from\s+"@grok\/agent-sdk[^"]*";/gms)].map(
        (match) => match[0],
      ),
    );
    expect(sdkImports.length).toBeGreaterThan(0);
    for (const statement of sdkImports) expect(statement).toMatch(/^(import|export) type /);
  });
});
