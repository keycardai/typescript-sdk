const SUBSTITUTE_USER_HEADER = { typ: "vnd.kc.su+jwt", alg: "none" };

export function buildSubstituteUserToken(identifier: string): string {
  if (!identifier) {
    throw new Error("identifier is required");
  }
  const header = btoau(JSON.stringify(SUBSTITUTE_USER_HEADER));
  const payload = btoau(JSON.stringify({ sub: identifier }));
  return `${header}.${payload}.`;
}

function btoau(str: string): string {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
