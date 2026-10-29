/**
 * Whether a JWT subject token is already expired.
 *
 * Decode-only, no signature verification: the zone remains the authority on
 * validity. The check skips an exchange round trip that is guaranteed to fail
 * and names the failure `subject_token_expired`, so the caller knows to send
 * a fresh bearer. Opaque or malformed tokens, and tokens with no `exp`, return
 * false and are left for the zone to judge.
 *
 * Same contract as `@keycardai/eve`'s `subjectTokenExpired`.
 */
export function subjectTokenExpired(token: string): boolean {
  const claims = decodeClaims(token);
  if (claims === null) return false;
  const exp = claims.exp;
  return typeof exp === "number" && Number.isFinite(exp) && exp <= Date.now() / 1000;
}

/**
 * When a JWT subject token expires, in epoch milliseconds, or undefined for an
 * opaque token or one with no `exp`. Decode-only, like the check above: it
 * only caps how long an exchanged token is cached.
 */
export function subjectTokenExpiresAt(token: string): number | undefined {
  const claims = decodeClaims(token);
  const exp = claims?.exp;
  return typeof exp === "number" && Number.isFinite(exp) ? exp * 1000 : undefined;
}

/**
 * The unverified claims of a JWT, or null when the value is not a JWT.
 *
 * Used for the expiry check above and for the issuer peek that decides whether
 * an inbound bearer is a caller this package recognizes. Never a substitute
 * for verification: every claim a decision depends on is re-read from the
 * verified claims.
 */
export function decodeClaims(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  let payload: unknown;
  try {
    payload = JSON.parse(decodeSegment(parts[1]!));
  } catch {
    return null;
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return null;
  }
  return payload as Record<string, unknown>;
}

function decodeSegment(segment: string): string {
  const base64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
