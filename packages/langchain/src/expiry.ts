/**
 * Whether a JWT subject token is already expired.
 *
 * Decode-only, no signature verification: the zone remains the authority on
 * validity. This check exists to route an expiry to sign-in instead of a
 * consent page, and to skip an exchange round trip that is guaranteed to fail.
 * Opaque or malformed tokens return false and are left for the zone to judge.
 */
export function subjectTokenExpired(token: string): boolean {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  let payload: unknown;
  try {
    payload = JSON.parse(decodeSegment(parts[1]!));
  } catch {
    return false;
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return false;
  }
  const exp = (payload as { exp?: unknown }).exp;
  return typeof exp === "number" && Number.isFinite(exp) && exp <= Date.now() / 1000;
}

/** Decode one base64url JWT segment to its UTF-8 text. */
function decodeSegment(segment: string): string {
  const base64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
