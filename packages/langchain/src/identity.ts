import { z } from "zod";

/**
 * Per-invocation identity, passed as the agent's runtime context.
 *
 * Exactly one of the three should be set:
 * - `subjectToken`: on-behalf-of. The caller's Keycard access token, exchanged
 *   per tool call for resource tokens (RFC 8693).
 * - `userIdentifier`: impersonation. A substitute-user exchange for this user,
 *   authenticated by the agent's own application credential. Forbidden by
 *   default; requires an explicit policy in the zone.
 * - `asSelf: true`: the agent acts as itself (client credentials). No user
 *   anywhere: resource access is attributed to the application alone. This is
 *   deliberately explicit; a run with no identity at all stays an error (or a
 *   sign-in interrupt), never silently escalates to the agent's own authority.
 *
 * Build one through the {@link Access} factories rather than by hand.
 */
export const keycardIdentitySchema = z.object({
  subjectToken: z.string().optional(),
  userIdentifier: z.string().optional(),
  asSelf: z.boolean().optional(),
});

export type KeycardIdentity = z.infer<typeof keycardIdentitySchema>;

/** Whether an identity carries one of the three access patterns. */
export function hasPattern(identity: KeycardIdentity | null | undefined): boolean {
  return !!(identity?.subjectToken || identity?.userIdentifier || identity?.asSelf);
}
