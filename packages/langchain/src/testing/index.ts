/**
 * Test seams for agents built with `@keycardai/langchain`.
 *
 * Lets tests exercise tools without a zone, a network, or real token exchange.
 *
 * ```ts
 * import { mockAccessContext } from "@keycardai/langchain/testing";
 *
 * await mockAccessContext({ resourceTokens: { [CALENDAR]: "test-token" } }, () =>
 *   listEvents.invoke({ daysAhead: 0 }),
 * );
 * ```
 */

export { mockAccessContext, overrideAccessContext } from "./testUtils.js";
export type { MockAccessContextOptions } from "./testUtils.js";
