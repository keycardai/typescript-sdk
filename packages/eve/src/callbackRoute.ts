import type { HttpRouteDefinition } from "eve/channels";

/** Default path of the stable callback route. */
export const DEFAULT_CALLBACK_PATH = "/keycard/callback";

/** Separator between the random part of `state` and the encoded attempt callback URL. */
const STATE_SEPARATOR = ".";

export interface KeycardCallbackRouteOptions {
  /**
   * Route path, relative to the agent's origin. The Keycard Application
   * registers `<origin><path>` as a redirect URI, and every
   * `Keycard.interactive()` definition on the confidential path names the
   * same value in `callbackPath`. Defaults to `/keycard/callback`.
   */
  path?: string;
  /**
   * The public origin this route is reached at, when it differs from the one
   * the handler sees on the request (a proxy that rewrites `Host` without
   * forwarding it). The attempt callback URL in `state` must be on this
   * origin. Defaults to the request's own origin.
   */
  origin?: string;
}

/**
 * Builds the `state` for an authorization request on the confidential path:
 * the random value the flow generated, then the attempt's eve callback URL,
 * base64url encoded. Both halves are returned by the zone unchanged, so the
 * resume state's exact-match check keeps working and the route can read the
 * callback URL without any state of its own.
 */
export function encodeCallbackState(random: string, callbackUrl: string): string {
  return `${random}${STATE_SEPARATOR}${Buffer.from(callbackUrl, "utf8").toString("base64url")}`;
}

/** The attempt callback URL carried by a confidential-path `state`, or undefined. */
export function decodeCallbackState(state: string): string | undefined {
  const index = state.indexOf(STATE_SEPARATOR);
  if (index <= 0 || index === state.length - 1) return undefined;
  const encoded = state.slice(index + 1);
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) return undefined;
  const decoded = Buffer.from(encoded, "base64url").toString("utf8");
  return decoded.length > 0 ? decoded : undefined;
}

/**
 * Where eve's connection callbacks live, under an optional public route
 * prefix (`EVE_PUBLIC_ROUTE_PREFIX`) when the agent is served under one.
 */
function isAttemptCallbackPath(pathname: string): boolean {
  const prefix = process.env.EVE_PUBLIC_ROUTE_PREFIX?.trim().replace(/\/$/, "");
  const path =
    prefix && prefix !== "" && pathname.startsWith(`${prefix}/`)
      ? pathname.slice(prefix.length)
      : pathname;
  return path.startsWith("/eve/v1/connections/") && path.includes("/callback/");
}

/**
 * One stable callback URL for every `Keycard.interactive()` definition
 * configured with a `clientId`, so the agent's Keycard Application registers
 * that URL once and signs users in as a confidential client.
 *
 * The handler reads the attempt's eve callback URL from `state`, requires it
 * to be on this route's origin under `/eve/v1/connections/<name>/callback/`,
 * and answers `302` to it with every query parameter the zone sent, unchanged
 * (`code` and `state`, or `error` and `error_description`). Anything else
 * answers `400` with no `Location` header, so the route is not an open
 * redirect. It verifies nothing itself: eve's callback checks the attempt
 * token in its path, and `completeAuthorization` checks `state` against the
 * resume state.
 *
 * A plain route object, the shape eve's `GET(path, handler)` returns, so this
 * package loads no eve code. The host mounts it from a channel file:
 *
 * ```ts
 * // agent/channels/keycard.ts
 * import { defineChannel } from "eve/channels";
 * import { keycardCallbackRoute } from "@keycardai/eve";
 *
 * export default defineChannel({ routes: [keycardCallbackRoute()] });
 * ```
 */
export function keycardCallbackRoute(
  options: KeycardCallbackRouteOptions = {},
): HttpRouteDefinition {
  const path = options.path ?? DEFAULT_CALLBACK_PATH;
  const configuredOrigin = options.origin ? new URL(options.origin).origin : undefined;
  return {
    transport: "http",
    method: "GET",
    path,
    async handler(request: Request): Promise<Response> {
      const incoming = new URL(request.url);
      const state = incoming.searchParams.get("state");
      const callbackUrl = state === null ? undefined : decodeCallbackState(state);
      let target: URL;
      try {
        target = new URL(callbackUrl ?? "");
      } catch {
        return new Response("Bad Request", { status: 400 });
      }
      if (
        target.origin !== (configuredOrigin ?? incoming.origin) ||
        !isAttemptCallbackPath(target.pathname)
      ) {
        return new Response("Bad Request", { status: 400 });
      }
      target.search = incoming.search;
      target.hash = "";
      return new Response(null, {
        status: 302,
        headers: { Location: target.toString() },
      });
    },
  };
}
