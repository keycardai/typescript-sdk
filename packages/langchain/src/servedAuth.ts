/**
 * Inbound authentication for an agent served by LangGraph JS.
 *
 * The middleware in this package grants outbound access for a run. This module
 * covers the other half: who the run is for. It verifies the caller's own
 * zone-issued bearer on every request, hands the run that identity plus the raw
 * bearer, and scopes threads, runs and store items to the caller who created
 * them. One deployment then serves many callers, each under their own
 * delegation chain, instead of acting as whoever signed in last.
 *
 * ```ts
 * import { Auth } from "@langchain/langgraph-sdk/auth";
 * import { installOwnerAuthorization, zoneAuthenticator } from "@keycardai/langchain/serve";
 *
 * export const auth = installOwnerAuthorization(
 *   new Auth().authenticate(
 *     zoneAuthenticator({
 *       zoneUrl: "https://your-zone.keycard.cloud",
 *       resource: "https://your-agent.example",
 *     }),
 *   ),
 * );
 * ```
 *
 * Point `langgraph.json` at that object and set `disable_studio_auth` to true;
 * see the package README for why that flag is not optional.
 *
 * Importing this module needs `@langchain/langgraph-sdk`, an optional peer, so
 * it is a subpath export rather than part of the package root.
 */

import { createHash } from "node:crypto";
import { JWKSOAuthKeyring, JWTVerifier } from "@keycardai/oauth";
import { HTTPException, isStudioUser } from "@langchain/langgraph-sdk/auth";
import type { Auth, AuthFilters } from "@langchain/langgraph-sdk/auth";
import { OWNER_KEY, SUBJECT_TOKEN_FIELD } from "./servedCaller.js";

/** The result of verifying one inbound bearer. */
export interface VerifiedCaller {
  identity: string;
  scopes?: readonly string[];
}

/** The verification seam: a bearer in, a verified caller out, throw to reject. */
export type VerifyToken = (token: string) => Promise<VerifiedCaller>;

export interface ZoneAuthenticatorOptions {
  /**
   * Keycard zone URL. The bearer's issuer, and the base of the metadata URL
   * named in the challenge.
   */
  zoneUrl: string;
  /**
   * This agent's resource URL, the audience the bearer must carry. A token
   * minted for another resource is rejected.
   */
  resource: string;
  /**
   * Injectable verification seam. Left unset, tokens are verified against the
   * zone's JWKS. Tests pass a stub so the suite needs no zone and no network.
   */
  verify?: VerifyToken;
}

/** What the hook returns: the verified caller, plus the bearer they sent. */
export interface ZoneAuthUser {
  identity: string;
  display_name: string;
  permissions: string[];
  /** The caller's raw bearer, exchanged per tool call by the middleware. */
  subject_token: string;
}

const OWNER_SEGMENT_LENGTH = 16;

/**
 * RFC 8414 metadata for the zone that issues the accepted bearers.
 *
 * A challenged client reads it to find where to sign in.
 */
function metadataUrl(zoneUrl: string): string {
  return `${zoneUrl}/.well-known/oauth-authorization-server`;
}

/**
 * A bearer challenge that survives the response.
 *
 * The SDK's own `HTTPException` is the right one here, unlike Python, where
 * the SDK exception drops headers: the JS server rethrows anything carrying a
 * numeric `status` and `headers` as an HTTP exception, status and headers
 * intact. A plain `Error` would surface as a 500 with no challenge.
 */
function challenge(
  metadata: string,
  status: number,
  error: string,
  description: string,
): HTTPException {
  return new HTTPException(status, {
    message: description,
    headers: {
      "WWW-Authenticate":
        `Bearer error="${error}", error_description="${description}", ` +
        `authorization_uri="${metadata}"`,
    },
  });
}

function bearer(request: Request): string | null {
  const raw = request.headers.get("authorization");
  if (raw === null) return null;
  const separator = raw.trim().indexOf(" ");
  if (separator < 0) return null;
  const scheme = raw.trim().slice(0, separator);
  const token = raw.trim().slice(separator + 1).trim();
  if (scheme.toLowerCase() !== "bearer" || !token) return null;
  return token;
}

/** Verify against the zone's JWKS, audienced at this agent's resource. */
function zoneVerify(zoneUrl: string, resource: string): VerifyToken {
  const verifier = new JWTVerifier(new JWKSOAuthKeyring(), {
    issuers: [zoneUrl],
    audiences: [resource],
  });

  return async (token: string): Promise<VerifiedCaller> => {
    const claims = await verifier.verify(token);
    const email = claims["email"];
    const identity = typeof email === "string" && email ? email : claims.sub;
    if (!identity) {
      throw new Error("verified token carries neither email nor sub");
    }
    const scope = claims.scope;
    return {
      identity,
      scopes: typeof scope === "string" ? scope.split(" ").filter(Boolean) : [],
    };
  };
}

/**
 * Build the `authenticate` hook that verifies the caller's bearer.
 *
 * The returned hook reads the `Authorization` header, verifies the bearer as a
 * zone-issued JWT, and returns the verified identity together with the raw
 * bearer under `subject_token`. LangGraph delivers that object to the run as
 * `configurable.langgraph_auth_user`, which is the only per-request channel
 * the middleware can read the caller's token from
 * (`identitySource: "auth_user"`).
 *
 * Every rejection, including an unexpected failure inside verification, is a
 * 401 carrying a `WWW-Authenticate: Bearer` challenge that names the zone's
 * metadata URL, so a client learns where to sign in.
 */
export function zoneAuthenticator(
  options: ZoneAuthenticatorOptions,
): (request: Request) => Promise<ZoneAuthUser> {
  if (!options.zoneUrl) {
    throw new Error("zoneAuthenticator requires a zoneUrl");
  }
  if (!options.resource) {
    throw new Error(
      "zoneAuthenticator requires a resource (the token audience)",
    );
  }
  // Zone tokens carry no trailing slash in their issuer, and the verifier
  // matches issuers exactly, so a slash on the configured zoneUrl would reject
  // every token while the challenge names a correct-looking URL.
  const zoneUrl = options.zoneUrl.replace(/\/+$/, "");
  const metadata = metadataUrl(zoneUrl);
  let verify = options.verify;

  return async (request: Request): Promise<ZoneAuthUser> => {
    const token = bearer(request);
    if (token === null) {
      throw challenge(
        metadata,
        401,
        "invalid_request",
        "A zone-issued bearer token is required",
      );
    }
    if (verify === undefined) verify = zoneVerify(zoneUrl, options.resource);

    let caller: VerifiedCaller;
    try {
      caller = await verify(token);
    } catch (e) {
      throw challenge(
        metadata,
        401,
        "invalid_token",
        `Bearer token verification failed: ${errorName(e)}`,
      );
    }
    return {
      identity: caller.identity,
      display_name: caller.identity,
      permissions: [...(caller.scopes ?? [])],
      // The middleware exchanges this per tool call, under the caller's own
      // delegation chain. Nothing else carries it into the run.
      [SUBJECT_TOKEN_FIELD]: token,
    };
  };
}

function errorName(e: unknown): string {
  return e instanceof Error ? e.constructor.name : typeof e;
}

/** A user as the framework hands it to an authorization handler. */
interface HandlerUser {
  identity: string;
  is_authenticated: boolean;
  display_name: string;
  permissions: string[];
}

/** The identity that owns whatever this request creates or reads. */
function owner(user: HandlerUser): string {
  if (isStudioUser(user)) {
    throw new HTTPException(403, { message: "Studio users are not accepted" });
  }
  if (!user.identity) {
    throw new HTTPException(403, {
      message: "Authenticated identity is required",
    });
  }
  return user.identity;
}

/**
 * A store-safe owner segment.
 *
 * Identities are usually emails, and the store rejects namespace labels
 * containing periods, so the raw identity cannot be a label. A digest is
 * dot-free, fixed-shape, and collision-safe where naive character replacement
 * is not: `a.b@x` and `a_b@x` must not share a namespace.
 */
function ownerSegment(identity: string): string {
  return createHash("sha256")
    .update(identity, "utf8")
    .digest("hex")
    .slice(0, OWNER_SEGMENT_LENGTH);
}

/** Record the owner on the resource being created, and filter on it. */
function stamp(user: HandlerUser, value: unknown): AuthFilters<string> {
  const identity = owner(user);
  const target = (value ?? {}) as { metadata?: Record<string, unknown> | null };
  let metadata = target.metadata;
  if (metadata === undefined || metadata === null) {
    metadata = {};
    target.metadata = metadata;
  }
  metadata[OWNER_KEY] = identity;
  return { [OWNER_KEY]: identity };
}

/**
 * Scope threads, runs and store items to the caller who created them.
 *
 * Authentication says who is calling; it grants no ownership by itself, so
 * without these handlers any valid caller can read and resume any other
 * caller's thread. Installs, on the passed `Auth` object:
 *
 * - owner metadata stamped on thread creation, run creation and thread
 *   updates, taken from the verified identity and never from the request
 *   body, so an update cannot reassign ownership either,
 * - thread reads, searches and deletes filtered by that owner, which is also
 *   what stops a cross-owner resume,
 * - store namespaces prefixed in place with a digest of the owner, so puts,
 *   gets, deletes, searches and prefixed namespace listings all run inside
 *   the caller's own subtree,
 * - a prefix-less `list_namespaces` denied outright: the server queries it in
 *   a way no owner scope can reach, so enumeration is unsupported rather than
 *   unscoped,
 * - assistant reads and searches left open to any authenticated caller, so a
 *   chat client can fetch the graph schema, while creating or mutating an
 *   assistant is denied,
 * - Studio users denied,
 * - a catch-all denying every unmatched resource and action pair, because the
 *   framework otherwise fails open.
 *
 * Returns the same `Auth` object, so the call can be chained.
 */
export function installOwnerAuthorization<T extends Auth<never, never, never>>(
  auth: T,
): T {
  const target = auth as unknown as Auth;

  // threads:update is stamped too: the server merges the update's metadata
  // into the thread, so without the stamp a caller could hand their own
  // thread to another identity (or lock themselves out) by writing
  // `metadata.owner` in the body.
  target.on(
    ["threads:create", "threads:create_run", "threads:update"],
    ({ user, value }) => stamp(user, value),
  );

  target.on("threads", ({ user }) => ({ [OWNER_KEY]: owner(user) }));

  // Store events split by how the server consumes the mutated value. put, get
  // and delete read `value.namespace` back and operate on it, so any write to
  // the field reaches them. search and a prefixed list_namespaces query the
  // request's own payload, and `value.namespace` IS that payload array (the
  // server passes it by reference), so prepending in place is what puts the
  // owner segment on the queried prefix. That positional scoping is the
  // isolation: every query runs inside the caller's own subtree, which is
  // also how the Python runtime behaves. The returned containment filter is a
  // second layer only, never sufficient by itself: namespace labels are
  // caller-chosen, so any caller can store items whose namespace merely
  // contains another caller's (publicly computable) segment, and a
  // containment match would surface those in the victim's results.
  target.on("store", ({ action, user, value }) => {
    const segment = ownerSegment(owner(user));
    const item = value as { namespace?: string[] | null };
    if (Array.isArray(item.namespace)) {
      item.namespace.unshift(segment);
    } else if (action === "put" || action === "get" || action === "delete") {
      // These read the value back, so a fresh array reaches the operation.
      item.namespace = [segment];
    } else {
      // A prefix-less list_namespaces: the server queries with no prefix and
      // ignores the mutated value, and the only expressible filter is the
      // forgeable containment match, so no owner scope can reach the query.
      // Denied rather than unscoped; callers reach their own data through
      // scoped search and get.
      throw new HTTPException(403, {
        message:
          "Namespace enumeration without a prefix is not supported on this deployment",
      });
    }
    return { namespace: { $contains: segment } };
  });

  // Assistants are the deployment's static graph config, not caller data.
  target.on(["assistants:read", "assistants:search"], ({ user }) => {
    owner(user);
    return true;
  });

  target.on("*", () => false);

  return auth;
}
