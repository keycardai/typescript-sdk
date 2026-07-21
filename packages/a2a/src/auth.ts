import type { Request } from "express";
import type { User } from "@a2a-js/sdk/server";
import type { UserBuilder } from "@a2a-js/sdk/server/express";
import { TokenVerifier } from "@keycardai/oauth/server/tokenVerifier";
import type { TokenVerifierOptions } from "@keycardai/oauth/server/tokenVerifier";
import type { AccessToken } from "@keycardai/oauth/server/accessToken";
import type { RequestContext } from "@a2a-js/sdk/server";
import { A2AError } from "@a2a-js/sdk/server";

/**
 * A Keycard-verified user. Implements `@a2a-js/sdk`'s `User` interface
 * and carries the full `AccessToken` for downstream delegation.
 *
 * Python equivalent: the `KeycardUser` injected into `ServerCallContext.state`
 * by `KeycardServerCallContextBuilder`.
 */
export class KeycardUser implements User {
  readonly accessToken: AccessToken;

  constructor(accessToken: AccessToken) {
    this.accessToken = accessToken;
  }

  get isAuthenticated(): boolean {
    return true;
  }

  get userName(): string {
    return this.accessToken.clientId;
  }
}

/**
 * Verification options for `keycardUserBuilder`'s standalone mode.
 *
 * Set `audience` to this agent's public URL so tokens minted for other
 * resources are rejected. When `audience` is unset, the audience check
 * is disabled.
 */
export type KeycardUserBuilderOptions = Pick<
  TokenVerifierOptions,
  "issuer" | "audience" | "enableMultiZone" | "keyring" | "requiredScopes"
>;

/**
 * Returns a `UserBuilder` for `@a2a-js/sdk`'s Express handlers that injects
 * a `KeycardUser` into the request context.
 *
 * Mount `requireBearerAuth` from `@keycardai/express` (re-exported by this
 * package) in front of the JSON-RPC handler. The middleware verifies the
 * bearer token, responds to auth failures with HTTP 401 and an RFC 6750
 * `WWW-Authenticate` challenge, and sets `req.auth` to the verified
 * `AccessToken`. The builder then wraps that token in a `KeycardUser`
 * without verifying it a second time:
 *
 * ```ts
 * app.post(
 *   "/a2a/jsonrpc",
 *   requireBearerAuth({ zoneUrl: "https://zone.keycard.cloud" }),
 *   jsonRpcHandler({ requestHandler, userBuilder: keycardUserBuilder() }),
 * );
 * ```
 *
 * When `req.auth` is absent, the builder falls back to verifying the bearer
 * token itself using `options` (which are then required). In that standalone
 * mode auth failures throw an A2A `-32001` error, which `@a2a-js/sdk`'s
 * handlers surface as a JSON-RPC error body over HTTP 500 with no
 * `WWW-Authenticate` challenge. Prefer the `requireBearerAuth` composition.
 *
 * Python equivalent: `KeycardServerCallContextBuilder`, the auth extension
 * point of `a2a-sdk` where Keycard auth is wired in.
 */
export function keycardUserBuilder(options?: KeycardUserBuilderOptions): UserBuilder {
  const verifier = options
    ? new TokenVerifier({
        issuer: options.issuer,
        audience: options.audience,
        enableMultiZone: options.enableMultiZone,
        keyring: options.keyring,
        requiredScopes: options.requiredScopes,
      })
    : undefined;

  return async (req: Request): Promise<User> => {
    // Token already verified by requireBearerAuth middleware: reuse it.
    const preVerified = (req as Request & { auth?: AccessToken }).auth;
    if (preVerified) {
      return new KeycardUser(preVerified);
    }

    if (!verifier) {
      // -32001 is the A2A unauthorized error code
      throw new A2AError(
        -32001,
        "Request not authenticated: mount requireBearerAuth() in front of this handler, or pass verification options to keycardUserBuilder()",
      );
    }

    const authorization = req.headers.authorization;
    if (!authorization?.startsWith("Bearer ")) {
      // -32001 is the A2A unauthorized error code
      throw new A2AError(-32001, "Missing or invalid Authorization header");
    }
    const token = authorization.slice(7);
    const accessToken = await verifier.verifyToken(token);
    if (!accessToken) {
      throw new A2AError(-32001, "Invalid or expired token");
    }
    return new KeycardUser(accessToken);
  };
}

/**
 * Extract the `AccessToken` from an A2A `RequestContext`.
 * Returns `null` if the request was not authenticated with a Keycard token.
 *
 * ```ts
 * const auth = getKeycardAuth(requestContext);
 * if (!auth) throw new Error("unauthenticated");
 * // use auth.token for downstream delegation
 * ```
 */
export function getKeycardAuth(requestContext: RequestContext): AccessToken | null {
  const user = requestContext.context?.user;
  if (user instanceof KeycardUser) {
    return user.accessToken;
  }
  return null;
}

class UnauthenticatedUser implements User {
  get isAuthenticated(): boolean {
    return false;
  }
  get userName(): string {
    return "anonymous";
  }
}
