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

export type KeycardUserBuilderOptions = Pick<
  TokenVerifierOptions,
  "issuer" | "audience" | "enableMultiZone" | "keyring" | "requiredScopes"
>;

/**
 * Returns a `UserBuilder` for `@a2a-js/sdk`'s Express handlers that validates
 * Keycard-issued JWTs and injects a `KeycardUser` into the request context.
 *
 * Python equivalent: `KeycardServerCallContextBuilder`, the auth extension
 * point of `a2a-sdk` where Keycard auth is wired in.
 *
 * ```ts
 * const userBuilder = keycardUserBuilder({ issuer: "https://zone.keycard.cloud" });
 * app.post("/a2a/jsonrpc", jsonRpcHandler({ requestHandler, userBuilder }));
 * ```
 *
 * On a valid token the SDK receives a `KeycardUser`; on an invalid or missing
 * token it receives an `UnauthenticatedUser`, and the SDK rejects the request
 * with a 401.
 */
export function keycardUserBuilder(options: KeycardUserBuilderOptions): UserBuilder {
  const verifier = new TokenVerifier({
    issuer: options.issuer,
    audience: options.audience,
    enableMultiZone: options.enableMultiZone,
    keyring: options.keyring,
    requiredScopes: options.requiredScopes,
  });

  return async (req: Request): Promise<User> => {
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
