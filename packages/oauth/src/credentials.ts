import { ConfigurationError } from "./errors.js";
import { setPrinted } from "./printed.js";
import type { TokenExchangeRequest } from "./tokenExchange.js";

export { basicAuthorization } from "./basicAuthorization.js";

/**
 * The headers and form fields that authenticate the client on one request to
 * the authorization server. Keys are wire names, such as `Authorization` or
 * `client_assertion`. It never includes a grant parameter such as
 * `grant_type` or `subject_token_type`. The caller merges it into its own
 * request.
 *
 * The values hold a client secret or a client assertion. Build it with
 * `createClientAuthentication`, so that `console.log` prints field names only.
 */
export interface ClientAuthentication {
  headers: Record<string, string>;
  form: Record<string, string>;
}

/**
 * Returns a `ClientAuthentication` with `headers` and `form`. Node's
 * `util.inspect` and `console.log` print the header and form field names, not
 * their values. `JSON.stringify` writes the values.
 */
export function createClientAuthentication(
  headers: Record<string, string>,
  form: Record<string, string>,
): ClientAuthentication {
  return setPrinted({ headers, form }, "ClientAuthentication", (auth) => ({
    headers: Object.keys(auth.headers),
    form: Object.keys(auth.form),
  }));
}

/**
 * Common interface for application-level credentials used in token exchange.
 *
 * Implementations live in downstream packages (@keycardai/mcp, @keycardai/cloudflare)
 * because they depend on platform-specific APIs (Node.js fs, Cloudflare Workers, etc.).
 *
 * The optional `issuer` parameter is the zone's issuer URL; it routes per-zone
 * credentials in multi-zone deployments. Implementations that ignore the issuer
 * (single-zone) are accepted by the interface.
 */
export interface ApplicationCredential {
  /** Zone issuers for an issuer-keyed credential; undefined for a zone-independent credential. */
  readonly zoneIssuers?: readonly string[];
  getAuth(issuer?: string): { clientId: string; clientSecret: string } | null;
  prepareTokenExchangeRequest(
    subjectToken: string,
    resource: string,
    options?: { tokenEndpoint?: string; authInfo?: Record<string, string>; issuer?: string },
  ): Promise<TokenExchangeRequest>;
  /**
   * Returns the client authentication for one request to `endpoint` on the
   * zone `issuer`. Optional. Operations that need it throw
   * `ConfigurationError` before any request when it is missing. Call it once
   * per request: assertion-based credentials sign or fetch a new assertion on
   * every call.
   */
  clientAuthentication?(issuer: string, endpoint: string): Promise<ClientAuthentication>;
  /**
   * Throws `ConfigurationError` when the credential's configuration does not
   * allow `clientAuthentication`, such as a `WebIdentity` without `clientId`.
   * Optional.
   */
  checkClientAuthentication?(): void;
}

/** An `ApplicationCredential` that provides `clientAuthentication`. */
export type ClientAuthenticator = ApplicationCredential &
  Required<Pick<ApplicationCredential, "clientAuthentication">>;

/** Reports whether `credential` provides `clientAuthentication`. */
export function providesClientAuthentication(
  credential: ApplicationCredential,
): credential is ClientAuthenticator {
  return typeof credential.clientAuthentication === "function";
}

/**
 * Returns `credential` when it provides `clientAuthentication` and its
 * `checkClientAuthentication` passes. Throws `ConfigurationError` otherwise.
 * Call it before sending any request, including discovery.
 */
export function requireClientAuthentication(
  credential: ApplicationCredential,
  operation: string,
): ClientAuthenticator {
  if (!providesClientAuthentication(credential)) {
    throw new ConfigurationError(
      `${operation} requires a credential that provides clientAuthentication`,
    );
  }
  credential.checkClientAuthentication?.();
  return credential;
}
