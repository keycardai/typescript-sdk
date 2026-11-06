import { ConfigurationError } from "./errors.js";
import type { TokenExchangeRequest } from "./tokenExchange.js";

/**
 * The headers and form fields that authenticate the client on one request to
 * the authorization server. Keys are wire names, such as `Authorization` or
 * `client_assertion`. It never includes a grant parameter such as
 * `grant_type` or `subject_token_type`. The caller merges it into its own
 * request.
 */
export interface ClientAuthentication {
  headers: Record<string, string>;
  form: Record<string, string>;
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
  getAuth(issuer?: string): { clientId: string; clientSecret: string } | null;
  prepareTokenExchangeRequest(
    subjectToken: string,
    resource: string,
    options?: { tokenEndpoint?: string; authInfo?: Record<string, string>; issuer?: string },
  ): Promise<TokenExchangeRequest>;
  /**
   * Returns the client authentication for one request to `endpoint` on the
   * zone `issuer`. Optional. Refresh with a credential and the device
   * authorization grant need it, and throw `ConfigurationError` before any
   * request when it is absent. `ClientSecret`, `WebIdentity`, and
   * `WorkloadIdentity` provide it. Call it once per request: assertion-based
   * credentials sign or fetch a new assertion on every call.
   */
  clientAuthentication?(issuer: string, endpoint: string): Promise<ClientAuthentication>;
  /**
   * Throws `ConfigurationError` when the credential's configuration does not
   * allow `clientAuthentication`, such as a `WebIdentity` without `clientId`.
   * Optional. Operations call it before they send any request, including
   * discovery.
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
 * Operations call it before they send any request.
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
