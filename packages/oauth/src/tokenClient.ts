import { basicAuthorization } from "./basicAuthorization.js";
import { requireClientAuthentication, type ApplicationCredential, type ClientAuthenticator } from "./credentials.js";
import { ConfigurationError } from "./errors.js";

/**
 * How a token request authenticates the client: with a credential's
 * `clientAuthentication`, or as `clientId` with `clientSecret` for a
 * confidential client.
 */
export type TokenClient =
  | { credential: ClientAuthenticator }
  | { clientId: string; clientSecret?: string };

/** The client options of an operation that takes a credential or a client ID. */
export interface TokenClientOptions {
  credential?: ApplicationCredential;
  clientId?: string;
  clientSecret?: string;
}

/**
 * Returns the client `operation` authenticates as. Throws
 * `ConfigurationError` when a credential is set together with `clientId` or
 * `clientSecret`, when neither a credential nor a non-empty `clientId` is
 * set, or when the credential does not provide `clientAuthentication`. Call
 * it before sending any request, including discovery.
 */
export function resolveTokenClient(options: TokenClientOptions, operation: string): TokenClient {
  if (options.credential !== undefined) {
    if (options.clientId !== undefined || options.clientSecret !== undefined) {
      throw new ConfigurationError(
        `${operation}: set either credential or clientId and clientSecret, not both`,
      );
    }
    return { credential: requireClientAuthentication(options.credential, operation) };
  }
  if (typeof options.clientId === "string" && options.clientId) {
    return { clientId: options.clientId, clientSecret: options.clientSecret };
  }
  throw new ConfigurationError(`${operation}: clientId or credential is required`);
}

/**
 * Adds the client authentication for one request to `endpoint` to `headers`
 * and `params`: the headers and form fields from the credential's
 * `clientAuthentication`, called with `issuer` and `endpoint`; HTTP Basic
 * for a client secret; or `client_id` in the body for a public client.
 * Errors from the credential are thrown as is.
 */
export async function addClientAuthentication(
  client: TokenClient,
  issuer: string,
  endpoint: string,
  headers: Record<string, string>,
  params: URLSearchParams,
): Promise<void> {
  if ("credential" in client) {
    const auth = await client.credential.clientAuthentication(issuer, endpoint);
    Object.assign(headers, auth.headers);
    for (const [name, value] of Object.entries(auth.form)) params.set(name, value);
  } else if (client.clientSecret) {
    headers["Authorization"] = basicAuthorization(client.clientId, client.clientSecret);
  } else {
    params.set("client_id", client.clientId);
  }
}
