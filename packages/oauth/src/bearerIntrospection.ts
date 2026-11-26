import { requireClientAuthentication, type ApplicationCredential } from "./credentials.js";
import { ConfigurationError, HTTPError, OAuthError } from "./errors.js";
import { DEFAULT_REQUEST_TIMEOUT_MS } from "./requestSignal.js";
import { introspectToken } from "./tokenIntrospection.js";

export interface BearerIntrospectionOptions {
  /** Checks the current status of locally verified tokens. Defaults to false. */
  introspect?: boolean;
  /** Resource owner's credential, or credentials keyed by the exact verified zone issuer URL. */
  credential?: ApplicationCredential | Readonly<Record<string, ApplicationCredential>>;
  /** Introspection request timeout in milliseconds, up to the default of 10 seconds. */
  introspectionTimeoutMs?: number;
  /** Transport for introspection and its authorization server discovery. */
  introspectionFetch?: typeof globalThis.fetch;
}

export function configureBearerIntrospection(
  options: BearerIntrospectionOptions,
  multiZone: boolean,
  loggedCauses = new Set<string>(),
): ((issuer: string | undefined, token: string) => Promise<boolean>) | undefined {
  if (!options.introspect) return undefined;

  const { credential, introspectionTimeoutMs, introspectionFetch } = options;
  if (!credential) throw new ConfigurationError("Bearer introspection requires a credential");
  if (introspectionTimeoutMs !== undefined &&
      (!Number.isInteger(introspectionTimeoutMs) || introspectionTimeoutMs <= 0)) {
    throw new ConfigurationError("introspectionTimeoutMs must be a positive integer");
  }
  let forIssuer: (issuer: string) => ApplicationCredential | undefined;
  if (isApplicationCredential(credential)) {
    const allowedIssuers = credential.zoneIssuers?.map(normalizeIssuer);
    if (multiZone && !allowedIssuers?.length) {
      throw new ConfigurationError("Bearer introspection requires credentials keyed by issuer for a multi-zone verifier");
    }
    const authenticator = requireClientAuthentication(credential, "Bearer introspection");
    forIssuer = issuer => !allowedIssuers || allowedIssuers.includes(normalizeIssuer(issuer)) ? authenticator : undefined;
  } else {
    const credentials = new Map(Object.entries(credential));
    if (credentials.size === 0) throw new ConfigurationError("Bearer introspection requires a credential");
    for (const value of credentials.values()) {
      if (!value || !isApplicationCredential(value)) {
        throw new ConfigurationError("Bearer introspection requires an application credential for each issuer");
      }
      requireClientAuthentication(value, "Bearer introspection");
    }
    forIssuer = issuer => credentials.get(issuer);
  }

  const timeoutMs = Math.min(introspectionTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS, DEFAULT_REQUEST_TIMEOUT_MS);
  function unavailable(cause: string): never {
    if (!loggedCauses.has(cause)) {
      loggedCauses.add(cause);
      console.warn("Bearer token introspection failed:", cause);
    }
    throw new HTTPError("Bearer token introspection failed", 503);
  }

  return async (issuer, token) => {
    if (!issuer) return unavailable("Missing verified issuer");
    const authenticator = forIssuer(issuer);
    if (!authenticator) return unavailable("No credential for the verified issuer");
    try {
      const result = await introspectToken(issuer, token, {
        credential: authenticator,
        timeoutMs,
        fetch: introspectionFetch,
      });
      return result.active;
    } catch (error) {
      return unavailable(describeFailure(error));
    }
  };
}

function normalizeIssuer(issuer: string): string {
  return issuer.replace(/\/+$/, "");
}

function isApplicationCredential(
  credential: NonNullable<BearerIntrospectionOptions["credential"]>,
): credential is ApplicationCredential {
  return typeof credential.getAuth === "function";
}

function describeFailure(error: unknown): string {
  // Response descriptions and transport errors can include credential or token values.
  if (error instanceof OAuthError) {
    const code = ["invalid_client", "invalid_request", "invalid_response", "server_error"].includes(error.errorCode)
      ? error.errorCode
      : "OAuth error";
    return error.status === undefined ? code : `${code} (HTTP ${error.status})`;
  }
  if (error instanceof HTTPError) {
    if (error.status !== undefined) return `HTTP ${error.status}`;
    if (error.cause instanceof Error && error.cause.name === "TimeoutError") return "Request timed out";
    return "Transport error";
  }
  if (error instanceof ConfigurationError) return "Invalid introspection configuration or metadata";
  return "Introspection credential or request failed";
}
