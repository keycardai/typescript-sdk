import { requireClientAuthentication, type ApplicationCredential } from "./credentials.js";
import { fetchAuthorizationServerMetadata, type OAuthAuthorizationServerMetadata } from "./discovery.js";
import { ConfigurationError, HTTPError, OAuthError } from "./errors.js";
import { isTransientMetadataFailure, MetadataRetryCache } from "./metadataRetry.js";
import { DEFAULT_REQUEST_TIMEOUT_MS } from "./requestSignal.js";
import { DEFAULT_DISCOVERY_TTL_MS } from "./tokenEndpoint.js";
import { introspectToken, isUrlWithProtocol, resolveIntrospectionEndpoint } from "./tokenIntrospection.js";

export interface BearerIntrospectionOptions {
  /** Checks the current status of locally verified tokens. Defaults to false. */
  introspect?: boolean;
  /** Resource owner's credential, or credentials keyed by the verified zone issuer URL. */
  credential?: ApplicationCredential | Readonly<Record<string, ApplicationCredential>>;
  /** Introspection request timeout in milliseconds, up to the default of 10 seconds. */
  introspectionTimeoutMs?: number;
  /** Transport for introspection and its authorization server discovery. */
  introspectionFetch?: typeof globalThis.fetch;
}

export function createBearerIntrospectionState() {
  return {
    loggedCauses: new Set<string>(),
    metadata: new Map<string, { value: OAuthAuthorizationServerMetadata; expiresAt: number }>(),
    retry: new MetadataRetryCache(),
  };
}

export function configureBearerIntrospection(
  options: BearerIntrospectionOptions,
  multiZone: boolean,
  state = createBearerIntrospectionState(),
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
    const entries = Object.entries(credential);
    if (entries.length === 0) throw new ConfigurationError("Bearer introspection requires a credential");
    const credentials = new Map<string, ApplicationCredential>();
    for (const [issuer, value] of entries) {
      if (!value || !isApplicationCredential(value)) {
        throw new ConfigurationError("Bearer introspection requires an application credential for each issuer");
      }
      requireClientAuthentication(value, "Bearer introspection");
      const normalizedIssuer = normalizeIssuer(issuer);
      if (credentials.has(normalizedIssuer)) {
        throw new ConfigurationError("Bearer introspection requires a single credential per issuer");
      }
      credentials.set(normalizedIssuer, value);
    }
    forIssuer = issuer => credentials.get(normalizeIssuer(issuer));
  }

  const timeoutMs = Math.min(introspectionTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS, DEFAULT_REQUEST_TIMEOUT_MS);
  function unavailable(cause: string): never {
    if (!state.loggedCauses.has(cause)) {
      state.loggedCauses.add(cause);
      console.warn("Bearer token introspection failed:", cause);
    }
    throw new HTTPError("Bearer token introspection failed", 503);
  }

  async function resolveMetadata(issuer: string): Promise<OAuthAuthorizationServerMetadata> {
    if (!isUrlWithProtocol(issuer, "https:")) {
      throw new ConfigurationError("Bearer introspection requires an HTTPS issuer URL for discovery");
    }
    const cached = state.metadata.get(issuer);
    if (cached && Date.now() < cached.expiresAt) return cached.value;
    state.retry.check(issuer, performance.now());
    try {
      const metadata = await fetchAuthorizationServerMetadata(issuer, { timeoutMs, fetch: introspectionFetch });
      resolveIntrospectionEndpoint(metadata);
      if (state.metadata.get(issuer) === cached) {
        state.metadata.set(issuer, { value: metadata, expiresAt: Date.now() + DEFAULT_DISCOVERY_TTL_MS });
        state.retry.delete(issuer);
      }
      return metadata;
    } catch (error) {
      if (state.metadata.get(issuer) === cached &&
          !(error instanceof ConfigurationError) &&
          (!(error instanceof OAuthError) || error.status !== undefined) &&
          isTransientMetadataFailure(error)) {
        state.retry.record(issuer, error, error, performance.now());
      }
      throw error;
    }
  }

  return async (issuer, token) => {
    if (!issuer) return unavailable("Missing verified issuer");
    const authenticator = forIssuer(issuer);
    if (!authenticator) return unavailable("No credential for the verified issuer");
    try {
      const result = await introspectToken(issuer, token, {
        credential: authenticator,
        metadata: await resolveMetadata(issuer),
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
  if (error instanceof Error && error.name === "TimeoutError") return "Request timed out";
  return "Introspection credential or request failed";
}
