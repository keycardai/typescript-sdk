import { z } from "zod";
import { requireClientAuthentication, type ApplicationCredential } from "./credentials.js";
import { assertMetadataIssuer, fetchAuthorizationServerMetadata, type OAuthAuthorizationServerMetadata } from "./discovery.js";
import { ConfigurationError, HTTPError, OAuthError, TokenIntrospectionHTTPError } from "./errors.js";
import { requestSignal } from "./requestSignal.js";
import { readResponseText } from "./responseBody.js";
import { parseOAuthError } from "./tokenEndpointError.js";

const TokenIntrospectionSchema = z.discriminatedUnion("active", [
  z.object({ active: z.literal(false) }),
  z.looseObject({
    active: z.literal(true),
    token_type: z.string().optional().catch(undefined),
    iss: z.string().optional().catch(undefined),
    sub: z.string().optional().catch(undefined),
    client_id: z.string().optional().catch(undefined),
    aud: z.union([z.string(), z.array(z.string())]).optional().catch(undefined),
    scope: z.string().transform((scope) => scope.split(" ").filter(Boolean)).optional().catch(undefined),
    sid: z.string().optional().catch(undefined),
    jti: z.string().optional().catch(undefined),
    iat: z.number().int().optional().catch(undefined),
    exp: z.number().int().optional().catch(undefined),
  }),
]);

/** The token's current status and, when active, its verified claims. */
export type TokenIntrospection = z.output<typeof TokenIntrospectionSchema>;

export interface IntrospectTokenOptions {
  credential: ApplicationCredential;
  tokenTypeHint?: string;
  /** Pre-discovered metadata. When supplied, no discovery request is made. */
  metadata?: OAuthAuthorizationServerMetadata;
  /** HTTP transport for discovery and introspection. Defaults to global fetch. */
  fetch?: typeof globalThis.fetch;
  signal?: AbortSignal;
  /** Timeout in milliseconds per request (default 10 seconds; 0 disables). */
  timeoutMs?: number;
}

/** Check a token at the advertised RFC 7662 endpoint without caching the result. */
export async function introspectToken(
  issuer: string | undefined,
  token: string,
  options: IntrospectTokenOptions,
): Promise<TokenIntrospection> {
  if (typeof token !== "string" || token.length === 0) {
    throw new ConfigurationError("introspectToken requires a token");
  }
  const { credential, metadata, tokenTypeHint } = options;
  if (!credential) {
    throw new ConfigurationError("introspectToken requires a credential");
  }
  const authenticator = requireClientAuthentication(credential, "introspectToken");
  const zoneIssuer = issuer ?? metadata?.issuer;
  if (!isUrlWithProtocol(zoneIssuer, "http:", "https:")) {
    throw new ConfigurationError("introspectToken requires an HTTP or HTTPS issuer URL");
  }
  if (!metadata && !isUrlWithProtocol(zoneIssuer, "https:")) {
    throw new ConfigurationError("introspectToken requires an HTTPS issuer URL for discovery");
  }
  if (metadata) assertMetadataIssuer(zoneIssuer, metadata, "introspectToken");

  const transport = options.fetch ?? globalThis.fetch;
  const server = metadata ?? await withTransport("Introspection discovery", options, (signal) =>
    fetchAuthorizationServerMetadata(zoneIssuer, { signal, timeoutMs: 0, fetch: transport }),
  );
  const endpoint = resolveIntrospectionEndpoint(server);

  options.signal?.throwIfAborted();
  const params = new URLSearchParams({ token });
  if (tokenTypeHint !== undefined) params.set("token_type_hint", tokenTypeHint);
  // The zone issuer is the audience for an introspection client assertion.
  const auth = await authenticator.clientAuthentication(zoneIssuer, zoneIssuer);
  const headers = {
    Accept: "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
    ...auth.headers,
  };
  for (const [name, value] of Object.entries(auth.form)) params.set(name, value);

  return withTransport("Token introspection", options, async (signal) => {
    const response = await transport(endpoint, {
      method: "POST",
      headers,
      body: params.toString(),
      signal,
      redirect: "manual",
    });
    const text = await readResponseText(response);
    if (response.status !== 200) {
      throw parseOAuthError(text, response.status) ?? new HTTPError(
        `Token introspection failed (HTTP ${response.status})`,
        response.status,
        undefined,
        response.headers.get("Retry-After") ?? undefined,
      );
    }
    try {
      return TokenIntrospectionSchema.parse(JSON.parse(text));
    } catch {
      throw new OAuthError("invalid_response", "Invalid token introspection response", undefined, {
        retryable: true,
        status: response.status,
      });
    }
  });
}

export function resolveIntrospectionEndpoint(metadata: OAuthAuthorizationServerMetadata): string {
  const endpoint = metadata.introspection_endpoint;
  if (!isUrlWithProtocol(endpoint, "https:")) {
    throw new ConfigurationError("introspectToken requires an HTTPS introspection_endpoint in authorization server metadata");
  }
  return endpoint;
}

export function isUrlWithProtocol(value: string | undefined, ...protocols: string[]): value is string {
  if (!value) return false;
  try {
    return protocols.includes(new URL(value).protocol);
  } catch {
    return false;
  }
}

async function withTransport<T>(
  operation: string,
  options: IntrospectTokenOptions,
  request: (signal: AbortSignal | undefined) => Promise<T>,
): Promise<T> {
  options.signal?.throwIfAborted();
  const signal = requestSignal(options.signal, options.timeoutMs);
  try {
    return await request(signal);
  } catch (cause) {
    if (signal?.aborted) {
      if (options.signal?.aborted && signal.reason === options.signal.reason) {
        throw signal.reason;
      }
      throw new TokenIntrospectionHTTPError(`${operation} request timed out`, undefined, signal.reason);
    }
    if (cause instanceof OAuthError) throw cause;
    if (cause instanceof HTTPError) {
      throw new TokenIntrospectionHTTPError(cause.message, cause.status, cause.cause, cause.retryAfter);
    }
    throw new TokenIntrospectionHTTPError(`${operation} request failed`, undefined, cause);
  }
}
