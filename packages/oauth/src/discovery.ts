import { z } from "zod";
import { HTTPError, OAuthError } from "./errors.js";

const OAuthAuthorizationServerMetadataSchema = z.object({
  issuer: z.string(),
  authorization_endpoint: z.string().optional(),
  token_endpoint: z.string().optional(),
  jwks_uri: z.string().optional(),
  registration_endpoint: z.string().optional(),
  grant_types_supported: z.array(z.string()).optional(),
  response_types_supported: z.array(z.string()).optional(),
  token_endpoint_auth_methods_supported: z.array(z.string()).optional(),
}).passthrough();

export type OAuthAuthorizationServerMetadata = z.infer<typeof OAuthAuthorizationServerMetadataSchema>;

export async function fetchAuthorizationServerMetadata(
  issuer: string,
  options?: { signal?: AbortSignal },
): Promise<OAuthAuthorizationServerMetadata> {
  const issuerURL = new URL(issuer);
  let path = issuerURL.pathname;
  if (path.endsWith("/")) {
    path = path.slice(0, -1);
  }

  const url = new URL(`/.well-known/oauth-authorization-server${path}`, issuer);
  const response = await fetch(url, { signal: options?.signal });
  if (!response.ok) {
    throw new HTTPError(
      `Failed to fetch OAuth authorization server metadata for "${issuer}" (HTTP ${response.status})`,
    );
  }

  let json: unknown;
  try {
    json = await response.json();
  } catch {
    throw new OAuthError(
      "invalid_metadata",
      `Malformed JSON in OAuth authorization server metadata for "${issuer}"`,
    );
  }

  let metadata: OAuthAuthorizationServerMetadata;
  try {
    metadata = OAuthAuthorizationServerMetadataSchema.parse(json);
  } catch {
    throw new OAuthError(
      "invalid_metadata",
      `Invalid OAuth authorization server metadata for "${issuer}"`,
    );
  }

  // Compare ignoring a trailing slash, matching the Python SDK.
  if (metadata.issuer.replace(/\/$/, "") !== issuer.replace(/\/$/, "")) {
    throw new OAuthError(
      "issuer_mismatch",
      `Issuer mismatch in OAuth authorization server metadata for "${issuer}"`,
    );
  }

  return metadata;
}
