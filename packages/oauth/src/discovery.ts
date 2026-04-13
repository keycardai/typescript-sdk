import { z } from "zod";

const OAuthAuthorizationServerMetadataSchema = z.object({
  issuer: z.string(),
  authorization_endpoint: z.string().optional(),
  token_endpoint: z.string().optional(),
  jwks_uri: z.string().optional(),
  registration_endpoint: z.string().optional(),
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
    throw new Error(
      `Failed to fetch OAuth authorization server metadata for "${issuer}"`,
    );
  }

  const json = await response.json();
  const metadata = OAuthAuthorizationServerMetadataSchema.parse(json);
  if (metadata.issuer !== issuer) {
    throw new Error(`Issuer mismatch in OAuth authorization server metadata for "${issuer}"`);
  }

  return metadata;
}

// RFC 9728 - OAuth 2.0 Protected Resource Metadata
const OAuthProtectedResourceMetadataSchema = z.object({
  resource: z.string(),
  authorization_servers: z.array(z.string()).optional(),
  jwks_uri: z.string().optional(),
  scopes_supported: z.array(z.string()).optional(),
  bearer_methods_supported: z.array(z.string()).optional(),
  resource_signing_alg_values_supported: z.array(z.string()).optional(),
  resource_name: z.string().optional(),
  resource_documentation: z.string().optional(),
  resource_policy_uri: z.string().optional(),
  resource_tos_uri: z.string().optional(),
  tls_client_certificate_bound_access_tokens: z.boolean().optional(),
  authorization_details_types_supported: z.array(z.string()).optional(),
  dpop_signing_alg_values_supported: z.array(z.string()).optional(),
  dpop_bound_access_tokens_required: z.boolean().optional(),
  signed_metadata: z.string().optional(),
}).passthrough();

export type OAuthProtectedResourceMetadata = z.infer<typeof OAuthProtectedResourceMetadataSchema>;

/**
 * Fetch OAuth 2.0 Protected Resource Metadata as defined in RFC 9728.
 *
 * @param url - The `resource_metadata` URL from the WWW-Authenticate challenge.
 * @returns The parsed protected resource metadata document.
 */
export async function fetchProtectedResourceMetadata(
  resource: string,
  options?: { signal?: AbortSignal },
): Promise<OAuthProtectedResourceMetadata> {
  const resourceURL = new URL(resource);
  let path = resourceURL.pathname;
  if (path.endsWith("/")) {
    path = path.slice(0, -1);
  }

  const url = new URL(`/.well-known/oauth-protected-resource${path}`, resource);
  const response = await fetch(url, { signal: options?.signal });
  if (!response.ok) {
    throw new Error(
      `Failed to fetch OAuth protected resource metadata for "${resource}"`,
    );
  }

  const json = await response.json();
  const metadata = OAuthProtectedResourceMetadataSchema.parse(json);
  if (metadata.resource !== resource) {
    throw new Error(`Resource mismatch in OAuth protected resource metadata for "${resource}"`);
  }

  return metadata;
}
