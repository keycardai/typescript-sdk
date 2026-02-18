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

export async function fetchAuthorizationServerMetadata(issuer: string): Promise<OAuthAuthorizationServerMetadata> {
  const issuerURL = new URL(issuer);
  let path = issuerURL.pathname;
  if (path.endsWith("/")) {
    path = path.slice(0, -1);
  }

  const url = new URL(`/.well-known/oauth-authorization-server${path}`, issuer);
  const response = await fetch(url);
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
