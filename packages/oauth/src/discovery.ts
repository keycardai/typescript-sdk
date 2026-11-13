import { requestSignal } from "./requestSignal.js";
import { z } from "zod";
import { HTTPError, OAuthError } from "./errors.js";

const OAuthAuthorizationServerMetadataSchema = z.looseObject({
  issuer: z.string(),
  authorization_endpoint: z.string().optional(),
  token_endpoint: z.string().optional(),
  jwks_uri: z.string().optional(),
  registration_endpoint: z.string().optional(),
  grant_types_supported: z.array(z.string()).optional(),
  response_types_supported: z.array(z.string()).optional(),
  token_endpoint_auth_methods_supported: z.array(z.string()).optional(),
  code_challenge_methods_supported: z.array(z.string()).optional(),
  scopes_supported: z.array(z.string()).optional(),
  // RFC 8628 §4
  device_authorization_endpoint: z.string().optional(),
  // OpenID Connect Discovery 1.0 §3
  userinfo_endpoint: z.string().optional(),
  end_session_endpoint: z.string().optional(),
  subject_types_supported: z.array(z.string()).optional(),
  id_token_signing_alg_values_supported: z.array(z.string()).optional(),
  claims_supported: z.array(z.string()).optional(),
});

export type OAuthAuthorizationServerMetadata = z.infer<typeof OAuthAuthorizationServerMetadataSchema>;

export async function fetchAuthorizationServerMetadata(
  issuer: string,
  options?: { signal?: AbortSignal; timeoutMs?: number },
): Promise<OAuthAuthorizationServerMetadata> {
  const issuerURL = new URL(issuer);
  let path = issuerURL.pathname;
  if (path.endsWith("/")) {
    path = path.slice(0, -1);
  }

  const url = new URL(`/.well-known/oauth-authorization-server${path}`, issuer);
  const response = await fetch(url, { signal: requestSignal(options?.signal, options?.timeoutMs) });
  if (!response.ok) {
    throw new HTTPError(
      `Failed to fetch OAuth authorization server metadata for "${issuer}" (HTTP ${response.status})`,
      response.status,
    );
  }

  // A failure to read the body, such as a timeout, is thrown as is.
  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new OAuthError(
      "invalid_response",
      `Malformed JSON in OAuth authorization server metadata for "${issuer}"`,
    );
  }

  let metadata: OAuthAuthorizationServerMetadata;
  try {
    metadata = OAuthAuthorizationServerMetadataSchema.parse(json);
  } catch {
    throw new OAuthError(
      "invalid_response",
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
