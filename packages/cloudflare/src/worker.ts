import {
  CLIENT_SECRET_TYPE,
  resolveCredentialType,
} from "@keycardai/oauth/credentialDiscovery";
import { CredentialDiscoveryError } from "@keycardai/oauth/errors";
import { configureBearerIntrospection } from "@keycardai/oauth/bearerIntrospection";
import { verifyRequest, isAuthError } from "./auth.js";
import { handleMetadata } from "./metadata.js";
import { WorkersClientSecret, WorkersWebIdentity } from "./credentials.js";
import type { KeycardEnv, KeycardWorkerOptions, MetadataOptions } from "./types.js";
import { resolveResourceBinding, validateAudience, validateZoneResolver, warnLegacy } from "./resourceBinding.js";

/**
 * Creates a Cloudflare Worker `ExportedHandler` with Keycard auth built in.
 *
 * Handles the full request lifecycle:
 * 1. CORS preflight
 * 2. OAuth metadata endpoints (/.well-known/*)
 * 3. Bearer token verification
 * 4. Delegates to your authenticated handler
 *
 * Automatically detects credential type from env:
 * - `KEYCARD_PRIVATE_KEY` → WorkersWebIdentity (private_key_jwt)
 * - `KEYCARD_CLIENT_ID` + `KEYCARD_CLIENT_SECRET` → WorkersClientSecret
 */
export function createKeycardWorker<Env extends KeycardEnv = KeycardEnv>(
  options: KeycardWorkerOptions<Env>,
): ExportedHandler<Env> {
  const binding = resolveResourceBinding(options);
  validateAudience(binding, options.audiences);
  validateZoneResolver(binding, options.zoneResolver);
  const introspect = configureBearerIntrospection(options,
    (binding.mode === "perZone" || binding.mode === "shared") && binding.entries.size > 1);
  if (binding.mode === "legacy") warnLegacy("createKeycardWorker");

  // Cache the WebIdentity instance across requests (module-level is safe —
  // it only holds the private key, which is the same for all requests)
  let webIdentity: WorkersWebIdentity | undefined;

  return {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
      // CORS preflight for non-metadata paths
      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, MCP-Protocol-Version",
          },
        });
      }

      // Resolve credential type and build metadata options
      const metadataOptions = await buildMetadataOptions(env, options, () => {
        if (!webIdentity && env.KEYCARD_PRIVATE_KEY) {
          webIdentity = new WorkersWebIdentity(env.KEYCARD_PRIVATE_KEY);
        }
        return webIdentity;
      });

      // Handle metadata endpoints
      const metadataResponse = await handleMetadata(request, metadataOptions, binding, false);
      if (metadataResponse) {
        return metadataResponse;
      }

      // Verify bearer token. `KEYCARD_ISSUER` from env is the trust anchor:
      // tokens with any other `iss` are rejected before any JWKS lookup.
      const authOptions = {
        issuers: env.KEYCARD_ISSUER,
        audiences: options.audiences,
        requiredScopes: options.requiredScopes,
        zoneResolver: options.zoneResolver,
      };
      const authResult = introspect
        ? await verifyRequest(request, authOptions, binding, false, introspect)
        : await verifyRequest(request, authOptions, binding, false);

      if (isAuthError(authResult)) {
        return authResult;
      }

      // Delegate to user handler
      return options.fetch(request, env, ctx, authResult);
    },
  };
}

async function buildMetadataOptions<Env extends KeycardEnv>(
  env: Env,
  options: KeycardWorkerOptions<Env>,
  getWebIdentity: () => WorkersWebIdentity | undefined,
): Promise<MetadataOptions> {
  const metadataOptions: MetadataOptions = {
    issuer: env.KEYCARD_ISSUER,
    scopesSupported: options.scopesSupported,
    resourceName: options.resourceName,
    serviceDocumentationUrl: options.serviceDocumentationUrl,
  };

  // If using WebIdentity, serve the public JWKS
  const identity = getWebIdentity();
  if (identity) {
    metadataOptions.publicJwks = await identity.getPublicJwks();
  }

  return metadataOptions;
}

/**
 * Resolves the appropriate ApplicationCredential from env bindings.
 *
 * Useful when building an IsolateSafeTokenCache outside of createKeycardWorker.
 */
export function resolveCredential<Env extends KeycardEnv>(
  env: Env,
): WorkersClientSecret | WorkersWebIdentity {
  if (env.KEYCARD_PRIVATE_KEY) {
    return new WorkersWebIdentity(env.KEYCARD_PRIVATE_KEY, { clientId: env.KEYCARD_CLIENT_ID });
  }

  const { KEYCARD_CLIENT_ID, KEYCARD_CLIENT_SECRET } = env;
  try {
    const resolved = resolveCredentialType({ KEYCARD_CLIENT_ID, KEYCARD_CLIENT_SECRET }, { tokenFileEnvVars: [] });
    if (resolved.type === CLIENT_SECRET_TYPE) {
      return new WorkersClientSecret(resolved.clientId, resolved.clientSecret);
    }
  } catch (error) {
    if (!(error instanceof CredentialDiscoveryError)) {
      throw error;
    }
  }

  throw new Error(
    "Missing Keycard credentials in env. Set either KEYCARD_PRIVATE_KEY (WebIdentity) " +
    "or KEYCARD_CLIENT_ID + KEYCARD_CLIENT_SECRET (ClientSecret).",
  );
}
