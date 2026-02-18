import express from "express";
import { AuthMetadataOptions } from "@modelcontextprotocol/sdk/server/auth/router.js";
import type { InferredOAuthProtectedResourceMetadata } from "../../shared/auth.js";
import { protectedResourceMetadataHandler, authorizationServerMetadataHandler } from "./handlers/metadata.js";

export type { AuthMetadataOptions };
export type InferredAuthMetadataOptions = Omit<AuthMetadataOptions, "resourceServerUrl">;


export function mcpAuthMetadataRouter(options: InferredAuthMetadataOptions): express.Router {
  const router = express.Router();

  const protectedResourceMetadata: InferredOAuthProtectedResourceMetadata = {
    authorization_servers: [
      options.oauthMetadata.issuer
    ],

    scopes_supported: options.scopesSupported,
    resource_name: options.resourceName,
    resource_documentation: options.serviceDocumentationUrl?.href,
  };

  router.use("/.well-known/oauth-protected-resource", protectedResourceMetadataHandler(protectedResourceMetadata));

  // Always add this for backwards compatibility
  router.use("/.well-known/oauth-authorization-server", authorizationServerMetadataHandler(options.oauthMetadata.issuer));

  return router;
}

export function getOAuthProtectedResourceMetadataUrl(resourceUrl: URL): string {
  const wellKnownUrl = new URL(resourceUrl);
  let path = wellKnownUrl.pathname;
  if (path === '/') {
		path = '';
	}

  wellKnownUrl.pathname = `/.well-known/oauth-protected-resource${path}`
  return wellKnownUrl.toString();
}
