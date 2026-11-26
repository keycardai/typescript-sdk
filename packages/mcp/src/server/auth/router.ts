import express from "express";
import type { InferredOAuthProtectedResourceMetadata } from "../../shared/auth.js";
import { protectedResourceMetadataHandler, authorizationServerMetadataHandler } from "./handlers/metadata.js";
import {
  AUTHORIZATION_SERVER_PATH, PROTECTED_RESOURCE_PATH, requestTarget, resolveResourceBinding, warnLegacy, zoneIssuers,
  type ResourceBindingOptions, type ResourceIdentifier,
} from "./resourceBinding.js";
export { keycardMetadataRouter } from "@keycardai/express";

export type InferredAuthMetadataOptions = ResourceBindingOptions & {
  oauthMetadata: { issuer: string };
  serviceDocumentationUrl?: URL;
  scopesSupported?: string[];
  resourceName?: string;
};


export function mcpAuthMetadataRouter(options: InferredAuthMetadataOptions): express.Router {
  const router = express.Router();
  const binding = resolveResourceBinding(options);
  const issuer = options.oauthMetadata?.issuer;
  const issuers = zoneIssuers(binding, issuer);

  const protectedResourceMetadata: InferredOAuthProtectedResourceMetadata = {
    authorization_servers: [issuer],

    scopes_supported: options.scopesSupported,
    resource_name: options.resourceName,
    resource_documentation: options.serviceDocumentationUrl?.href,
  };

  if (binding.mode === "legacy") {
    warnLegacy("mcpAuthMetadataRouter");
    router.use(PROTECTED_RESOURCE_PATH, protectedResourceMetadataHandler(protectedResourceMetadata));
  } else {
    const documents = new Map<string, Array<{ url: URL; send: express.RequestHandler }>>();
    const add = (identifier: ResourceIdentifier, authorization_servers: string[]) => {
      if (!identifier.metadataTarget || !identifier.metadataUrl) return;
      const entries = documents.get(identifier.metadataTarget) ?? [];
      entries.push({
        url: new URL(identifier.metadataUrl),
        send: protectedResourceMetadataHandler({ ...protectedResourceMetadata, authorization_servers }, identifier.value),
      });
      documents.set(identifier.metadataTarget, entries);
    };
    if (binding.mode === "single") add(binding.identifier, [issuer]);
    if (binding.mode === "shared") add(binding.identifier, [...issuers.values()]);
    if (binding.mode === "perZone") {
      for (const [zone, identifier] of binding.entries) {
        if (identifier.metadataTarget) add(identifier, [issuers.get(zone)!]);
      }
    }
    if (documents.size) router.use((req, res, next) => {
      if (req.method !== "GET" && req.method !== "OPTIONS") return next();
      const entries = documents.get(requestTarget(req.url));
      const host = req.headers.host?.toLowerCase().replace(/:0+(\d+)$/, ":$1");
      const entry = entries?.length === 1 ? entries[0]
        : entries?.find(({ url }) => url.host === host)
          ?? entries?.find(({ url }) => url.host === host?.replace(url.protocol === "https:" ? /:443$/ : /:80$/, ""));
      return entry ? entry.send(req, res, next) : next();
    });
  }

  if (binding.mode === "perZone" || binding.mode === "shared") {
    router.use(AUTHORIZATION_SERVER_PATH, authorizationServerMetadataHandler(issuer, { zoneIssuers: issuers, preserveBody: true }));
  } else if (issuer) {
    router.use(AUTHORIZATION_SERVER_PATH, authorizationServerMetadataHandler(issuer, { preserveBody: binding.mode !== "legacy" }));
  }

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
