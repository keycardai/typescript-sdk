import { Router } from "express";
import type { RequestHandler } from "express";
import { getRequestOrigin } from "./host.js";
import {
  AUTHORIZATION_SERVER_PATH, PROTECTED_RESOURCE_PATH, requestTarget, resolveResourceBinding, warnLegacy, zoneIssuers,
  type ResourceBindingOptions, type ResourceIdentifier,
} from "./resourceBinding.js";

export interface KeycardRouterOptions extends ResourceBindingOptions {
  /**
   * Keycard issuer URL, e.g. "https://zone-id.keycard.cloud".
   * Used to proxy AS metadata from the Keycard authorization server.
   */
  issuer: string;
  /**
   * Human-readable resource name shown in AS metadata.
   */
  resourceName?: string;
  /**
   * Scopes this resource server supports.
   */
  scopesSupported?: readonly string[];
  /**
   * Link to documentation for this resource.
   */
  resourceDocumentation?: string;
  /**
   * Timeout in milliseconds for the upstream AS metadata fetch.
   * Default: 10 000 ms.
   */
  asMetadataTimeoutMs?: number;
  /**
   * Public JWKS to serve at `GET /.well-known/jwks.json`.
   * When omitted, no JWKS route is registered.
   */
  publicJwks?: { keys: Record<string, unknown>[] };
}

const CORS_ALLOW_METHODS = "GET, OPTIONS";
const CORS_ALLOW_HEADERS = "Content-Type, MCP-Protocol-Version";

/**
 * Returns an Express Router that serves the two OAuth discovery endpoints
 * required by RFC 9728 and RFC 8414:
 *
 * - `GET /.well-known/oauth-protected-resource` (RFC 9728 §2)
 * - `GET /.well-known/oauth-authorization-server` (RFC 8414 §3, proxied)
 *
 * Mount it at the application root:
 * ```ts
 * import express from "express";
 * import { keycardMetadataRouter } from "@keycardai/express";
 *
 * const app = express();
 * app.use(keycardMetadataRouter({ issuer: "https://zone.keycard.cloud" }));
 * ```
 *
 * These paths must remain publicly accessible (no bearer auth) per their
 * respective specs. Per the security guidance in
 * `@keycardai/starlette` and the feedback_specific_path_bypass rule:
 * only bypass auth for these exact paths, never a broad `/.well-known/` prefix.
 */
export function keycardMetadataRouter(options: KeycardRouterOptions): Router {
  return metadataRouter(options);
}

export function metadataRouter(
  options: KeycardRouterOptions,
  binding = resolveResourceBinding(options),
  warn = true,
): Router {
  const router = Router();
  const issuers = zoneIssuers(binding, options.issuer);
  if (binding.mode === "legacy" && warn) warnLegacy("keycardMetadataRouter");
  const timeout = options.asMetadataTimeoutMs ?? 10_000;
  const documents = new Map<string, Array<{ identifier: ResourceIdentifier; url: URL; issuers: string[] }>>();
  const addDocument = (identifier: ResourceIdentifier, authorizationServers: string[]) => {
    if (!identifier.metadataTarget || !identifier.metadataUrl) return;
    const entries = documents.get(identifier.metadataTarget) ?? [];
    entries.push({ identifier, url: new URL(identifier.metadataUrl), issuers: authorizationServers });
    documents.set(identifier.metadataTarget, entries);
  };

  if (binding.mode === "legacy") {
    router.get(PROTECTED_RESOURCE_PATH, protectedResourceHandler(options));
    router.options(PROTECTED_RESOURCE_PATH, preflightHandler);
  } else if (binding.mode === "single") {
    addDocument(binding.identifier, [options.issuer]);
  } else if (binding.mode === "perZone") {
    for (const [zone, identifier] of binding.entries) {
      if (identifier.metadataTarget) addDocument(identifier, [issuers.get(zone)!]);
    }
  } else if (binding.mode === "shared") {
    addDocument(binding.identifier, [...issuers.values()]);
  }

  if (documents.size) {
    const findDocument: RequestHandler = (req, res, next) => {
      const entries = documents.get(requestTarget(req.url));
      const host = req.headers.host?.toLowerCase().replace(/:0+(\d+)$/, ":$1");
      const entry = entries?.length === 1 ? entries[0]
        : entries?.find(({ url }) => url.host === host)
          ?? entries?.find(({ url }) => url.host === host?.replace(url.protocol === "https:" ? /:443$/ : /:80$/, ""));
      if (!entry) return next();
      if (req.method === "OPTIONS") return preflightHandler(req, res, next);
      return protectedResourceHandler(options, entry.identifier.value, entry.issuers)(req, res, next);
    };
    router.get(/^\/\.well-known\/oauth-protected-resource(?:\/|$)/, findDocument);
    router.options(/^\/\.well-known\/oauth-protected-resource(?:\/|$)/, findDocument);
  }

  if (binding.mode === "perZone" || binding.mode === "shared") {
    const proxy: RequestHandler = (req, res, next) => {
      const zone = req.path.slice(AUTHORIZATION_SERVER_PATH.length + 1).split("/")[0];
      const issuer = issuers.get(zone);
      if (!issuer) return next();
      if (req.method === "OPTIONS") return preflightHandler(req, res, next);
      return authorizationServerHandler(issuer, timeout)(req, res, next);
    };
    router.get(/^\/\.well-known\/oauth-authorization-server\//, proxy);
    router.options(/^\/\.well-known\/oauth-authorization-server\//, proxy);
  } else if (options.issuer) {
    router.get(AUTHORIZATION_SERVER_PATH, authorizationServerHandler(options.issuer, timeout, binding.mode === "legacy"));
    router.options(AUTHORIZATION_SERVER_PATH, preflightHandler);
  }
  if (options.publicJwks) {
    router.get("/.well-known/jwks.json", jwksHandler(options.publicJwks));
    router.options("/.well-known/jwks.json", preflightHandler);
  }

  return router;
}

const preflightHandler: RequestHandler = (_req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", CORS_ALLOW_METHODS);
  res.set("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS);
  res.status(204).end();
};

function jwksHandler(publicJwks: { keys: Record<string, unknown>[] }): RequestHandler {
  return (_req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.status(200).json(publicJwks);
  };
}

function protectedResourceHandler(
  options: KeycardRouterOptions,
  identifier?: string,
  issuers = [options.issuer],
): RequestHandler {
  return (req, res) => {
    const resource = identifier ?? getRequestOrigin(req);
    const metadata: Record<string, unknown> = {
      resource,
      authorization_servers: issuers,
    };
    if (options.resourceName) metadata.resource_name = options.resourceName;
    if (options.scopesSupported) metadata.scopes_supported = [...options.scopesSupported];
    if (options.resourceDocumentation) metadata.resource_documentation = options.resourceDocumentation;

    res.set("Access-Control-Allow-Origin", "*");
    res.status(200).json(metadata);
  };
}

function authorizationServerHandler(issuer: string, timeoutMs: number, legacy = false): RequestHandler {
  return async (_req, res, next) => {
    let upstream: Response;
    try {
      upstream = await fetch(
        `${issuer}/.well-known/oauth-authorization-server`,
        { signal: AbortSignal.timeout(timeoutMs) },
      );
    } catch (error) {
      if (legacy) return next(error);
      res.status(502).json({ error: "Failed to fetch AS metadata from issuer" });
      return;
    }
    if (!upstream.ok) {
      res.status(502).json({ error: "Failed to fetch AS metadata from issuer" });
      return;
    }
    try {
      res.set("Access-Control-Allow-Origin", "*");
      if (legacy) {
        res.status(200).json(await upstream.json());
      } else {
        res.status(200).type("json").send(Buffer.from(await upstream.arrayBuffer()));
      }
    } catch (e) {
      next(e);
    }
  };
}
