import { Router } from "express";
import type { RequestHandler } from "express";

export interface KeycardRouterOptions {
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
  const router = Router();

  const metadataPaths = [
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-authorization-server",
  ];

  router.get(
    "/.well-known/oauth-protected-resource",
    protectedResourceHandler(options),
  );

  router.get(
    "/.well-known/oauth-authorization-server",
    authorizationServerHandler(options.issuer, options.asMetadataTimeoutMs ?? 10_000),
  );

  if (options.publicJwks) {
    metadataPaths.push("/.well-known/jwks.json");
    router.get("/.well-known/jwks.json", jwksHandler(options.publicJwks));
  }

  // CORS preflight for the metadata endpoints. Browsers send OPTIONS before
  // cross-origin GETs that include headers such as MCP-Protocol-Version.
  router.options(metadataPaths, preflightHandler);

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

function protectedResourceHandler(options: KeycardRouterOptions): RequestHandler {
  return (req, res) => {
    const resource = `${req.protocol}://${req.host}`;
    const metadata: Record<string, unknown> = {
      resource,
      authorization_servers: [options.issuer],
    };
    if (options.resourceName) metadata.resource_name = options.resourceName;
    if (options.scopesSupported) metadata.scopes_supported = [...options.scopesSupported];
    if (options.resourceDocumentation) metadata.resource_documentation = options.resourceDocumentation;

    res.set("Access-Control-Allow-Origin", "*");
    res.status(200).json(metadata);
  };
}

function authorizationServerHandler(issuer: string, timeoutMs: number): RequestHandler {
  return async (req, res, next) => {
    try {
      const upstream = await fetch(
        `${issuer}/.well-known/oauth-authorization-server`,
        { signal: AbortSignal.timeout(timeoutMs) },
      );
      if (!upstream.ok) {
        res.status(502).json({ error: "Failed to fetch AS metadata from issuer" });
        return;
      }
      const metadata = await upstream.json() as Record<string, unknown>;

      // Rewrite authorization_endpoint to include a `resource` param pointing
      // at this server's origin so the AS knows which resource is being accessed.
      if (typeof metadata.authorization_endpoint === "string") {
        const authUrl = new URL(metadata.authorization_endpoint);
        authUrl.searchParams.set("resource", `${req.protocol}://${req.host}`);
        metadata.authorization_endpoint = authUrl.toString();
      }

      res.set("Access-Control-Allow-Origin", "*");
      res.status(200).json(metadata);
    } catch (e) {
      next(e);
    }
  };
}
