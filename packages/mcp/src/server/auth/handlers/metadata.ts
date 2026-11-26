import express, { RequestHandler } from "express";
import type { InferredOAuthProtectedResourceMetadata, OAuthProtectedResourceMetadata } from "../../../shared/auth.js";
import cors from 'cors';

export function protectedResourceMetadataHandler(
  metadata: InferredOAuthProtectedResourceMetadata,
  identifier?: string,
): RequestHandler {
  const router = express.Router();

  router.use(cors());

  router.use("/", (req, res) => {
    let resource = identifier;
    if (resource === undefined) {
      let path = req.url;
      if (path === '/' || path.indexOf('/?') === 0) {
        path = path.slice(1);
      }
      resource = `${req.protocol}://${req.host}${path}`;
    }
    const json: OAuthProtectedResourceMetadata = { resource, ...metadata };
    res.status(200).json(json);
  });

  return router;
}

/** Default timeout for the metadata request to the issuer. */
export const DEFAULT_METADATA_TIMEOUT_MS = 10_000;

export interface AuthorizationServerMetadataHandlerOptions {
  /** Timeout in milliseconds for the request to the issuer (default 10 seconds). */
  timeoutMs?: number;
  zoneIssuers?: ReadonlyMap<string, string>;
  preserveBody?: boolean;
}

export function authorizationServerMetadataHandler(
  issuer: string,
  options: AuthorizationServerMetadataHandlerOptions = {},
): RequestHandler {
  const router = express.Router();
  const timeoutMs = options.timeoutMs ?? DEFAULT_METADATA_TIMEOUT_MS;

  if (options.zoneIssuers) {
    const issuers = options.zoneIssuers;
    router.use((req, _res, next) => next(issuers.has(req.path.split("/")[1]) ? undefined : "router"));
  }
  router.use(cors());

  router.get(options.zoneIssuers ? /^\/[^/]+(?:\/|$)/ : "/", async (req, res, next) => {
    const selectedIssuer = options.zoneIssuers ? options.zoneIssuers.get(req.path.split("/")[1]) : issuer;
    if (!selectedIssuer) return next();
    let resp: Response;
    try {
      resp = await fetch(selectedIssuer + '/.well-known/oauth-authorization-server', {
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch {
      res.status(502).json({ error: "Failed to fetch AS metadata from issuer" });
      return;
    }

    if (!resp.ok) {
      res.status(502).json({ error: "Failed to fetch AS metadata from issuer" });
      return;
    }

    if (options.preserveBody) {
      res.status(200).type("json").send(Buffer.from(await resp.arrayBuffer()));
    } else {
      res.status(200).json(await resp.json());
    }
  });

  return router;
}
