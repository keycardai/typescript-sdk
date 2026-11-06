import express, { RequestHandler } from "express";
import type { InferredOAuthProtectedResourceMetadata, OAuthProtectedResourceMetadata } from "../../../shared/auth.js";
import cors from 'cors';

export function protectedResourceMetadataHandler(metadata: InferredOAuthProtectedResourceMetadata): RequestHandler {
  const router = express.Router();

  router.use(cors());

  router.use("/", (req, res) => {
    let path = req.url;
    if (path === '/' || path.indexOf('/?') === 0) {
      path = path.slice(1);
    }

    const baseUrl = `${req.protocol}://${req.host}`;
    const resource = `${baseUrl}${path}`;

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
}

export function authorizationServerMetadataHandler(
  issuer: string,
  options: AuthorizationServerMetadataHandlerOptions = {},
): RequestHandler {
  const router = express.Router();
  const timeoutMs = options.timeoutMs ?? DEFAULT_METADATA_TIMEOUT_MS;

  router.use(cors());

  router.get("/", async (_req, res) => {
    let resp: Response;
    try {
      resp = await fetch(issuer + '/.well-known/oauth-authorization-server', {
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

    const json = await resp.json() as Record<string, unknown>;

    res.status(200).json(json);
  });

  return router;
}
