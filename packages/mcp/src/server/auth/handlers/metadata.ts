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

export function authorizationServerMetadataHandler(issuer: string): RequestHandler {
  const router = express.Router();

  router.use(cors());

  router.get("/", async (req, res) => {
    let resp: Response;
    try {
      resp = await fetch(issuer + '/.well-known/oauth-authorization-server');
    } catch {
      res.status(502).json({ error: "Failed to fetch AS metadata from issuer" });
      return;
    }

    if (!resp.ok) {
      res.status(502).json({ error: "Failed to fetch AS metadata from issuer" });
      return;
    }

    const json = await resp.json() as Record<string, unknown>;

    const baseUrl = `${req.protocol}://${req.host}`

    if (typeof json.authorization_endpoint === 'string') {
      const authorizationUrl = new URL(json.authorization_endpoint);
      authorizationUrl.searchParams.set('resource', baseUrl);
      json.authorization_endpoint = authorizationUrl.toString();
    }

    res.status(200).json(json);
  });

  return router;
}
