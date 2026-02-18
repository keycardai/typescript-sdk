import express, { RequestHandler } from "express";
import { OAuthProtectedResourceMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { InferredOAuthProtectedResourceMetadata } from "../../../shared/auth.js";
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
    const mcpVersion = req.headers['mcp-protocol-version'];

    const json: OAuthProtectedResourceMetadata = { resource, ...metadata };
    switch (mcpVersion) {
      case '2025-03-26':
        json.authorization_servers = [ baseUrl ]
        break;
    }
    res.status(200).json(json);
  });

  return router;
}

export function authorizationServerMetadataHandler(issuer: string): RequestHandler {
  const router = express.Router();

  router.use(cors());

  router.get("/", async (req, res) => {
    const resp = await fetch(issuer + '/.well-known/oauth-authorization-server');

    const json = await resp.json();

    const baseUrl = `${req.protocol}://${req.host}`

    const authorizationUrl = new URL(json.authorization_endpoint);
    authorizationUrl.searchParams.set('resource', baseUrl);

    json.authorization_endpoint = authorizationUrl.toString();

    res.status(200).json(json);
  });

  return router;
}
