import { Router } from "express";
import type { RequestHandler } from "express";
import { requireBearerAuth } from "@keycardai/express";
import type { TokenVerifierOptions } from "@keycardai/oauth/server/tokenVerifier";
import type { AccessToken } from "@keycardai/oauth/server/accessToken";
import type {
  AgentCard,
  A2AMessage,
  A2ARequest,
  A2ASuccessResponse,
  A2AErrorResponse,
} from "./types.js";
import {
  A2A_JSONRPC_PATH,
  A2A_AGENT_CARD_PATH,
  A2A_JSONRPC_VERSION,
  A2A_ERROR_CODES,
} from "./types.js";
import type { AgentServiceConfig } from "./config.js";
import { getJsonrpcUrl } from "./config.js";

/**
 * Context injected into every executor call. Contains the verified Keycard
 * token so the executor can perform downstream delegation.
 *
 * Python equivalent: the contents of `ServerCallContext.state` set by
 * `KeycardServerCallContextBuilder`.
 */
export interface AgentExecutorContext {
  /** Verified Keycard access token for the requesting caller. */
  auth: AccessToken;
  /** Raw bearer token string, usable as a subject_token for delegation. */
  accessToken: string;
}

/**
 * Interface that customers implement to handle incoming A2A tasks.
 *
 * Python equivalent: `a2a-sdk`'s `AgentExecutor` interface. Since no
 * JS a2a-sdk exists, this is a minimal equivalent defined by Keycard.
 */
export interface AgentExecutor {
  execute(message: A2AMessage, context: AgentExecutorContext): Promise<A2AMessage>;
}

export interface AgentRouterOptions {
  /** Keycard issuer URL for bearer token validation. */
  issuer: string;
  /** Optional audience to validate. */
  audience?: string;
  /** Additional TokenVerifier options (multi-zone, required scopes, etc.). */
  verifierOptions?: Omit<TokenVerifierOptions, "issuer" | "audience">;
}

/**
 * Returns an Express Router that exposes two A2A endpoints:
 *
 * - `GET /.well-known/agent-card.json`: serves the agent card
 * - `POST /a2a/jsonrpc`: authenticated JSONRPC endpoint (requireBearerAuth
 *   is applied automatically; calls executor.execute() with the verified token)
 *
 * ```ts
 * const router = createAgentRouter(executor, config, {
 *   issuer: "https://zone.keycard.cloud",
 * });
 * app.use(router);
 * ```
 */
export function createAgentRouter(
  executor: AgentExecutor,
  config: AgentServiceConfig,
  options: AgentRouterOptions,
): Router {
  const router = Router();
  const agentCard = buildAgentCard(config);

  router.get(A2A_AGENT_CARD_PATH, agentCardHandler(agentCard));

  router.post(
    A2A_JSONRPC_PATH,
    requireBearerAuth({
      issuer: options.issuer,
      audience: options.audience,
      ...options.verifierOptions,
    }),
    jsonrpcHandler(executor),
  );

  return router;
}

function agentCardHandler(card: AgentCard): RequestHandler {
  return (_req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.status(200).json(card);
  };
}

function jsonrpcHandler(executor: AgentExecutor): RequestHandler {
  return async (req, res) => {
    const auth = (req as { auth?: AccessToken }).auth;
    if (!auth) {
      res.status(401).json(jsonrpcError(null, A2A_ERROR_CODES.UNAUTHORIZED, "Unauthorized"));
      return;
    }

    let body: unknown;
    try {
      body = typeof req.body === "object" ? req.body : JSON.parse(req.body as string);
    } catch {
      res.status(400).json(jsonrpcError(null, A2A_ERROR_CODES.PARSE_ERROR, "Parse error"));
      return;
    }

    const envelope = body as Partial<A2ARequest>;
    if (
      envelope.jsonrpc !== A2A_JSONRPC_VERSION ||
      envelope.method !== "message/send" ||
      !envelope.params?.message
    ) {
      const id = envelope.id ?? null;
      res.status(400).json(jsonrpcError(id, A2A_ERROR_CODES.INVALID_REQUEST, "Invalid request"));
      return;
    }

    try {
      const responseMessage = await executor.execute(envelope.params.message, {
        auth,
        accessToken: auth.token,
      });

      const response: A2ASuccessResponse = {
        jsonrpc: A2A_JSONRPC_VERSION,
        id: envelope.id!,
        result: { message: responseMessage },
      };
      res.status(200).json(response);
    } catch (e) {
      const errorResponse: A2AErrorResponse = {
        jsonrpc: A2A_JSONRPC_VERSION,
        id: envelope.id!,
        error: {
          code: A2A_ERROR_CODES.INTERNAL_ERROR,
          message: e instanceof Error ? e.message : "Internal error",
        },
      };
      res.status(500).json(errorResponse);
    }
  };
}

function buildAgentCard(config: AgentServiceConfig): AgentCard {
  return {
    name: config.serviceName,
    description: config.description,
    url: config.identityUrl,
    version: "1.0",
    capabilities: {
      streaming: false,
      pushNotifications: false,
      stateTransitionHistory: false,
    },
    skills: config.skills?.map((s) => ({
      id: s.id,
      name: s.name,
      description: s.description,
      tags: s.tags,
    })),
    defaultInputModes: ["text"],
    defaultOutputModes: ["text"],
  };
}

function jsonrpcError(
  id: string | null | undefined,
  code: number,
  message: string,
): A2AErrorResponse {
  return {
    jsonrpc: A2A_JSONRPC_VERSION,
    id: id ?? "null",
    error: { code, message },
  };
}

export { getJsonrpcUrl };
