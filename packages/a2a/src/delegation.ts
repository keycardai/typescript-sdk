import { TokenExchangeClient } from "@keycardai/oauth/tokenExchange";
import { ClientSecret } from "@keycardai/oauth/server/clientSecret";
import type { AgentCard, A2AMessage, A2ARequest, A2ASuccessResponse } from "./types.js";
import {
  A2A_JSONRPC_VERSION,
  A2A_VERSION_HEADER,
  A2A_PROTOCOL_VERSION,
  A2A_JSONRPC_PATH,
} from "./types.js";
import { ServiceDiscovery } from "./discovery.js";
import type { AgentServiceConfig } from "./config.js";
import { getAuthServerUrl, getJsonrpcUrl } from "./config.js";

export interface DelegationResult {
  /** The agent's response message. */
  message: A2AMessage;
  /** Resolved agent card for the target service. */
  agentCard: AgentCard;
}

export interface InvokeOptions {
  /**
   * Keycard bearer token from the current request context, used as the
   * subject token for RFC 8693 delegation to the target service. In a
   * server handler this is typically `context.accessToken` from the
   * `AgentExecutorContext`.
   *
   * Required. Service-to-service flows without a user token should acquire
   * a service access token via client credentials first, then pass it here.
   */
  subjectToken: string;
  /** Timeout in ms for the JSONRPC call. Default: 30 000. */
  timeoutMs?: number;
  /** Arbitrary metadata to include in the A2A message. */
  metadata?: Record<string, unknown>;
}

/**
 * Client for delegating tasks to remote A2A agent services with
 * Keycard token exchange.
 *
 * Python equivalent: `keycardai.a2a.DelegationClient`
 */
export class DelegationClient {
  #config: AgentServiceConfig;
  #tokenClient: TokenExchangeClient;
  #discovery: ServiceDiscovery;

  constructor(config: AgentServiceConfig, options?: { discovery?: ServiceDiscovery }) {
    this.#config = config;
    this.#discovery = options?.discovery ?? new ServiceDiscovery();
    this.#tokenClient = new TokenExchangeClient(getAuthServerUrl(config), {
      credential: new ClientSecret(config.clientId, config.clientSecret),
    });
  }

  /**
   * Discover, authenticate, and invoke a remote A2A agent in one call.
   */
  async invokeService(
    serviceUrl: string,
    task: string,
    options: InvokeOptions,
  ): Promise<DelegationResult> {
    const agentCard = await this.#discovery.getServiceCard(serviceUrl);
    const delegationToken = await this.#getDelegationToken(serviceUrl, options.subjectToken);
    const message = buildUserMessage(task, options?.metadata);
    const jsonrpcUrl = buildJsonrpcUrl(serviceUrl, agentCard);
    const responseMessage = await this.#sendMessage(jsonrpcUrl, message, delegationToken, options?.timeoutMs);
    return { message: responseMessage, agentCard };
  }

  async #getDelegationToken(targetUrl: string, subjectToken: string): Promise<string> {
    const response = await this.#tokenClient.exchangeToken({
      subjectToken,
      subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
      resource: targetUrl,
    });
    return response.accessToken;
  }

  async #sendMessage(
    jsonrpcUrl: string,
    message: A2AMessage,
    bearerToken: string,
    timeoutMs = 30_000,
  ): Promise<A2AMessage> {
    const requestBody: A2ARequest = {
      jsonrpc: A2A_JSONRPC_VERSION,
      id: crypto.randomUUID(),
      method: "message/send",
      params: { message },
    };

    const response = await fetch(jsonrpcUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Authorization: `Bearer ${bearerToken}`,
        [A2A_VERSION_HEADER]: A2A_PROTOCOL_VERSION,
      },
      body: JSON.stringify(requestBody),
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!response.ok) {
      throw new Error(
        `DelegationClient: A2A request to "${jsonrpcUrl}" failed (HTTP ${response.status})`,
      );
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new Error(`DelegationClient: response from "${jsonrpcUrl}" is not valid JSON`);
    }

    const envelope = body as Partial<A2ASuccessResponse>;
    if (!envelope.result?.message) {
      const err = (body as { error?: { message?: string } }).error;
      throw new Error(
        `DelegationClient: A2A error from "${jsonrpcUrl}": ${err?.message ?? "unknown error"}`,
      );
    }

    return envelope.result.message;
  }
}

function buildUserMessage(text: string, metadata?: Record<string, unknown>): A2AMessage {
  return {
    messageId: crypto.randomUUID(),
    role: "user",
    parts: [{ type: "text", text }],
    ...(metadata ? { metadata } : {}),
  };
}

function buildJsonrpcUrl(serviceUrl: string, agentCard: AgentCard): string {
  // Prefer the agent card's own URL if it has a jsonrpc path.
  if (agentCard.url) {
    const base = agentCard.url.endsWith("/")
      ? agentCard.url.slice(0, -1)
      : agentCard.url;
    return `${base}${A2A_JSONRPC_PATH}`;
  }
  const base = serviceUrl.endsWith("/") ? serviceUrl.slice(0, -1) : serviceUrl;
  return `${base}${A2A_JSONRPC_PATH}`;
}
