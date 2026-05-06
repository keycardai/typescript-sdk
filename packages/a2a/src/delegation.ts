import { TokenExchangeClient } from "@keycardai/oauth/tokenExchange";
import { ClientSecret } from "@keycardai/oauth/server/clientSecret";
import type { AgentCard } from "@a2a-js/sdk";
import type { Message } from "@a2a-js/sdk";
import { ServiceDiscovery } from "./discovery.js";
import type { AgentServiceConfig } from "./config.js";
import { getAuthServerUrl } from "./config.js";

export interface DelegationResult {
  /** The agent's response message. */
  message: Message;
  /** Resolved agent card for the target service. */
  agentCard: AgentCard;
}

export interface InvokeOptions {
  /**
   * Keycard bearer token from the current request context. Pass
   * `getKeycardAuth(requestContext)?.token` from the executor.
   * Required for all delegation flows.
   *
   * For service-to-service delegation without a user token (equivalent to
   * Python's client-credentials fallback in `DelegationClient`), first
   * acquire a service access token from Keycard, then pass it here.
   * A convenience method for this path is a planned follow-up.
   */
  subjectToken: string;
  /** Timeout in ms for the JSONRPC call. Default: 30 000. */
  timeoutMs?: number;
  /** Arbitrary metadata to attach to the A2A message. */
  metadata?: Record<string, unknown>;
}

const A2A_JSONRPC_PATH = "/a2a/jsonrpc";
const A2A_PROTOCOL_VERSION = "0.3";
const A2A_VERSION_HEADER = "x-a2a-protocol-version";

/**
 * Client for delegating tasks to remote A2A agent services with
 * Keycard token exchange.
 *
 * ```ts
 * const client = new DelegationClient(config);
 *
 * // Inside your AgentExecutor.execute():
 * const auth = getKeycardAuth(requestContext);
 * const result = await client.invokeService(targetUrl, "summarize this", {
 *   subjectToken: auth!.token,
 * });
 * eventBus.publish(result.message);
 * eventBus.finished();
 * ```
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
    const message = buildUserMessage(task, options.metadata);
    const jsonrpcUrl = buildJsonrpcUrl(serviceUrl, agentCard);
    const responseMessage = await this.#sendMessage(
      jsonrpcUrl,
      message,
      delegationToken,
      options.timeoutMs,
    );
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
    message: Message,
    bearerToken: string,
    timeoutMs = 30_000,
  ): Promise<Message> {
    const requestBody = {
      jsonrpc: "2.0",
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

    const envelope = body as { result?: { message?: Message }; error?: { message?: string } };
    if (!envelope.result?.message) {
      throw new Error(
        `DelegationClient: A2A error from "${jsonrpcUrl}": ${envelope.error?.message ?? "unknown error"}`,
      );
    }

    return envelope.result.message;
  }
}

function buildUserMessage(text: string, metadata?: Record<string, unknown>): Message {
  return {
    messageId: crypto.randomUUID(),
    role: "user",
    parts: [{ kind: "text", text }],
    ...(metadata ? { metadata } : {}),
  } as Message;
}

function buildJsonrpcUrl(serviceUrl: string, agentCard: AgentCard): string {
  // agentCard.url IS the JSONRPC endpoint per the A2A spec — use it directly.
  // Do not append A2A_JSONRPC_PATH: the agent card is built with getJsonrpcUrl()
  // which already includes /a2a/jsonrpc, so appending would double the path.
  if (agentCard.url) {
    return agentCard.url;
  }
  return `${serviceUrl.replace(/\/$/, "")}${A2A_JSONRPC_PATH}`;
}
