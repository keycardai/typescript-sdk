import { TokenExchangeClient } from "@keycardai/oauth/tokenExchange";
import { ClientSecret } from "@keycardai/oauth/server/clientSecret";
import type { AgentCard, Message, Task } from "@a2a-js/sdk";
import { Role } from "@a2a-js/sdk";
import {
  ClientFactory,
  DefaultAgentCardResolver,
  JsonRpcTransportFactory,
  type Client,
} from "@a2a-js/sdk/client";
import { ServiceDiscovery } from "./discovery.js";
import type { AgentServiceConfig } from "./config.js";
import { getAuthServerUrl } from "./config.js";

export interface DelegationResult {
  /**
   * The agent's direct response, when it answered with a message. A2A 1.0
   * agents may instead answer with a task (see `task`); exactly one of the
   * two is set.
   */
  message?: Message;
  /** The task the agent created or updated, when it did not answer inline. */
  task?: Task;
  /** Resolved agent card for the target service, as discovered. */
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

export interface DelegationClientOptions {
  /** Agent-card discovery to use. Default: a fresh `ServiceDiscovery`. */
  discovery?: ServiceDiscovery;
  /**
   * Opt into `@a2a-js/sdk`'s v0.3 compatibility layer. When enabled, a
   * target whose agent card advertises a protocol version below 1.0 (or a
   * 0.3-shaped card without `supportedInterfaces`) is called with the 0.3
   * wire format (`message/send`, `kind`-tagged parts). Targets advertising
   * 1.0 are unaffected. Default: disabled; only A2A 1.0 agents are reachable.
   */
  legacyCompat?: { enabled: boolean };
  /** `fetch` implementation for the JSON-RPC transport. Default: global `fetch`. */
  fetchImpl?: typeof fetch;
}

/**
 * Client for delegating tasks to remote A2A agent services with
 * Keycard token exchange.
 *
 * Requests go through `@a2a-js/sdk`'s typed client, so the JSON-RPC method
 * names, the `A2A-Version` header and the request envelope follow the A2A
 * 1.0 generation the dependency implements.
 *
 * ```ts
 * const client = new DelegationClient(config);
 *
 * // Inside your AgentExecutor.execute():
 * const auth = getKeycardAuth(requestContext);
 * const result = await client.invokeService(targetUrl, "summarize this", {
 *   subjectToken: auth!.token,
 * });
 * if (result.message) eventBus.publish({ kind: "message", data: result.message });
 * eventBus.finished();
 * ```
 *
 * Python equivalent: `keycardai.a2a.DelegationClient`
 */
export class DelegationClient {
  #config: AgentServiceConfig;
  #tokenClient: TokenExchangeClient;
  #discovery: ServiceDiscovery;
  #clientFactory: ClientFactory;

  constructor(config: AgentServiceConfig, options?: DelegationClientOptions) {
    this.#config = config;
    this.#discovery = options?.discovery ?? new ServiceDiscovery();
    this.#tokenClient = new TokenExchangeClient(getAuthServerUrl(config), {
      credential: new ClientSecret(config.clientId, config.clientSecret),
    });
    const transportOptions = {
      fetchImpl: options?.fetchImpl,
      legacyCompat: options?.legacyCompat,
    };
    this.#clientFactory = new ClientFactory({
      transports: [new JsonRpcTransportFactory(transportOptions)],
      cardResolver: new DefaultAgentCardResolver(transportOptions),
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
    const client = await this.#createClient(agentCard);
    const message = buildUserMessage(task, options.metadata);

    let result: Message | Task;
    try {
      result = await client.sendMessage(
        { tenant: "", message, configuration: undefined, metadata: undefined },
        {
          serviceParameters: { Authorization: `Bearer ${delegationToken}` },
          signal: AbortSignal.timeout(options.timeoutMs ?? 30_000),
        },
      );
    } catch (error) {
      throw new Error(
        `DelegationClient: A2A request to "${serviceUrl}" failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }

    return isMessage(result)
      ? { message: result, agentCard }
      : { task: result, agentCard };
  }

  async #createClient(agentCard: AgentCard): Promise<Client> {
    try {
      return await this.#clientFactory.createFromAgentCard(agentCard);
    } catch (error) {
      throw new Error(
        `DelegationClient: agent card for "${agentCard.name}" exposes no usable JSON-RPC interface: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  async #getDelegationToken(targetUrl: string, subjectToken: string): Promise<string> {
    const response = await this.#tokenClient.exchangeToken({
      subjectToken,
      subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
      resource: targetUrl,
    });
    return response.accessToken;
  }
}

function isMessage(result: Message | Task): result is Message {
  return "messageId" in result;
}

function buildUserMessage(text: string, metadata?: Record<string, unknown>): Message {
  return {
    messageId: crypto.randomUUID(),
    contextId: "",
    taskId: "",
    role: Role.ROLE_USER,
    parts: [
      {
        content: { $case: "text", value: text },
        metadata: undefined,
        filename: "",
        mediaType: "",
      },
    ],
    metadata,
    extensions: [],
    referenceTaskIds: [],
  };
}
