import { TokenExchangeClient } from "@keycardai/oauth/tokenExchange";
import { ResponseBodyTooLargeError } from "@keycardai/oauth";
import { ClientSecret } from "@keycardai/oauth/server/clientSecret";
import type { AgentCard, Message, Task } from "@a2a-js/sdk";
import { A2A_PROTOCOL_VERSION, Role } from "@a2a-js/sdk";
import {
  ClientFactory,
  DefaultAgentCardResolver,
  JsonRpcTransportFactory,
  type Client,
} from "@a2a-js/sdk/client";
import { ServiceDiscovery } from "./discovery.js";
import { A2ADiscoveryError } from "./errors.js";
import { boundedPeerFetch, peerResponseLimit } from "./peer-response.js";
import type { AgentServiceConfig } from "./config.js";
import { getAuthServerUrl } from "./config.js";

const MAX_INVOCATION_REDIRECTS = 10;

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
  /** Maximum decoded bytes per peer reply on the default fetch (64 MiB). */
  maxPeerResponseBytes?: number;
  /** Trusted invocation origins other than the target's own. Defaults to empty. */
  trustedEndpointOrigins?: readonly string[];
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
  #fetch: typeof fetch;
  #legacyCompat: DelegationClientOptions["legacyCompat"];
  #cardResolver: DefaultAgentCardResolver;
  #trustedOrigins: ReadonlySet<string>;

  constructor(config: AgentServiceConfig, options?: DelegationClientOptions) {
    this.#config = config;
    const limit = peerResponseLimit(options?.maxPeerResponseBytes);
    this.#discovery = options?.discovery ?? new ServiceDiscovery({ maxPeerResponseBytes: limit });
    this.#tokenClient = new TokenExchangeClient(getAuthServerUrl(config), {
      credential: new ClientSecret(config.clientId, config.clientSecret),
    });
    this.#fetch = options?.fetchImpl ?? boundedPeerFetch(limit, true);
    this.#legacyCompat = options?.legacyCompat;
    this.#cardResolver = new DefaultAgentCardResolver({
      fetchImpl: this.#fetch,
      legacyCompat: this.#legacyCompat,
    });
    this.#trustedOrigins = new Set(
      (options?.trustedEndpointOrigins ?? []).map(trustedHttpOrigin),
    );
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
    const client = await this.#createClient(agentCard, serviceUrl);
    const delegationToken = await this.#getDelegationToken(serviceUrl, options.subjectToken);
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
      if (error instanceof ResponseBodyTooLargeError || error instanceof A2ADiscoveryError) throw error;
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

  async #createClient(agentCard: AgentCard, target: string): Promise<Client> {
    const targetOrigin = httpOrigin(target, "delegation target");
    const transportFactory = new JsonRpcTransportFactory({
      legacyCompat: this.#legacyCompat,
      // Redirects are followed here, one hop at a time, so each hop's origin is
      // checked before any request reaches it. A 307 or 308 to the target's
      // origin or a trusted origin is re-sent with the same method, body and
      // token; a 301, 302 or 303 is returned as is, since following it would
      // drop the JSON-RPC body.
      fetchImpl: async (input, init) => {
        let url = typeof input === "string" || input instanceof URL ? String(input) : input.url;
        for (let hops = 0; ; hops++) {
          const response = await this.#fetch(url, { ...init, redirect: "manual" });
          const location = response.headers.get("location");
          if (!location || ![301, 302, 303, 307, 308].includes(response.status)) return response;
          const redirect = new URL(location, url);
          const origin = httpOrigin(redirect.href, `redirect for target "${target}"`);
          if (origin !== targetOrigin && !this.#trustedOrigins.has(origin)) {
            void response.body?.cancel().catch(() => {});
            throw new A2ADiscoveryError(`Redirect origin ${origin} is not trusted for target "${target}"`);
          }
          if (response.status !== 307 && response.status !== 308) return response;
          if (hops >= MAX_INVOCATION_REDIRECTS) return response;
          void response.body?.cancel().catch(() => {});
          url = redirect.href;
        }
      },
    });
    const factory = new ClientFactory({
      transports: [{
        protocolName: transportFactory.protocolName,
        create: (endpoint, card) => {
          const origin = httpOrigin(endpoint, `invocation endpoint for target "${target}"`);
          if (origin !== targetOrigin && !this.#trustedOrigins.has(origin)) {
            throw new A2ADiscoveryError(`Endpoint origin ${origin} is not trusted for target "${target}"`);
          }
          return transportFactory.create(endpoint, card);
        },
      }],
      cardResolver: {
        resolve: (url, path) => this.#cardResolver.resolve(url, path),
        normalizeAgentCard: (card) => {
          const hasLegacyFields = typeof card === "object" && card !== null && (
            ("url" in card && typeof card.url === "string") ||
            ("protocolVersion" in card && typeof card.protocolVersion === "string")
          );
          const normalized = this.#cardResolver.normalizeAgentCard(card);
          return hasLegacyFields ? normalized : withConventionEndpoint(normalized, target);
        },
      },
    });
    try {
      return await factory.createFromAgentCard(agentCard);
    } catch (error) {
      if (error instanceof A2ADiscoveryError) throw error;
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

function withConventionEndpoint(card: AgentCard, target: string): AgentCard {
  if (card.supportedInterfaces?.length) return card;
  return {
    ...card,
    supportedInterfaces: [{
      url: `${target.replace(/\/+$/, "")}/a2a/jsonrpc`,
      protocolBinding: "JSONRPC",
      protocolVersion: A2A_PROTOCOL_VERSION,
      tenant: "",
    }],
  };
}

function trustedHttpOrigin(value: string): string {
  if (!/^https?:\/\/[^\s/?#@\\]+\/?$/i.test(value)) {
    throw new A2ADiscoveryError("Invalid trusted endpoint origin: expected a bare HTTP or HTTPS origin");
  }
  return httpOrigin(value, "trusted endpoint origin");
}

function httpOrigin(value: string, label: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new A2ADiscoveryError(`Invalid ${label}: expected an absolute HTTP or HTTPS URL`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new A2ADiscoveryError(`Invalid ${label}: expected an absolute HTTP or HTTPS URL`);
  }
  return `${url.protocol}//${url.hostname}:${url.port || (url.protocol === "https:" ? "443" : "80")}`;
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
