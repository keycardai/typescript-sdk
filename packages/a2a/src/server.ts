import {
  DefaultRequestHandler,
  InMemoryTaskStore,
  type AgentExecutor,
  type TaskStore,
} from "@a2a-js/sdk/server";
import { A2A_PROTOCOL_VERSION, type AgentCard, type AgentInterface } from "@a2a-js/sdk";
import { A2A_LEGACY_PROTOCOL_VERSION } from "@a2a-js/sdk/compat/v0_3";
import type { AgentServiceConfig } from "./config.js";
import { getJsonrpcUrl } from "./config.js";

export type { AgentExecutor, RequestContext, ExecutionEventBus } from "@a2a-js/sdk/server";
export { InMemoryTaskStore } from "@a2a-js/sdk/server";

/**
 * Creates a `DefaultRequestHandler` from `@a2a-js/sdk` pre-wired with a
 * `KeycardUser`-aware agent card and the provided executor.
 *
 * Pass the returned handler to the SDK's Express adapters alongside a
 * `keycardUserBuilder` for auth:
 *
 * ```ts
 * const requestHandler = createKeycardRequestHandler(executor, config, agentCard);
 * const userBuilder = keycardUserBuilder({ issuer: "https://zone.keycard.cloud" });
 *
 * app.get("/.well-known/agent-card.json", agentCardHandler({ agentCardProvider: requestHandler }));
 * app.post("/a2a/jsonrpc", jsonRpcHandler({ requestHandler, userBuilder }));
 * ```
 *
 * Python equivalent: the composition of `create_agent_card_server`,
 * `serve_agent`, and the `KeycardServerCallContextBuilder` from `keycardai-a2a`.
 */
export function createKeycardRequestHandler(
  executor: AgentExecutor,
  agentCard: AgentCard,
  options?: { taskStore?: TaskStore },
): DefaultRequestHandler {
  return new DefaultRequestHandler(
    agentCard,
    options?.taskStore ?? new InMemoryTaskStore(),
    executor,
  );
}

/**
 * Build an `AgentCard` from an `AgentServiceConfig` for use with
 * `createKeycardRequestHandler`.
 *
 * The card advertises a single A2A 1.0 JSON-RPC interface at the service's
 * `/a2a/jsonrpc` endpoint, declares a `bearer` HTTP security scheme
 * (Keycard-issued JWT) and requires it for all interactions via
 * `securityRequirements`, matching the auth enforced by `requireBearerAuth`
 * and `keycardUserBuilder`.
 *
 * With `legacyCompat.enabled` the card additionally advertises the same
 * endpoint as a 0.3 interface, which is what `@a2a-js/sdk`'s Express
 * `jsonRpcHandler({ legacyCompat: { enabled: true } })` requires before it
 * will accept 0.3 envelopes (`message/send`) from old agents.
 */
export function buildAgentCard(
  config: AgentServiceConfig,
  options?: { legacyCompat?: { enabled: boolean } },
): AgentCard {
  const jsonrpcUrl = getJsonrpcUrl(config);
  const supportedInterfaces: AgentInterface[] = [
    {
      url: jsonrpcUrl,
      protocolBinding: "JSONRPC",
      protocolVersion: A2A_PROTOCOL_VERSION,
      tenant: "",
    },
  ];
  if (options?.legacyCompat?.enabled) {
    supportedInterfaces.push({
      url: jsonrpcUrl,
      protocolBinding: "JSONRPC",
      protocolVersion: A2A_LEGACY_PROTOCOL_VERSION,
      tenant: "",
    });
  }
  return {
    name: config.serviceName,
    description: config.description ?? "",
    supportedInterfaces,
    provider: undefined,
    version: "0.1",
    signatures: [],
    capabilities: { extensions: [] },
    securitySchemes: {
      bearer: {
        scheme: {
          $case: "httpAuthSecurityScheme",
          value: {
            scheme: "bearer",
            bearerFormat: "JWT",
            description: "Keycard-issued JWT access token",
          },
        },
      },
    },
    securityRequirements: [{ schemes: { bearer: { list: [] } } }],
    defaultInputModes: ["text/plain"],
    defaultOutputModes: ["text/plain"],
    skills:
      config.skills?.map((s) => ({
        id: s.id,
        name: s.name,
        description: s.description,
        tags: s.tags ?? [],
        examples: [],
        inputModes: [],
        outputModes: [],
        securityRequirements: [],
      })) ?? [],
  };
}
