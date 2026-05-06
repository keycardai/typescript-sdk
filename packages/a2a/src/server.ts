import {
  DefaultRequestHandler,
  InMemoryTaskStore,
  type AgentExecutor,
  type TaskStore,
} from "@a2a-js/sdk/server";
import type { AgentCard } from "@a2a-js/sdk";
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
 */
export function buildAgentCard(config: AgentServiceConfig): AgentCard {
  return {
    name: config.serviceName,
    description: config.description ?? "",
    url: getJsonrpcUrl(config),
    version: "0.1",
    protocolVersion: "0.3",
    capabilities: {},
    defaultInputModes: ["text/plain"],
    defaultOutputModes: ["text/plain"],
    skills: config.skills?.map((s) => ({
      id: s.id,
      name: s.name,
      description: s.description,
      tags: s.tags ?? [],
    })) ?? [],
  };
}
