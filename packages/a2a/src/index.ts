// Keycard auth adapter for @a2a-js/sdk
export { KeycardUser, keycardUserBuilder, getKeycardAuth } from "./auth.js";
export type { KeycardUserBuilderOptions } from "./auth.js";

// Server convenience helpers (thin wrappers over @a2a-js/sdk)
export { createKeycardRequestHandler, buildAgentCard } from "./server.js";
export type { AgentExecutor, RequestContext, ExecutionEventBus } from "./server.js";
export { InMemoryTaskStore } from "./server.js";

// Config
export type { AgentServiceConfig } from "./config.js";
export { getAgentCardUrl, getJsonrpcUrl, getAuthServerUrl } from "./config.js";

// Discovery
export { ServiceDiscovery } from "./discovery.js";

// Delegation client
export { DelegationClient } from "./delegation.js";
export type { DelegationResult, InvokeOptions } from "./delegation.js";

// Re-export the SDK's Express handlers and UserBuilder so customers
// import from one place.
export {
  agentCardHandler,
  jsonRpcHandler,
  restHandler,
  UserBuilder,
} from "@a2a-js/sdk/server/express";

// Re-export core SDK types customers need for executor implementations.
export type { AgentCard, Message, Task } from "@a2a-js/sdk";
export { DefaultRequestHandler } from "@a2a-js/sdk/server";
