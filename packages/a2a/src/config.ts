import type { AgentSkill } from "@a2a-js/sdk";

export type { AgentSkill } from "@a2a-js/sdk";

/**
 * Configuration for a Keycard-protected A2A agent service.
 *
 * Python equivalent: `keycardai.a2a.AgentServiceConfig`
 */
export interface AgentServiceConfig {
  /** Human-readable service name, used as the agent card `name`. */
  serviceName: string;
  /** Keycard client ID for service-to-service token exchange. */
  clientId: string;
  /** Keycard client secret. */
  clientSecret: string;
  /**
   * Public URL of this agent service, e.g. "https://my-agent.example.com".
   * Used to construct the JSONRPC endpoint URL.
   */
  identityUrl: string;
  /** Keycard zone ID, e.g. "abc1234". Constructs the auth server URL. */
  zoneId?: string;
  /**
   * Explicit authorization server URL. Defaults to
   * `https://{zoneId}.keycard.cloud` when `zoneId` is provided.
   */
  authorizationServerUrl?: string;
  /** Description for the agent card. */
  description?: string;
  /** Skills advertised in the agent card. */
  skills?: readonly AgentSkill[];
}

export function getAgentCardUrl(config: AgentServiceConfig): string {
  return `${config.identityUrl}/.well-known/agent-card.json`;
}

export function getJsonrpcUrl(config: AgentServiceConfig): string {
  return `${config.identityUrl}/a2a/jsonrpc`;
}

export function getAuthServerUrl(config: AgentServiceConfig): string {
  if (config.authorizationServerUrl) return config.authorizationServerUrl;
  if (config.zoneId) return `https://${config.zoneId}.keycard.cloud`;
  throw new Error(
    "AgentServiceConfig: either `authorizationServerUrl` or `zoneId` is required",
  );
}
