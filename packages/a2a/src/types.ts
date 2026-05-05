/**
 * A2A (Agent-to-Agent) protocol types.
 * Reference: https://google.github.io/A2A
 */

export interface AgentSkill {
  id: string;
  name: string;
  description?: string;
  tags?: readonly string[];
}

export interface AgentCapabilities {
  streaming?: boolean;
  pushNotifications?: boolean;
  stateTransitionHistory?: boolean;
}

/**
 * Agent card served at `GET /.well-known/agent-card.json`.
 * Describes the agent's identity, capabilities, and endpoint.
 */
export interface AgentCard {
  name: string;
  description?: string;
  url: string;
  version: string;
  capabilities?: AgentCapabilities;
  skills?: AgentSkill[];
  defaultInputModes?: readonly string[];
  defaultOutputModes?: readonly string[];
}

// =============================================================================
// Message types
// =============================================================================

export interface TextPart {
  type: "text";
  text: string;
}

export interface DataPart {
  type: "data";
  data: Record<string, unknown>;
}

export type Part = TextPart | DataPart;

export type MessageRole = "user" | "agent";

export interface A2AMessage {
  messageId: string;
  role: MessageRole;
  parts: readonly Part[];
  metadata?: Record<string, unknown>;
}

// =============================================================================
// JSONRPC envelope
// =============================================================================

export interface A2ARequest {
  jsonrpc: "2.0";
  id: string;
  method: "message/send";
  params: {
    message: A2AMessage;
  };
}

export interface A2ASuccessResponse {
  jsonrpc: "2.0";
  id: string;
  result: {
    message: A2AMessage;
  };
}

export interface A2AErrorResponse {
  jsonrpc: "2.0";
  id: string;
  error: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export type A2AResponse = A2ASuccessResponse | A2AErrorResponse;

export const A2A_JSONRPC_VERSION = "2.0" as const;
export const A2A_PROTOCOL_VERSION = "1.0" as const;
export const A2A_VERSION_HEADER = "x-a2a-protocol-version" as const;
export const A2A_JSONRPC_PATH = "/a2a/jsonrpc" as const;
export const A2A_AGENT_CARD_PATH = "/.well-known/agent-card.json" as const;

export const A2A_ERROR_CODES = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  UNAUTHORIZED: -32001,
} as const;
