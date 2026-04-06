// Pi-mono integration re-exports
// Install @keycardai/pi-mono (and its peer deps) to use these.
export {
  PiMonoClient,
  DefaultAuthToolHandler,
  ConsoleAuthToolHandler,
  createAuthRequestTool,
  convertMcpToolToAgentTool,
  convertServerTools,
  jsonSchemaToTypeBox,
  buildSystemPromptSection,
} from "@keycardai/pi-mono";

export type {
  ConnectedServer,
  PiMonoClientConfig,
  ServerAuthStatus,
  ServerState,
  AuthToolHandler,
} from "@keycardai/pi-mono";
