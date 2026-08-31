import type {
  ClientCredentialsRequest,
  ImpersonateRequest,
  TokenExchangeRequest,
  TokenResponse,
} from "@keycardai/oauth";
import { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { AIMessage, type BaseMessage } from "@langchain/core/messages";
import type { ChatResult } from "@langchain/core/outputs";

/** A zone client that records every call and serves scripted responses. */
export interface RecordingZoneClient {
  exchanges: TokenExchangeRequest[];
  impersonations: ImpersonateRequest[];
  clientCredentials: (ClientCredentialsRequest | undefined)[];
  exchangeToken(request: TokenExchangeRequest): Promise<TokenResponse>;
  impersonate(request: ImpersonateRequest): Promise<TokenResponse>;
  clientCredentialsGrant(request?: ClientCredentialsRequest): Promise<TokenResponse>;
}

/**
 * A zone client for tests: no zone, no network.
 *
 * `failures` maps a resource URL to the error thrown for it, so one denied
 * resource can sit alongside a granted one in the same run.
 */
export function recordingZoneClient(
  failures: Record<string, Error> = {},
): RecordingZoneClient {
  const fail = (resource: string | undefined) => {
    const error = resource === undefined ? undefined : failures[resource];
    if (error) throw error;
  };
  return {
    exchanges: [],
    impersonations: [],
    clientCredentials: [],
    async exchangeToken(request) {
      this.exchanges.push(request);
      fail(request.resource);
      return { accessToken: `exchanged:${request.resource}`, tokenType: "Bearer" };
    },
    async impersonate(request) {
      this.impersonations.push(request);
      fail(request.resource);
      return { accessToken: `impersonated:${request.resource}`, tokenType: "Bearer" };
    },
    async clientCredentialsGrant(request) {
      this.clientCredentials.push(request);
      fail(request?.resource);
      return { accessToken: `as-self:${request?.resource}`, tokenType: "Bearer" };
    },
  };
}

/** A JWT with the given `exp`, unsigned: the expiry check never verifies one. */
export function jwtWithExp(exp: number): string {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value))
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${encode({ alg: "none" })}.${encode({ sub: "user", exp })}.signature`;
}

/**
 * A chat model that calls `toolName` once, then answers.
 *
 * Enough of a model to drive a real `createAgent` loop in tests without a
 * provider: the first turn emits a tool call, the second turn ends the run.
 */
export class FakeToolCallingModel extends BaseChatModel {
  #toolName: string;
  #args: Record<string, unknown>;
  #turn = 0;

  constructor(toolName: string, args: Record<string, unknown> = {}) {
    super({});
    this.#toolName = toolName;
    this.#args = args;
  }

  _llmType(): string {
    return "fake-tool-calling";
  }

  override bindTools(): ReturnType<NonNullable<BaseChatModel["bindTools"]>> {
    return this as unknown as ReturnType<NonNullable<BaseChatModel["bindTools"]>>;
  }

  async _generate(_messages: BaseMessage[]): Promise<ChatResult> {
    this.#turn += 1;
    const message =
      this.#turn === 1
        ? new AIMessage({
            content: "",
            tool_calls: [
              { name: this.#toolName, args: this.#args, id: "call-1", type: "tool_call" },
            ],
          })
        : new AIMessage({ content: "done" });
    return { generations: [{ text: message.text, message }] };
  }
}
