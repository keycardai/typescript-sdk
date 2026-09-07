import { jest } from '@jest/globals';
import { DelegationClient } from './delegation.js';
import { buildAgentCard } from './server.js';
import { ServiceDiscovery } from './discovery.js';
import type { AgentCard } from '@a2a-js/sdk';

const CONFIG = {
  serviceName: 'Caller Agent',
  clientId: 'client-id',
  clientSecret: 'secret',
  identityUrl: 'https://caller.example.com',
  zoneId: 'zone-abc',
};

const TARGET_URL = 'https://agent.example.com';
const TARGET_JSONRPC_URL = `${TARGET_URL}/a2a/jsonrpc`;

// The agent card a 1.0-generation Keycard agent serves, as it appears on the
// wire (the JSON form of buildAgentCard for the target service).
const TARGET_CARD_JSON = {
  name: 'Target Agent',
  description: 'A 1.0 agent',
  version: '0.1',
  supportedInterfaces: [
    { url: TARGET_JSONRPC_URL, protocolBinding: 'JSONRPC', protocolVersion: '1.0' },
  ],
  capabilities: {},
  securitySchemes: {
    bearer: { httpAuthSecurityScheme: { scheme: 'bearer', bearerFormat: 'JWT' } },
  },
  securityRequirements: [{ schemes: { bearer: {} } }],
  defaultInputModes: ['text/plain'],
  defaultOutputModes: ['text/plain'],
  skills: [],
};

// The same agent, as a 0.3-generation card (what @keycardai/a2a 0.3.x served).
const LEGACY_TARGET_CARD_JSON = {
  name: 'Legacy Agent',
  description: 'A 0.3 agent',
  url: TARGET_JSONRPC_URL,
  version: '0.1',
  protocolVersion: '0.3',
  capabilities: {},
  securitySchemes: {
    bearer: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
  },
  security: [{ bearer: [] }],
  defaultInputModes: ['text/plain'],
  defaultOutputModes: ['text/plain'],
  skills: [],
};

// Recorded from a keycardai-a2a (Python, a2a-sdk 1.x) agent answering
// SendMessage with an inline message.
const RECORDED_1_0_MESSAGE_RESPONSE = {
  jsonrpc: '2.0',
  id: 0,
  result: {
    message: {
      messageId: 'resp-1',
      contextId: 'ctx-1',
      taskId: '',
      role: 'ROLE_AGENT',
      parts: [{ text: 'echo: ping' }],
    },
  },
};

// Recorded from the same agent when the executor produced a task.
const RECORDED_1_0_TASK_RESPONSE = {
  jsonrpc: '2.0',
  id: 0,
  result: {
    task: {
      id: 'task-1',
      contextId: 'ctx-1',
      status: {
        state: 'TASK_STATE_COMPLETED',
        message: {
          messageId: 'resp-2',
          role: 'ROLE_AGENT',
          parts: [{ text: 'done' }],
        },
      },
      artifacts: [],
      history: [],
    },
  },
};

interface Recorded {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function headersOf(init?: RequestInit): Record<string, string> {
  const out: Record<string, string> = {};
  new Headers(init?.headers).forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

/**
 * Hermetic transport: routes the agent-card fetch, the OAuth metadata and
 * token-exchange calls, and the A2A JSON-RPC call, recording the latter.
 */
function makeHarness(opts: {
  card?: unknown;
  rpcResponse?: unknown;
  rpcStatus?: number;
} = {}) {
  const rpcCalls: Recorded[] = [];
  const fetchMock = jest.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (url === `${TARGET_URL}/.well-known/agent-card.json`) {
      return jsonResponse(opts.card ?? TARGET_CARD_JSON);
    }
    if (url === 'https://zone-abc.keycard.cloud/.well-known/oauth-authorization-server') {
      return jsonResponse({
        issuer: 'https://zone-abc.keycard.cloud',
        token_endpoint: 'https://zone-abc.keycard.cloud/token',
      });
    }
    if (url === 'https://zone-abc.keycard.cloud/token') {
      return jsonResponse({
        access_token: 'delegated-token',
        token_type: 'Bearer',
        issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      });
    }
    if (url === TARGET_JSONRPC_URL) {
      const body = JSON.parse(String(init?.body));
      rpcCalls.push({ url, method: init?.method ?? 'GET', headers: headersOf(init), body });
      const response = { ...(opts.rpcResponse ?? RECORDED_1_0_MESSAGE_RESPONSE), id: body.id };
      return jsonResponse(response, opts.rpcStatus ?? 200);
    }
    throw new Error(`unexpected fetch: ${url}`);
  });
  return { fetch: fetchMock as unknown as typeof fetch, rpcCalls };
}

let originalFetch: typeof fetch;
beforeEach(() => {
  originalFetch = globalThis.fetch;
});
afterEach(() => {
  globalThis.fetch = originalFetch;
});

function makeClient(harness: ReturnType<typeof makeHarness>, extra: { legacyCompat?: { enabled: boolean } } = {}) {
  // ServiceDiscovery and TokenExchangeClient use the global fetch; the A2A
  // transport receives the same mock via fetchImpl.
  globalThis.fetch = harness.fetch;
  return new DelegationClient(CONFIG, {
    discovery: new ServiceDiscovery(),
    fetchImpl: harness.fetch,
    ...extra,
  });
}

describe('DelegationClient wire shape (A2A 1.0)', () => {
  it('sends SendMessage with an A2A-Version: 1.0 header and the delegated bearer token', async () => {
    const harness = makeHarness();
    const client = makeClient(harness);

    await client.invokeService(TARGET_URL, 'ping', { subjectToken: 'user-token' });

    expect(harness.rpcCalls).toHaveLength(1);
    const call = harness.rpcCalls[0];
    expect(call.url).toBe(TARGET_JSONRPC_URL);
    expect(call.method).toBe('POST');
    expect(call.headers['a2a-version']).toBe('1.0');
    expect(call.headers['authorization']).toBe('Bearer delegated-token');
    expect(call.headers['content-type']).toBe('application/json');
    expect(call.headers['x-a2a-protocol-version']).toBeUndefined();

    const body = call.body as { jsonrpc: string; method: string; id: unknown; params: any };
    expect(body.jsonrpc).toBe('2.0');
    expect(body.method).toBe('SendMessage');
    expect(body.id).toBeDefined();
  });

  it('encodes the message in the 1.0 envelope: ROLE_USER, text parts, no kind tags', async () => {
    const harness = makeHarness();
    const client = makeClient(harness);

    await client.invokeService(TARGET_URL, 'ping', {
      subjectToken: 'user-token',
      metadata: { traceId: 'abc' },
    });

    const params = (harness.rpcCalls[0].body as any).params;
    expect(Object.keys(params).sort()).toEqual(['configuration', 'message']);
    expect(params.message.role).toBe('ROLE_USER');
    expect(typeof params.message.messageId).toBe('string');
    expect(params.message.parts).toEqual([{ text: 'ping' }]);
    expect(params.message.metadata).toEqual({ traceId: 'abc' });
    // Blocking send: the typed client emits an empty configuration (proto
    // defaults, returnImmediately false, are omitted on the wire).
    expect(params.configuration).toEqual({});
    // 0.3-generation fields must not leak into a 1.0 envelope.
    expect(params.message).not.toHaveProperty('kind');
    expect(params.message.parts[0]).not.toHaveProperty('kind');
  });

  it('never sends the 0.3 method name message/send to a 1.0 agent (regression: -32601 from Python agents)', async () => {
    const harness = makeHarness();
    const client = makeClient(harness);

    await client.invokeService(TARGET_URL, 'ping', { subjectToken: 'user-token' });

    const methods = harness.rpcCalls.map((c) => (c.body as { method: string }).method);
    expect(methods).not.toContain('message/send');
    expect(methods).toEqual(['SendMessage']);
  });

  it('parses a recorded 1.0 message response', async () => {
    const harness = makeHarness();
    const client = makeClient(harness);

    const result = await client.invokeService(TARGET_URL, 'ping', { subjectToken: 'user-token' });

    expect(result.task).toBeUndefined();
    expect(result.message?.messageId).toBe('resp-1');
    expect(result.message?.parts[0]?.content).toEqual({ $case: 'text', value: 'echo: ping' });
    expect(result.agentCard.name).toBe('Target Agent');
  });

  it('parses a recorded 1.0 task response', async () => {
    const harness = makeHarness({ rpcResponse: RECORDED_1_0_TASK_RESPONSE });
    const client = makeClient(harness);

    const result = await client.invokeService(TARGET_URL, 'ping', { subjectToken: 'user-token' });

    expect(result.message).toBeUndefined();
    expect(result.task?.id).toBe('task-1');
    expect(result.task?.status?.message?.parts[0]?.content).toEqual({ $case: 'text', value: 'done' });
  });

  it('surfaces a JSON-RPC error response as a thrown error', async () => {
    const harness = makeHarness({
      rpcResponse: {
        jsonrpc: '2.0',
        id: 0,
        error: { code: -32601, message: 'Method not found' },
      },
    });
    const client = makeClient(harness);

    await expect(
      client.invokeService(TARGET_URL, 'ping', { subjectToken: 'user-token' }),
    ).rejects.toThrow(/Method not found/);
  });

  it('calls the JSON-RPC URL advertised by the card without doubling /a2a/jsonrpc', async () => {
    const harness = makeHarness();
    const client = makeClient(harness);

    await client.invokeService(TARGET_URL, 'ping', { subjectToken: 'user-token' });

    expect(harness.rpcCalls[0].url).toBe(TARGET_JSONRPC_URL);
    expect(harness.rpcCalls[0].url).not.toContain('/a2a/jsonrpc/a2a/jsonrpc');
  });
});

describe('DelegationClient and 0.3-generation agents', () => {
  it('rejects a 0.3 agent card by default (no compatibility layer)', async () => {
    const harness = makeHarness({ card: LEGACY_TARGET_CARD_JSON });
    const client = makeClient(harness);

    await expect(
      client.invokeService(TARGET_URL, 'ping', { subjectToken: 'user-token' }),
    ).rejects.toThrow(/no usable JSON-RPC interface/);
    expect(harness.rpcCalls).toHaveLength(0);
  });

  it('speaks 0.3 to a 0.3 agent only when legacyCompat is enabled (upstream compat layer)', async () => {
    const harness = makeHarness({
      card: LEGACY_TARGET_CARD_JSON,
      rpcResponse: {
        jsonrpc: '2.0',
        id: 0,
        result: {
          kind: 'message',
          messageId: 'legacy-resp',
          role: 'agent',
          parts: [{ kind: 'text', text: 'legacy echo' }],
        },
      },
    });
    const client = makeClient(harness, { legacyCompat: { enabled: true } });

    const result = await client.invokeService(TARGET_URL, 'ping', { subjectToken: 'user-token' });

    const call = harness.rpcCalls[0];
    expect((call.body as { method: string }).method).toBe('message/send');
    expect(call.headers['a2a-version']).toBe('0.3');
    expect((call.body as any).params.message.parts).toEqual([{ kind: 'text', text: 'ping' }]);
    expect(result.message?.messageId).toBe('legacy-resp');
  });

  it('still speaks 1.0 to a 1.0 agent when legacyCompat is enabled', async () => {
    const harness = makeHarness();
    const client = makeClient(harness, { legacyCompat: { enabled: true } });

    await client.invokeService(TARGET_URL, 'ping', { subjectToken: 'user-token' });

    expect((harness.rpcCalls[0].body as { method: string }).method).toBe('SendMessage');
    expect(harness.rpcCalls[0].headers['a2a-version']).toBe('1.0');
  });
});

describe('buildAgentCard interface', () => {
  it('advertises the JSON-RPC endpoint as a 1.0 interface', () => {
    const card: AgentCard = buildAgentCard({ ...CONFIG, identityUrl: TARGET_URL });
    expect(card.supportedInterfaces).toEqual([
      {
        url: TARGET_JSONRPC_URL,
        protocolBinding: 'JSONRPC',
        protocolVersion: '1.0',
        tenant: '',
      },
    ]);
  });
});
