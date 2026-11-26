import { jest } from '@jest/globals';
import { A2ADiscoveryError, DelegationClient, type DelegationClientOptions } from './index.js';
import { buildAgentCard } from './server.js';
import { ServiceDiscovery } from './discovery.js';
import { boundedPeerFetch } from './peer-response.js';
import type { AgentCard } from '@a2a-js/sdk';
import { ResponseBodyTooLargeError } from '@keycardai/oauth';
import { createServer } from 'node:http';
import { gzipSync } from 'node:zlib';

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
  rpcUrl?: string;
  rpcStatus?: number;
  peerResponse?: (document: unknown, invocation: boolean) => Response;
  tokenResponse?: Response;
} = {}) {
  const rpcCalls: Recorded[] = [];
  let exchanges = 0;
  const fetchMock = jest.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (url === `${TARGET_URL}/.well-known/agent-card.json`) {
      if (opts.peerResponse) return opts.peerResponse(opts.card ?? TARGET_CARD_JSON, false);
      return jsonResponse(opts.card ?? TARGET_CARD_JSON);
    }
    if (url === 'https://zone-abc.keycard.cloud/.well-known/oauth-authorization-server') {
      return jsonResponse({
        issuer: 'https://zone-abc.keycard.cloud',
        token_endpoint: 'https://zone-abc.keycard.cloud/token',
      });
    }
    if (url === 'https://zone-abc.keycard.cloud/token') {
      exchanges++;
      if (opts.tokenResponse) return opts.tokenResponse;
      return jsonResponse({
        access_token: 'delegated-token',
        token_type: 'Bearer',
        issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      });
    }
    if (url === (opts.rpcUrl ?? TARGET_JSONRPC_URL)) {
      const body = JSON.parse(String(init?.body));
      rpcCalls.push({ url, method: init?.method ?? 'GET', headers: headersOf(init), body });
      const response = { ...(opts.rpcResponse ?? RECORDED_1_0_MESSAGE_RESPONSE), id: body.id };
      if (opts.peerResponse) return opts.peerResponse(response, true);
      return jsonResponse(response, opts.rpcStatus ?? 200);
    }
    throw new Error(`unexpected fetch: ${url}`);
  });
  return { fetch: fetchMock as unknown as typeof fetch, rpcCalls, exchangeCount: () => exchanges };
}

let originalFetch: typeof fetch;
beforeEach(() => {
  originalFetch = globalThis.fetch;
});
afterEach(() => {
  globalThis.fetch = originalFetch;
});

function makeClient(harness: ReturnType<typeof makeHarness>, extra: DelegationClientOptions = {}) {
  // ServiceDiscovery and TokenExchangeClient use the global fetch; the A2A
  // transport receives the same mock via fetchImpl.
  globalThis.fetch = harness.fetch;
  return new DelegationClient(CONFIG, {
    discovery: new ServiceDiscovery(),
    fetchImpl: harness.fetch,
    ...extra,
  });
}

const padding = new Uint8Array(1024 * 1024).fill(32);

function paddedResponse(document: unknown, mib: number, status = 200): Response {
  let remaining = mib;
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(JSON.stringify(document)));
    },
    pull(controller) {
      if (remaining-- > 0) controller.enqueue(padding);
      else controller.close();
    },
  });
  return new Response(body, { status, headers: { 'content-type': 'application/json' } });
}

describe('A2A delegation v3 peer response limit', () => {
  const options = { subjectToken: 'user-token' };

  it('replays accepted response chunks without copying them', async () => {
    const chunks = [new Uint8Array([1, 2]), new Uint8Array([3, 4])];
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(chunk);
        controller.close();
      },
    });
    globalThis.fetch = async () => new Response(body);

    const response = await boundedPeerFetch(4)(TARGET_URL);
    const reader = response.body!.getReader();
    for (const chunk of chunks) expect((await reader.read()).value).toBe(chunk);
    expect((await reader.read()).done).toBe(true);
  });

  it('row 9: accepts agent cards and invocation replies above 1 MiB by default', async () => {
    globalThis.fetch = makeHarness({ peerResponse: (doc) => paddedResponse(doc, 1) }).fetch;
    const result = await new DelegationClient(CONFIG).invokeService(TARGET_URL, 'ping', options);
    expect(result.agentCard.name).toBe(TARGET_CARD_JSON.name);
    expect(result.message?.messageId).toBe('resp-1');
  });

  it.each([false, true])('row 10: bounds the decoded gzip body (invocation: %s)', async (invocation) => {
    const compressed = gzipSync(JSON.stringify({ name: 'Peer' }) + ' '.repeat(1024));
    expect(compressed.byteLength).toBeLessThan(768);
    const harness = makeHarness();
    const server = createServer((request, response) => {
      if (invocation && request.method === 'GET') {
        const target = { ...TARGET_CARD_JSON, supportedInterfaces: [
          { ...TARGET_CARD_JSON.supportedInterfaces[0], url: targetUrl },
        ] };
        response.end(JSON.stringify(target));
      } else {
        response.writeHead(200, { 'content-encoding': 'gzip' });
        response.end(compressed);
      }
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Missing local server address');
    const targetUrl = `http://127.0.0.1:${address.port}`;
    globalThis.fetch = (input, init) => String(input).startsWith(targetUrl)
      ? originalFetch(input, init) : harness.fetch(input, init);
    try {
      const pending = invocation
        ? new DelegationClient(CONFIG, { maxPeerResponseBytes: 768 }).invokeService(targetUrl, 'ping', options)
        : new ServiceDiscovery({ maxPeerResponseBytes: 768 }).discoverService(targetUrl);
      await expect(pending).rejects.toMatchObject({
        errorCode: 'invalid_response', status: 200, retryable: !invocation,
      });
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it.each([200, 429, 503])('row 10a: preserves status and classifies HTTP %s', async (status) => {
    for (const invocation of [false, true]) {
      globalThis.fetch = makeHarness({
        peerResponse: (doc, rpc) => rpc === invocation ? paddedResponse(doc, 1, status) : jsonResponse(doc),
      }).fetch;
      const pending = invocation
        ? new DelegationClient(CONFIG, { maxPeerResponseBytes: 1024 }).invokeService(TARGET_URL, 'ping', options)
        : new ServiceDiscovery({ maxPeerResponseBytes: 1024 }).discoverService(TARGET_URL);
      await expect(pending).rejects.toMatchObject({
        errorCode: 'invalid_response', status, retryable: !invocation || status !== 200,
      });
    }
  });

  it('row 10a: bounds invocation through the legacy transport', async () => {
    globalThis.fetch = makeHarness({
      card: LEGACY_TARGET_CARD_JSON,
      peerResponse: (doc, rpc) => rpc ? paddedResponse(doc, 1) : jsonResponse(doc),
    }).fetch;
    const client = new DelegationClient(CONFIG, {
      legacyCompat: { enabled: true }, maxPeerResponseBytes: 1024,
    });
    await expect(client.invokeService(TARGET_URL, 'ping', options)).rejects.toMatchObject({
      errorCode: 'invalid_response', status: 200, retryable: false,
    });
  });

  it.each([false, true])('row 11: lowers and raises the default cap (invocation: %s)', async (invocation) => {
    const invoke = (maxPeerResponseBytes?: number) => invocation
      ? new DelegationClient(CONFIG, { maxPeerResponseBytes }).invokeService(TARGET_URL, 'ping', options)
      : new ServiceDiscovery({ maxPeerResponseBytes }).discoverService(TARGET_URL);
    const setup = (mib: number) => {
      globalThis.fetch = makeHarness({
        peerResponse: (doc, rpc) => rpc === invocation ? paddedResponse(doc, mib) : jsonResponse(doc),
      }).fetch;
    };
    setup(1);
    await expect(invoke()).resolves.toBeDefined();
    await expect(invoke(1024)).rejects.toBeInstanceOf(ResponseBodyTooLargeError);
    setup(64);
    await expect(invoke()).rejects.toBeInstanceOf(ResponseBodyTooLargeError);
    await expect(invoke(65 * padding.length)).resolves.toBeDefined();
  });

  it.each([1024, 65 * padding.length])('row 11: keeps the token exchange cap with peer limit %s', async (limit) => {
    globalThis.fetch = makeHarness({ tokenResponse: paddedResponse({ access_token: 'token' }, 1) }).fetch;
    const client = new DelegationClient(CONFIG, { maxPeerResponseBytes: limit });
    await expect(client.invokeService(TARGET_URL, 'ping', options)).rejects.toMatchObject({
      errorCode: 'invalid_response', limit: padding.length, status: 200,
    });
  });
});

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

describe('DelegationClient invocation endpoint origins', () => {
  const options = { subjectToken: 'user-token' };
  const rpcInterface = TARGET_CARD_JSON.supportedInterfaces[0];
  const cardAt = (url: string) => ({
    ...TARGET_CARD_JSON,
    supportedInterfaces: [{ ...rpcInterface, url }],
  });

  it.each([
    ['12: invokes on the same origin', `${TARGET_URL}/rpc`, []],
    ['14: invokes on an allowlisted origin', 'https://gateway.example.com/rpc', ['HTTPS://Gateway.Example.com:443/']],
    ['15: matches an explicit default port', 'https://agent.example.com:443/rpc', []],
    ['15b: matches scheme and host case-insensitively', 'HTTPS://Agent.Example.com/rpc', []],
  ])('row %s', async (_name, url, trustedEndpointOrigins) => {
    const harness = makeHarness({ card: cardAt(url), rpcUrl: url });
    const client = makeClient(harness, { trustedEndpointOrigins });

    await client.invokeService(TARGET_URL, 'ping', options);

    expect(harness.exchangeCount()).toBe(1);
    expect(harness.rpcCalls).toEqual([
      expect.objectContaining({ url, headers: expect.objectContaining({ authorization: 'Bearer delegated-token' }) }),
    ]);
  });

  it.each([
    ['13: refuses a different host', 'https://other.example.com/rpc', 'https://other.example.com:443', false],
    ['15: refuses a different port', 'https://agent.example.com:8443/rpc', 'https://agent.example.com:8443', false],
    ['15: refuses a different scheme', 'http://agent.example.com/rpc', 'http://agent.example.com:80', false],
    ['15a: refuses another origin in a 0.3 card', 'https://other.example.com/rpc', 'https://other.example.com:443', true],
  ])('row %s', async (_name, url, origin, legacy) => {
    const card = legacy ? { ...LEGACY_TARGET_CARD_JSON, url } : cardAt(url);
    const harness = makeHarness({ card, rpcUrl: url });
    const client = makeClient(harness, { legacyCompat: { enabled: legacy } });
    const call = client.invokeService(TARGET_URL, 'ping', options);

    await expect(call).rejects.toBeInstanceOf(A2ADiscoveryError);
    await expect(call).rejects.toMatchObject({
      retryable: false,
      message: expect.stringContaining(`Endpoint origin ${origin} is not trusted for target "${TARGET_URL}"`),
    });
    expect(harness.exchangeCount()).toBe(0);
    expect(harness.rpcCalls).toHaveLength(0);
  });

  it('checks the selected JSON-RPC interface rather than the first interface', async () => {
    const url = 'https://other.example.com/rpc';
    const card = {
      ...TARGET_CARD_JSON,
      supportedInterfaces: [
        { ...rpcInterface, protocolVersion: '0.3' },
        { ...rpcInterface, url },
      ],
    };
    const harness = makeHarness({ card, rpcUrl: url });

    await expect(makeClient(harness).invokeService(TARGET_URL, 'ping', options)).rejects.toBeInstanceOf(A2ADiscoveryError);
    expect(harness.exchangeCount()).toBe(0);
    expect(harness.rpcCalls).toHaveLength(0);
  });

  it.each([
    'https://gateway.example.com/rpc',
    'https://gateway.example.com/rpc/..',
    'https://gateway.example.com/?key=value',
    'https://gateway.example.com/?',
    'https://gateway.example.com/#part',
    'https://gateway.example.com/#',
    'https://user@gateway.example.com',
    'https://@gateway.example.com',
  ])('rejects a non-bare trusted endpoint origin: %s', (origin) => {
    expect(() => makeClient(makeHarness(), { trustedEndpointOrigins: [origin] })).toThrow(A2ADiscoveryError);
  });

  it('rejects a card advertising only non-JSON-RPC interfaces before exchange', async () => {
    const card = {
      ...TARGET_CARD_JSON,
      supportedInterfaces: ['HTTP+JSON', 'GRPC'].map((protocolBinding) => ({
        ...rpcInterface,
        url: `${TARGET_URL}/other`,
        protocolBinding,
      })),
    };
    const harness = makeHarness({ card });

    await expect(makeClient(harness).invokeService(TARGET_URL, 'ping', options))
      .rejects.toThrow(/no usable JSON-RPC interface/);
    expect(harness.exchangeCount()).toBe(0);
    expect(harness.rpcCalls).toHaveLength(0);
  });

  it('uses the convention endpoint on the target origin when the card advertises no endpoints', async () => {
    const harness = makeHarness({ card: { ...TARGET_CARD_JSON, supportedInterfaces: [] } });

    await makeClient(harness).invokeService(TARGET_URL, 'ping', options);

    expect(harness.exchangeCount()).toBe(1);
    expect(harness.rpcCalls[0]?.url).toBe(TARGET_JSONRPC_URL);
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

  it('rejects a protobuf-shaped 0.3 card before exchange when compatibility is disabled', async () => {
    const card = {
      ...LEGACY_TARGET_CARD_JSON,
      url: 'https://legacy.example.com/rpc',
      security: [{ schemes: { bearer: { list: [] } } }],
    };
    const harness = makeHarness({ card });
    const client = makeClient(harness, { legacyCompat: { enabled: false } });

    await expect(
      client.invokeService(TARGET_URL, 'ping', { subjectToken: 'user-token' }),
    ).rejects.toThrow(/no usable JSON-RPC interface/);
    expect(harness.exchangeCount()).toBe(0);
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
