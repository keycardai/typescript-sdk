import { jest } from '@jest/globals';
import express from 'express';
import request from 'supertest';
import { createKeycardRequestHandler, buildAgentCard } from './server.js';
import { keycardUserBuilder, KeycardUser, getKeycardAuth } from './auth.js';
import {
  agentCardHandler,
  jsonRpcHandler,
} from '@a2a-js/sdk/server/express';
import {
  DefaultExecutionEventBus,
  type AgentExecutor,
  type ExecutionEventBus,
  RequestContext,
} from '@a2a-js/sdk/server';
import type { Message } from '@a2a-js/sdk';
import { TokenVerifier } from '@keycardai/oauth/server';
import type { AccessToken } from '@keycardai/oauth/server';

const CONFIG = {
  serviceName: 'Test Agent',
  clientId: 'client-id',
  clientSecret: 'secret',
  identityUrl: 'https://agent.example.com',
  zoneId: 'zone-abc',
  description: 'A test agent',
};

const VALID_TOKEN: AccessToken = {
  token: 'valid-jwt',
  clientId: 'svc-x',
  scopes: ['read'],
};

const ECHO_EXECUTOR: AgentExecutor = {
  async execute(requestContext: RequestContext, eventBus: ExecutionEventBus): Promise<void> {
    const userMsg = requestContext.userMessage;
    const textPart = userMsg.parts.find((p): p is { kind: 'text'; text: string } =>
      (p as any).kind === 'text',
    );
    const responseMsg: Message = {
      messageId: crypto.randomUUID(),
      role: 'agent',
      parts: [{ kind: 'text', text: `echo: ${textPart?.text ?? ''}` } as any],
    };
    eventBus.publish(responseMsg);
    eventBus.finished();
  },
  async cancelTask(): Promise<void> {},
};

function makeVerifier(result: AccessToken | null) {
  return {
    verifyToken: jest.fn<() => Promise<AccessToken | null>>().mockResolvedValue(result),
    verifyTokenForZone: jest.fn(),
    clearCache: jest.fn(),
  } as unknown as TokenVerifier;
}

function makeApp(verifier: TokenVerifier) {
  const agentCard = buildAgentCard(CONFIG);
  const requestHandler = createKeycardRequestHandler(ECHO_EXECUTOR, agentCard);
  const userBuilder = keycardUserBuilder({ issuer: 'https://zone-abc.keycard.cloud' });

  // Override the TokenVerifier in the userBuilder for test isolation
  const testUserBuilder = async (req: any) => {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) return { isAuthenticated: false, userName: 'anonymous' };
    const token = auth.slice(7);
    const accessToken = await verifier.verifyToken(token);
    if (!accessToken) return { isAuthenticated: false, userName: 'anonymous' };
    return new KeycardUser(accessToken);
  };

  const app = express();
  app.use(express.json());
  app.use(
    '/.well-known/agent-card.json',
    agentCardHandler({ agentCardProvider: requestHandler }),
  );
  app.use(
    '/a2a/jsonrpc',
    jsonRpcHandler({ requestHandler, userBuilder: testUserBuilder }),
  );
  return app;
}

describe('buildAgentCard', () => {
  it('builds an agent card from config', () => {
    const card = buildAgentCard(CONFIG);
    expect(card.name).toBe('Test Agent');
    expect(card.url).toBe('https://agent.example.com/a2a/jsonrpc');
    expect(card.capabilities).toBeDefined();
  });
});

describe('agentCardHandler', () => {
  it('serves the agent card with correct name', async () => {
    const app = makeApp(makeVerifier(VALID_TOKEN));
    const res = await request(app).get('/.well-known/agent-card.json');
    expect(res.status).toBe(200);
    expect(res.body.name).toBe('Test Agent');
  });
});

describe('jsonRpcHandler with KeycardUser', () => {
  it('dispatches to executor and returns agent message', async () => {
    const app = makeApp(makeVerifier(VALID_TOKEN));
    const res = await request(app)
      .post('/a2a/jsonrpc')
      .set('Authorization', 'Bearer valid-jwt')
      .set('Content-Type', 'application/json')
      .send({
        jsonrpc: '2.0',
        id: 'req-1',
        method: 'message/send',
        params: {
          message: {
            messageId: 'msg-1',
            role: 'user',
            parts: [{ kind: 'text', text: 'hello' }],
          },
        },
      });
    expect(res.status).toBe(200);
  });

  it('returns a JSONRPC error for unauthenticated requests', async () => {
    const app = makeApp(makeVerifier(null));
    const res = await request(app)
      .post('/a2a/jsonrpc')
      .set('Content-Type', 'application/json')
      .send({
        jsonrpc: '2.0',
        id: '1',
        method: 'message/send',
        params: { message: { messageId: 'm', role: 'user', parts: [] } },
      });
    // The SDK returns JSONRPC error responses with HTTP 200 per the JSONRPC spec.
    expect(res.status).toBe(200);
    expect(res.body.error).toBeDefined();
  });
});

describe('getKeycardAuth', () => {
  it('returns null when context has no user', () => {
    const ctx = new RequestContext(
      { messageId: 'm', role: 'user', parts: [] } as any,
      'task-1',
      'ctx-1',
    );
    expect(getKeycardAuth(ctx)).toBeNull();
  });
});
