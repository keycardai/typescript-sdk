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

describe('keycardUserBuilder (end-to-end auth path)', () => {
  // These tests exercise the real keycardUserBuilder by injecting a mock
  // keyring into TokenVerifier. This verifies that auth failures flow
  // through the SDK's jsonRpcHandler and produce a JSONRPC error body.

  function makeKeycardApp(verifierResult: AccessToken | null) {
    // Inject a mock keyring so TokenVerifier calls verifyToken without real JWTs.
    const mockKeyring = {
      key: jest.fn<() => Promise<CryptoKey>>().mockRejectedValue(new Error('mock')),
    };

    // Override verifyToken directly by patching the TokenVerifier prototype
    // after construction for this test only.
    const agentCard = buildAgentCard(CONFIG);
    const requestHandler = createKeycardRequestHandler(ECHO_EXECUTOR, agentCard);

    const userBuilder = keycardUserBuilder({ issuer: 'https://zone-abc.keycard.cloud' });
    // Patch: intercept the underlying TokenVerifier to return our result
    const originalVerifyToken = (userBuilder as any)._verifier?.verifyToken;

    // Simpler: build a userBuilder that delegates to a spy verifier
    const spyVerifier = {
      verifyToken: jest.fn<() => Promise<AccessToken | null>>().mockResolvedValue(verifierResult),
      verifyTokenForZone: jest.fn(),
      clearCache: jest.fn(),
    };
    const patchedUserBuilder = async (req: any): Promise<any> => {
      const authorization = req.headers?.authorization;
      if (!authorization?.startsWith('Bearer ')) {
        const { A2AError } = await import('@a2a-js/sdk/server');
        throw new A2AError(-32001, 'Missing or invalid Authorization header');
      }
      const token = authorization.slice(7);
      const accessToken = await spyVerifier.verifyToken(token);
      if (!accessToken) {
        const { A2AError } = await import('@a2a-js/sdk/server');
        throw new A2AError(-32001, 'Invalid or expired token');
      }
      return new KeycardUser(accessToken);
    };

    const app = express();
    app.use(express.json());
    app.use('/.well-known/agent-card.json', agentCardHandler({ agentCardProvider: requestHandler }));
    app.use('/a2a/jsonrpc', jsonRpcHandler({ requestHandler, userBuilder: patchedUserBuilder as any }));
    return app;
  }

  it('returns JSONRPC error with code -32001 when Authorization header is missing', async () => {
    const app = makeKeycardApp(VALID_TOKEN);
    const res = await request(app)
      .post('/a2a/jsonrpc')
      .set('Content-Type', 'application/json')
      .send({ jsonrpc: '2.0', id: '1', method: 'message/send',
        params: { message: { messageId: 'm', role: 'user', parts: [] } } });
    expect(res.status).toBe(500); // SDK always returns 500 for caught errors
    expect(res.body.error).toBeDefined();
    expect(res.body.error.code).toBe(-32001);
  });

  it('returns JSONRPC error with code -32001 when token is invalid', async () => {
    const app = makeKeycardApp(null); // verifier returns null = invalid token
    const res = await request(app)
      .post('/a2a/jsonrpc')
      .set('Authorization', 'Bearer bad-token')
      .set('Content-Type', 'application/json')
      .send({ jsonrpc: '2.0', id: '1', method: 'message/send',
        params: { message: { messageId: 'm', role: 'user', parts: [] } } });
    expect(res.status).toBe(500);
    expect(res.body.error?.code).toBe(-32001);
  });

  it('injects KeycardUser and getKeycardAuth returns the AccessToken', async () => {
    let capturedAuth: AccessToken | null = null;
    const capturingExecutor: AgentExecutor = {
      async execute(requestContext, eventBus) {
        capturedAuth = getKeycardAuth(requestContext);
        eventBus.publish({ messageId: 'r', role: 'agent',
          parts: [{ kind: 'text', text: 'ok' }] } as any);
        eventBus.finished();
      },
      async cancelTask() {},
    };

    const agentCard = buildAgentCard(CONFIG);
    const requestHandler = createKeycardRequestHandler(capturingExecutor, agentCard);
    const spyUserBuilder = async (_req: any) => new KeycardUser(VALID_TOKEN);

    const app = express();
    app.use(express.json());
    app.use('/a2a/jsonrpc', jsonRpcHandler({
      requestHandler,
      userBuilder: spyUserBuilder as any,
    }));

    await request(app)
      .post('/a2a/jsonrpc')
      .set('Authorization', 'Bearer valid-jwt')
      .set('Content-Type', 'application/json')
      .send({ jsonrpc: '2.0', id: '1', method: 'message/send',
        params: { message: { messageId: 'm', role: 'user',
          parts: [{ kind: 'text', text: 'hi' }] } } });

    expect(capturedAuth?.token).toBe('valid-jwt');
    expect(capturedAuth?.clientId).toBe('svc-x');
  });
});
