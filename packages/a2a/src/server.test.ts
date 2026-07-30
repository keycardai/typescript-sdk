import { jest } from '@jest/globals';
import express from 'express';
import request from 'supertest';
import { createKeycardRequestHandler, buildAgentCard } from './server.js';
import { keycardUserBuilder, KeycardUser, getKeycardAuth } from './auth.js';
// Imported via the package index to cover the re-exports from @keycardai/express.
import { requireBearerAuth, keycardMetadataRouter } from './index.js';
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

  it('declares a bearer security scheme and requires it', () => {
    const card = buildAgentCard(CONFIG);
    expect(card.securitySchemes).toEqual({
      bearer: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Keycard-issued JWT access token',
      },
    });
    expect(card.security).toEqual([{ bearer: [] }]);
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

describe('requireBearerAuth + keycardUserBuilder (end-to-end auth path)', () => {
  // These tests exercise the recommended wiring: requireBearerAuth fronts
  // the JSON-RPC handler, rejecting auth failures with HTTP 401 and an
  // RFC 6750 WWW-Authenticate challenge, and keycardUserBuilder() wraps the
  // pre-verified token (branded on the request with KEYCARD_ACCESS_TOKEN)
  // into a KeycardUser.

  function makeKeycardApp(
    verifierResult: AccessToken | null,
    executor: AgentExecutor = ECHO_EXECUTOR,
  ) {
    const agentCard = buildAgentCard(CONFIG);
    const requestHandler = createKeycardRequestHandler(executor, agentCard);

    const app = express();
    app.use(express.json());
    app.use('/.well-known/agent-card.json', agentCardHandler({ agentCardProvider: requestHandler }));
    app.use(
      '/a2a/jsonrpc',
      requireBearerAuth({ verifier: makeVerifier(verifierResult) }),
      jsonRpcHandler({ requestHandler, userBuilder: keycardUserBuilder() }),
    );
    return app;
  }

  it('returns 401 with a WWW-Authenticate challenge when Authorization header is missing', async () => {
    const app = makeKeycardApp(VALID_TOKEN);
    const res = await request(app)
      .post('/a2a/jsonrpc')
      .set('Content-Type', 'application/json')
      .send({ jsonrpc: '2.0', id: '1', method: 'message/send',
        params: { message: { messageId: 'm', role: 'user', parts: [] } } });
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toMatch(/^Bearer /);
    expect(res.headers['www-authenticate']).toContain('resource_metadata=');
  });

  it("resolves the 401's resource_metadata pointer in the documented quickstart wiring", async () => {
    // Reproduces the README quickstart composition: keycardMetadataRouter at
    // the app root plus a requireBearerAuth-protected JSON-RPC route. The URL
    // advertised in the 401's WWW-Authenticate challenge must actually serve
    // the RFC 9728 protected-resource metadata.
    const agentCard = buildAgentCard(CONFIG);
    const requestHandler = createKeycardRequestHandler(ECHO_EXECUTOR, agentCard);
    const app = express();
    app.use(express.json());
    app.use(keycardMetadataRouter({ issuer: 'https://zone-abc.keycard.cloud' }));
    app.use('/.well-known/agent-card.json', agentCardHandler({ agentCardProvider: requestHandler }));
    app.use(
      '/a2a/jsonrpc',
      requireBearerAuth({ verifier: makeVerifier(null) }),
      jsonRpcHandler({ requestHandler, userBuilder: keycardUserBuilder() }),
    );

    const unauth = await request(app)
      .post('/a2a/jsonrpc')
      .set('Content-Type', 'application/json')
      .send({ jsonrpc: '2.0', id: '1', method: 'message/send',
        params: { message: { messageId: 'm', role: 'user', parts: [] } } });
    expect(unauth.status).toBe(401);

    const challenge = unauth.headers['www-authenticate'];
    const metadataUrl = /resource_metadata="([^"]+)"/.exec(challenge ?? '')?.[1];
    expect(metadataUrl).toBeDefined();

    const metadataRes = await request(app).get(new URL(String(metadataUrl)).pathname);
    expect(metadataRes.status).toBe(200);
    expect(metadataRes.body.resource).toBeDefined();
    expect(metadataRes.body.authorization_servers).toEqual(['https://zone-abc.keycard.cloud']);
  });

  it('returns 401 with a WWW-Authenticate challenge when token is invalid', async () => {
    const app = makeKeycardApp(null); // verifier returns null = invalid token
    const res = await request(app)
      .post('/a2a/jsonrpc')
      .set('Authorization', 'Bearer bad-token')
      .set('Content-Type', 'application/json')
      .send({ jsonrpc: '2.0', id: '1', method: 'message/send',
        params: { message: { messageId: 'm', role: 'user', parts: [] } } });
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toContain('error="invalid_token"');
  });

  it('injects KeycardUser from the branded request and getKeycardAuth returns the AccessToken', async () => {
    let capturedAuth: AccessToken | null = null;
    const capturingExecutor: AgentExecutor = {
      async execute(requestContext, eventBus) {
        capturedAuth = getKeycardAuth(requestContext);
        const responseMsg: Message = {
          kind: 'message',
          messageId: 'r',
          role: 'agent',
          parts: [{ kind: 'text', text: 'ok' }],
        };
        eventBus.publish(responseMsg);
        eventBus.finished();
      },
      async cancelTask() {},
    };

    const app = makeKeycardApp(VALID_TOKEN, capturingExecutor);

    const res = await request(app)
      .post('/a2a/jsonrpc')
      .set('Authorization', 'Bearer valid-jwt')
      .set('Content-Type', 'application/json')
      .send({ jsonrpc: '2.0', id: '1', method: 'message/send',
        params: { message: { messageId: 'm', role: 'user',
          parts: [{ kind: 'text', text: 'hi' }] } } });

    expect(res.status).toBe(200);
    expect(capturedAuth?.token).toBe('valid-jwt');
    expect(capturedAuth?.clientId).toBe('svc-x');
  });

  it('keycardUserBuilder verifies the token itself when no middleware ran (standalone fallback)', async () => {
    // Without requireBearerAuth in front, the builder throws an A2A -32001
    // error which the SDK's jsonRpcHandler surfaces as HTTP 500 with a
    // JSON-RPC error body. This documents the standalone contract; prefer
    // the requireBearerAuth composition above.
    const agentCard = buildAgentCard(CONFIG);
    const requestHandler = createKeycardRequestHandler(ECHO_EXECUTOR, agentCard);
    const app = express();
    app.use(express.json());
    app.use(
      '/a2a/jsonrpc',
      jsonRpcHandler({
        requestHandler,
        userBuilder: keycardUserBuilder({ issuer: 'https://zone-abc.keycard.cloud' }),
      }),
    );

    const res = await request(app)
      .post('/a2a/jsonrpc')
      .set('Content-Type', 'application/json')
      .send({ jsonrpc: '2.0', id: '1', method: 'message/send',
        params: { message: { messageId: 'm', role: 'user', parts: [] } } });
    expect(res.status).toBe(500);
    expect(res.body.error?.code).toBe(-32001);
  });

  it('does not launder a req.auth set by foreign middleware into an authenticated KeycardUser', async () => {
    // express-jwt also writes to req.auth (its default requestProperty), so a
    // token verified under someone else's rules could otherwise become an
    // authenticated KeycardUser. The builder must trust only requests branded
    // by requireBearerAuth, not bare req.auth.
    let executed = false;
    const trackingExecutor: AgentExecutor = {
      async execute(_requestContext, eventBus) {
        executed = true;
        eventBus.finished();
      },
      async cancelTask() {},
    };
    const agentCard = buildAgentCard(CONFIG);
    const requestHandler = createKeycardRequestHandler(trackingExecutor, agentCard);
    const app = express();
    app.use(express.json());
    app.use(
      '/a2a/jsonrpc',
      // Fake upstream middleware (stand-in for express-jwt): sets req.auth
      // without the KEYCARD_ACCESS_TOKEN brand.
      (req, _res, next) => {
        (req as express.Request & { auth?: AccessToken }).auth = {
          token: 'foreign',
          clientId: 'x',
          scopes: [],
        };
        next();
      },
      jsonRpcHandler({ requestHandler, userBuilder: keycardUserBuilder() }),
    );

    const res = await request(app)
      .post('/a2a/jsonrpc')
      .set('Content-Type', 'application/json')
      .send({ jsonrpc: '2.0', id: '1', method: 'message/send',
        params: { message: { messageId: 'm', role: 'user', parts: [] } } });

    // Without the brand the builder falls through to the standalone path;
    // with no verifier options it rejects with A2A -32001 over HTTP 500.
    expect(res.status).toBe(500);
    expect(res.body.error?.code).toBe(-32001);
    expect(executed).toBe(false);
  });
});
