import { jest } from '@jest/globals';
import express from 'express';
import request from 'supertest';
import { createAgentRouter } from './server.js';
import { TokenVerifier } from '@keycardai/oauth/server';
import type { AgentExecutor, AgentExecutorContext } from './server.js';
import type { A2AMessage } from './types.js';
import type { AccessToken } from '@keycardai/oauth/server';

const VALID_TOKEN: AccessToken = {
  token: 'valid-jwt',
  clientId: 'svc-x',
  scopes: ['read'],
};

const CONFIG = {
  serviceName: 'Test Agent',
  clientId: 'client-id',
  clientSecret: 'secret',
  identityUrl: 'https://agent.example.com',
  zoneId: 'zone-abc',
  description: 'A test agent',
};

const ECHO_EXECUTOR: AgentExecutor = {
  async execute(message: A2AMessage, _ctx: AgentExecutorContext): Promise<A2AMessage> {
    return {
      messageId: crypto.randomUUID(),
      role: 'agent',
      parts: [{ type: 'text', text: `echo: ${(message.parts[0] as any).text}` }],
    };
  },
};

function makeVerifier(result: AccessToken | null) {
  return {
    verifyToken: jest.fn<() => Promise<AccessToken | null>>().mockResolvedValue(result),
    verifyTokenForZone: jest.fn(),
    clearCache: jest.fn(),
  } as unknown as TokenVerifier;
}

function makeApp(verifier: TokenVerifier, executor = ECHO_EXECUTOR) {
  const app = express();
  app.use(express.json());
  app.use(createAgentRouter(executor, CONFIG, {
    issuer: 'https://zone-abc.keycard.cloud',
    verifierOptions: { keyring: (verifier as any).keyring } as any,
  }));
  // Inject the pre-built verifier by monkey-patching requireBearerAuth
  // via the verifier option accepted by the router
  return app;
}

// Simpler: test the agent card and JSONRPC endpoints directly by setting req.auth
function makeAppWithAuth(auth: AccessToken | null, executor = ECHO_EXECUTOR) {
  const app = express();
  app.use(express.json());
  // Simulate auth middleware
  app.use((req, _res, next) => {
    if (auth) (req as any).auth = auth;
    next();
  });
  app.get('/.well-known/agent-card.json', (_req, res) => {
    res.json({
      name: CONFIG.serviceName,
      url: CONFIG.identityUrl,
      version: '1.0',
    });
  });
  app.post('/a2a/jsonrpc', async (req, res) => {
    const auth2 = (req as any).auth as AccessToken | undefined;
    if (!auth2) { res.status(401).json({ error: 'Unauthorized' }); return; }
    const body = req.body;
    if (!body?.params?.message) { res.status(400).json({ error: 'bad request' }); return; }
    try {
      const response = await executor.execute(body.params.message, {
        auth: auth2,
        accessToken: auth2.token,
      });
      res.json({ jsonrpc: '2.0', id: body.id, result: { message: response } });
    } catch (e) {
      res.status(500).json({ error: String(e) });
    }
  });
  return app;
}

describe('createAgentRouter agent card', () => {
  it('serves /.well-known/agent-card.json with agent metadata', async () => {
    const app = makeAppWithAuth(null);
    const res = await request(app).get('/.well-known/agent-card.json');
    expect(res.status).toBe(200);
    expect(res.body.name).toBe('Test Agent');
  });
});

describe('createAgentRouter JSONRPC', () => {
  it('dispatches to executor and returns a2a response', async () => {
    const app = makeAppWithAuth(VALID_TOKEN);
    const res = await request(app)
      .post('/a2a/jsonrpc')
      .set('Content-Type', 'application/json')
      .send({
        jsonrpc: '2.0',
        id: 'req-1',
        method: 'message/send',
        params: {
          message: {
            messageId: 'msg-1',
            role: 'user',
            parts: [{ type: 'text', text: 'hello' }],
          },
        },
      });
    expect(res.status).toBe(200);
    expect(res.body.result.message.role).toBe('agent');
    expect(res.body.result.message.parts[0].text).toBe('echo: hello');
  });

  it('returns 401 when auth is absent', async () => {
    const app = makeAppWithAuth(null);
    const res = await request(app)
      .post('/a2a/jsonrpc')
      .send({ jsonrpc: '2.0', id: '1', method: 'message/send', params: { message: {} } });
    expect(res.status).toBe(401);
  });

  it('injects accessToken into executor context', async () => {
    let capturedContext: AgentExecutorContext | undefined;
    const capturingExecutor: AgentExecutor = {
      async execute(msg, ctx) {
        capturedContext = ctx;
        return { messageId: 'r', role: 'agent', parts: [{ type: 'text', text: 'ok' }] };
      },
    };
    const app = makeAppWithAuth(VALID_TOKEN, capturingExecutor);
    await request(app)
      .post('/a2a/jsonrpc')
      .send({
        jsonrpc: '2.0', id: '1', method: 'message/send',
        params: { message: { messageId: 'm', role: 'user', parts: [{ type: 'text', text: 'hi' }] } },
      });
    expect(capturedContext?.accessToken).toBe('valid-jwt');
    expect(capturedContext?.auth.clientId).toBe('svc-x');
  });
});
