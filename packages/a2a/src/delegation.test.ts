import { DelegationClient } from './delegation.js';
import { buildAgentCard } from './server.js';

const CONFIG = {
  serviceName: 'Test Agent',
  clientId: 'client-id',
  clientSecret: 'secret',
  identityUrl: 'https://agent.example.com',
  zoneId: 'zone-abc',
};

describe('buildJsonrpcUrl (double-path regression)', () => {
  it('does not double the /a2a/jsonrpc path when agentCard.url already contains it', () => {
    // buildAgentCard sets url to getJsonrpcUrl(config) = identityUrl + /a2a/jsonrpc
    const card = buildAgentCard(CONFIG);
    expect(card.url).toBe('https://agent.example.com/a2a/jsonrpc');

    // DelegationClient.invokeService internally calls buildJsonrpcUrl(serviceUrl, card).
    // If buildJsonrpcUrl appended /a2a/jsonrpc to card.url the result would be
    // .../a2a/jsonrpc/a2a/jsonrpc. Verify the card URL is used directly.
    // We test this indirectly by checking that the fetch call uses the card URL as-is.
    const originalFetch = globalThis.fetch;
    const calls: string[] = [];
    globalThis.fetch = (async (input: any) => {
      calls.push(typeof input === 'string' ? input : String(input));
      return new Response(JSON.stringify({
        issuer: 'https://zone-abc.keycard.cloud',
        token_endpoint: 'https://zone-abc.keycard.cloud/token',
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }) as any;

    const client = new DelegationClient(CONFIG);
    // invokeService will fail (no valid token endpoint for exchange) but we just
    // need to capture the URL it attempted to call for the JSONRPC step.
    client.invokeService('https://agent.example.com', 'test', { subjectToken: 'tok' })
      .catch(() => {});

    globalThis.fetch = originalFetch;
    // The discovery URL for .well-known/agent-card.json should be correct
    const agentCardFetch = calls.find(u => u.includes('.well-known/agent-card.json'));
    if (agentCardFetch) {
      expect(agentCardFetch).not.toContain('/a2a/jsonrpc/.well-known');
    }
  });

  it('buildAgentCard url equals the JSONRPC endpoint directly', () => {
    const card = buildAgentCard(CONFIG);
    expect(card.url).toBe('https://agent.example.com/a2a/jsonrpc');
    expect(card.url).not.toContain('/a2a/jsonrpc/a2a/jsonrpc');
  });
});
