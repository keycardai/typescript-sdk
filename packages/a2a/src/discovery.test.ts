import { jest } from '@jest/globals';
import { ServiceDiscovery } from './discovery.js';

const AGENT_URL = 'https://agent.example.com';
const AGENT_CARD = {
  name: 'Test Agent',
  url: AGENT_URL,
  version: '1.0',
  description: 'A test agent',
};

type FetchInput = Parameters<typeof fetch>[0];

describe('ServiceDiscovery', () => {
  let originalFetch: typeof fetch;
  let fetchMock: jest.Mock;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    fetchMock = jest.fn(async (_: FetchInput) =>
      new Response(JSON.stringify(AGENT_CARD), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('fetches the agent card from the correct URL', async () => {
    const discovery = new ServiceDiscovery();
    const card = await discovery.discoverService(AGENT_URL);
    expect(card.name).toBe('Test Agent');
    expect(fetchMock).toHaveBeenCalledWith(
      `${AGENT_URL}/.well-known/agent-card.json`,
      expect.anything(),
    );
  });

  it('caches the card on the second call', async () => {
    const discovery = new ServiceDiscovery();
    await discovery.getServiceCard(AGENT_URL);
    await discovery.getServiceCard(AGENT_URL);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('refetches when forceRefresh is true', async () => {
    const discovery = new ServiceDiscovery();
    await discovery.getServiceCard(AGENT_URL);
    await discovery.getServiceCard(AGENT_URL, { forceRefresh: true });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('throws when the agent card is missing the name field', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ url: AGENT_URL, version: '1.0' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    const discovery = new ServiceDiscovery();
    await expect(discovery.discoverService(AGENT_URL)).rejects.toThrow(/missing required field "name"/);
  });

  it('throws on non-2xx response', async () => {
    fetchMock.mockResolvedValue(new Response('Not Found', { status: 404 }));
    const discovery = new ServiceDiscovery();
    await expect(discovery.discoverService(AGENT_URL)).rejects.toThrow(/HTTP 404/);
  });
});
