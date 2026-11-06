import { jest } from '@jest/globals';
import { fetchAuthorizationServerMetadata } from './discovery.js';
import { resolveIssuerFromChallenge } from './challenge.js';
import { DEFAULT_REQUEST_TIMEOUT_MS, requestSignal } from './requestSignal.js';

const hang = () => new Promise<Response>(() => {});

describe('requestSignal', () => {
  it('defaults to a 10 second timeout', () => {
    expect(DEFAULT_REQUEST_TIMEOUT_MS).toBe(10_000);
    expect(requestSignal(undefined)).toBeInstanceOf(AbortSignal);
  });

  it('timeoutMs 0 returns the signal the caller passed', () => {
    const controller = new AbortController();
    expect(requestSignal(controller.signal, 0)).toBe(controller.signal);
    expect(requestSignal(undefined, 0)).toBeUndefined();
  });

  it('the abort the caller sends wins over the timeout', () => {
    const controller = new AbortController();
    const signal = requestSignal(controller.signal, 60_000)!;
    controller.abort(new Error('caller'));
    expect(signal.aborted).toBe(true);
    expect((signal.reason as Error).message).toBe('caller');
  });

  it('the timeout aborts a request the caller never aborted', async () => {
    const controller = new AbortController();
    const signal = requestSignal(controller.signal, 5)!;
    await new Promise((r) => setTimeout(r, 30));
    expect(signal.aborted).toBe(true);
    expect((signal.reason as DOMException).name).toBe('TimeoutError');
  });
});

describe('default request timeout on zone requests', () => {
  it('discovery rejects with TimeoutError instead of waiting forever', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
      const signal = init?.signal as AbortSignal;
      return new Promise<Response>((_, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason), { once: true });
      });
    }) as typeof fetch;
    try {
      await expect(
        fetchAuthorizationServerMetadata('https://zone.example', { timeoutMs: 5 }),
      ).rejects.toMatchObject({ name: 'TimeoutError' });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('challenge metadata fetch gets a signal even when the caller passed none', async () => {
    const originalFetch = globalThis.fetch;
    const fetchMock = jest.fn(hang);
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    try {
      void resolveIssuerFromChallenge(
        'Bearer resource_metadata="https://zone.example/.well-known/oauth-protected-resource"',
        {},
      ).catch(() => {});
      await Promise.resolve();
      const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
      expect(init.signal).toBeInstanceOf(AbortSignal);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
