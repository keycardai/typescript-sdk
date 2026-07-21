import type { Request } from 'express';
import { getRequestHost, getRequestOrigin } from './host.js';

/**
 * Builds a minimal Request stub. `host` mimics what each Express version
 * exposes: Express 5 passes the source header through (port included),
 * Express 4 strips the port.
 */
function fakeReq(options: {
  host: string;
  headers?: Record<string, string>;
  trustProxy?: boolean;
  protocol?: string;
}): Request {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(options.headers ?? {})) {
    headers[name.toLowerCase()] = value;
  }
  const app =
    options.trustProxy === undefined
      ? undefined
      : {
          get: (name: string) =>
            name === 'trust proxy fn' ? () => options.trustProxy : undefined,
        };
  return {
    host: options.host,
    protocol: options.protocol ?? 'http',
    get: (name: string) => headers[name.toLowerCase()],
    app,
    socket: { remoteAddress: '10.0.0.1' },
  } as unknown as Request;
}

describe('getRequestHost', () => {
  it('returns req.host unchanged when it already carries a port (Express 5)', () => {
    const req = fakeReq({
      host: 'api.example.com:8443',
      headers: { host: 'api.example.com:8443' },
    });
    expect(getRequestHost(req)).toBe('api.example.com:8443');
  });

  it('recovers the port from the Host header when req.host has none (Express 4)', () => {
    const req = fakeReq({
      host: 'api.example.com',
      headers: { host: 'api.example.com:8443' },
    });
    expect(getRequestHost(req)).toBe('api.example.com:8443');
  });

  it('returns the bare hostname when no header carries a port', () => {
    const req = fakeReq({
      host: 'api.example.com',
      headers: { host: 'api.example.com' },
    });
    expect(getRequestHost(req)).toBe('api.example.com');
  });

  it('recovers the port from X-Forwarded-Host when the proxy is trusted (Express 4)', () => {
    const req = fakeReq({
      host: 'pub.example.com',
      headers: {
        host: 'internal:3000',
        'x-forwarded-host': 'pub.example.com:8443',
      },
      trustProxy: true,
    });
    expect(getRequestHost(req)).toBe('pub.example.com:8443');
  });

  it('takes the first X-Forwarded-Host entry when proxies append values', () => {
    const req = fakeReq({
      host: 'pub.example.com',
      headers: {
        host: 'internal:3000',
        'x-forwarded-host': 'pub.example.com:8443, edge.example.com:9000',
      },
      trustProxy: true,
    });
    expect(getRequestHost(req)).toBe('pub.example.com:8443');
  });

  it('ignores X-Forwarded-Host when the proxy is not trusted', () => {
    const req = fakeReq({
      host: 'api.example.com',
      headers: {
        host: 'api.example.com:8443',
        'x-forwarded-host': 'api.example.com:9999',
      },
      trustProxy: false,
    });
    expect(getRequestHost(req)).toBe('api.example.com:8443');
  });

  it('ignores X-Forwarded-Host when no trust function is available', () => {
    const req = fakeReq({
      host: 'api.example.com',
      headers: {
        host: 'api.example.com:8443',
        'x-forwarded-host': 'api.example.com:9999',
      },
    });
    expect(getRequestHost(req)).toBe('api.example.com:8443');
  });

  it('returns req.host unchanged when the header hostname does not match', () => {
    const req = fakeReq({
      host: 'api.example.com',
      headers: { host: 'other.example.com:8443' },
    });
    expect(getRequestHost(req)).toBe('api.example.com');
  });

  it('matches the header hostname case-insensitively', () => {
    const req = fakeReq({
      host: 'api.example.com',
      headers: { host: 'API.Example.COM:8443' },
    });
    expect(getRequestHost(req)).toBe('API.Example.COM:8443');
  });

  it('handles bracketed IPv6 literals', () => {
    const withPort = fakeReq({ host: '[::1]:3000', headers: { host: '[::1]:3000' } });
    expect(getRequestHost(withPort)).toBe('[::1]:3000');

    const stripped = fakeReq({ host: '[::1]', headers: { host: '[::1]:3000' } });
    expect(getRequestHost(stripped)).toBe('[::1]:3000');

    const noPort = fakeReq({ host: '[::1]', headers: { host: '[::1]' } });
    expect(getRequestHost(noPort)).toBe('[::1]');
  });
});

describe('getRequestOrigin', () => {
  it('composes protocol and host with the recovered port', () => {
    const req = fakeReq({
      host: 'api.example.com',
      headers: { host: 'api.example.com:8443' },
      protocol: 'https',
    });
    expect(getRequestOrigin(req)).toBe('https://api.example.com:8443');
  });
});
