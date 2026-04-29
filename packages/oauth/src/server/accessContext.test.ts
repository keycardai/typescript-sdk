import { AccessContext } from './accessContext.js';
import { ResourceAccessError } from '../errors.js';
import type { TokenResponse } from '../tokenExchange.js';

const TOKEN: TokenResponse = {
  accessToken: 'tok',
  tokenType: 'bearer',
};

describe('AccessContext', () => {
  it('reports success when no errors are set and tokens are present', () => {
    const ctx = new AccessContext();
    ctx.setToken('https://api.example.com', TOKEN);
    expect(ctx.getStatus()).toBe('success');
    expect(ctx.hasErrors()).toBe(false);
  });

  it('access() returns the configured token', () => {
    const ctx = new AccessContext();
    ctx.setToken('https://api.example.com', TOKEN);
    expect(ctx.access('https://api.example.com')).toBe(TOKEN);
  });

  it('access() throws ResourceAccessError on missing resource', () => {
    const ctx = new AccessContext();
    expect(() => ctx.access('https://missing.example.com')).toThrow(ResourceAccessError);
  });

  it('reports partial_error when one resource fails', () => {
    const ctx = new AccessContext();
    ctx.setToken('https://api.example.com', TOKEN);
    ctx.setResourceError('https://other.example.com', { message: 'denied' });
    expect(ctx.getStatus()).toBe('partial_error');
    expect(ctx.hasResourceError('https://other.example.com')).toBe(true);
    expect(ctx.getFailedResources()).toEqual(['https://other.example.com']);
    expect(ctx.getSuccessfulResources()).toEqual(['https://api.example.com']);
  });

  it('reports error when a global error is set', () => {
    const ctx = new AccessContext();
    ctx.setError({ message: 'no auth' });
    expect(ctx.getStatus()).toBe('error');
    expect(ctx.hasError()).toBe(true);
    expect(ctx.getError()).toEqual({ message: 'no auth' });
  });

  it('access() throws on global error even if a resource was set', () => {
    const ctx = new AccessContext();
    ctx.setToken('https://api.example.com', TOKEN);
    ctx.setError({ message: 'no auth' });
    expect(() => ctx.access('https://api.example.com')).toThrow(ResourceAccessError);
  });

  it('setBulkTokens merges resources', () => {
    const ctx = new AccessContext();
    ctx.setBulkTokens({
      'https://a.example.com': TOKEN,
      'https://b.example.com': TOKEN,
    });
    expect(ctx.getSuccessfulResources()).toEqual([
      'https://a.example.com',
      'https://b.example.com',
    ]);
  });

  it('setting a token clears its prior resource error', () => {
    const ctx = new AccessContext();
    ctx.setResourceError('https://api.example.com', { message: 'transient' });
    ctx.setToken('https://api.example.com', TOKEN);
    expect(ctx.hasResourceError('https://api.example.com')).toBe(false);
    expect(ctx.access('https://api.example.com')).toBe(TOKEN);
  });

  it('initial accessTokens are accepted via the constructor', () => {
    const ctx = new AccessContext({ 'https://api.example.com': TOKEN });
    expect(ctx.access('https://api.example.com')).toBe(TOKEN);
    expect(ctx.getStatus()).toBe('success');
  });
});
