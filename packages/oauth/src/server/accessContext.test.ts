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

  it('access() carries missing_token context on the thrown error', () => {
    const ctx = new AccessContext();
    ctx.setToken('https://api.example.com', TOKEN);
    try {
      ctx.access('https://missing.example.com');
      throw new Error('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(ResourceAccessError);
      const err = e as ResourceAccessError;
      expect(err.errorType).toBe('missing_token');
      expect(err.resource).toBe('https://missing.example.com');
      expect(err.availableResources).toEqual(['https://api.example.com']);
      expect(err.errorDetails).toBeNull();
      expect(err.message).toContain("'https://missing.example.com'");
      expect(err.message).toContain('https://api.example.com');
    }
  });

  it('access() carries resource_error context on the thrown error', () => {
    const ctx = new AccessContext();
    const detail = { message: 'denied by AS', code: 'access_denied' };
    ctx.setResourceError('https://api.example.com', detail);
    try {
      ctx.access('https://api.example.com');
      throw new Error('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(ResourceAccessError);
      const err = e as ResourceAccessError;
      expect(err.errorType).toBe('resource_error');
      expect(err.resource).toBe('https://api.example.com');
      expect(err.errorDetails).toEqual(detail);
      expect(err.message).toContain('denied by AS');
    }
  });

  it('access() carries global_error context on the thrown error', () => {
    const ctx = new AccessContext();
    const detail = { message: 'token exchange failed' };
    ctx.setError(detail);
    try {
      ctx.access('https://api.example.com');
      throw new Error('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(ResourceAccessError);
      const err = e as ResourceAccessError;
      expect(err.errorType).toBe('global_error');
      expect(err.resource).toBe('https://api.example.com');
      expect(err.errorDetails).toEqual(detail);
      expect(err.message).toContain('token exchange failed');
    }
  });

  it('getResourceError returns the stored detail or null', () => {
    const ctx = new AccessContext();
    ctx.setResourceError('https://api.example.com', { message: 'transient' });
    expect(ctx.getResourceError('https://api.example.com')).toEqual({ message: 'transient' });
    expect(ctx.getResourceError('https://other.example.com')).toBeNull();
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

  describe('merge', () => {
    it('accumulates tokens and resource errors from another context', () => {
      const ctx = new AccessContext({ 'https://a.example.com': TOKEN });
      ctx.setResourceError('https://c.example.com', { message: 'still failing' });

      const other = new AccessContext({ 'https://b.example.com': TOKEN });
      other.setResourceError('https://d.example.com', { message: 'new failure' });

      ctx.merge(other);

      expect(ctx.access('https://a.example.com')).toBe(TOKEN);
      expect(ctx.access('https://b.example.com')).toBe(TOKEN);
      expect(ctx.hasResourceError('https://c.example.com')).toBe(true);
      expect(ctx.hasResourceError('https://d.example.com')).toBe(true);
      expect(ctx.getStatus()).toBe('partial_error');
    });

    it('later results win per resource: a merged token clears a prior error and vice versa', () => {
      const ctx = new AccessContext({ 'https://a.example.com': TOKEN });
      ctx.setResourceError('https://b.example.com', { message: 'old failure' });

      const other = new AccessContext({ 'https://b.example.com': TOKEN });
      other.setResourceError('https://a.example.com', { message: 'new failure' });

      ctx.merge(other);

      expect(ctx.access('https://b.example.com')).toBe(TOKEN);
      expect(ctx.hasResourceError('https://a.example.com')).toBe(true);
    });

    it('a global error on the merged context overwrites, but absence preserves', () => {
      const ctx = new AccessContext();
      ctx.setError({ message: 'existing' });
      ctx.merge(new AccessContext());
      expect(ctx.getError()).toEqual({ message: 'existing' });

      const other = new AccessContext();
      other.setError({ message: 'incoming' });
      ctx.merge(other);
      expect(ctx.getError()).toEqual({ message: 'incoming' });
    });
  });
});
