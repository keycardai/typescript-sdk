import { buildSubstituteUserToken } from './substituteUser.js';

function decodeBase64Url(input: string): string {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(padded, 'base64').toString('utf-8');
}

describe('buildSubstituteUserToken', () => {
  it('produces a three-segment JWT with empty signature', () => {
    const token = buildSubstituteUserToken('user@example.com');
    const parts = token.split('.');
    expect(parts.length).toBe(3);
    expect(parts[2]).toBe('');
  });

  it('encodes the substitute-user header and payload', () => {
    const token = buildSubstituteUserToken('user@example.com');
    const [headerB64, payloadB64] = token.split('.');
    expect(JSON.parse(decodeBase64Url(headerB64))).toEqual({ typ: 'vnd.kc.su+jwt', alg: 'none' });
    expect(JSON.parse(decodeBase64Url(payloadB64))).toEqual({ sub: 'user@example.com' });
  });

  it('throws on empty identifier', () => {
    expect(() => buildSubstituteUserToken('')).toThrow(/identifier is required/);
  });
});
