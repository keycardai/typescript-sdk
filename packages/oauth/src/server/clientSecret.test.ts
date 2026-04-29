import { ClientSecret } from './clientSecret.js';
import type { ApplicationCredential } from '../credentials.js';

describe('ClientSecret', () => {
  describe('two-arg constructor (legacy)', () => {
    it('returns the configured credentials regardless of zoneId', () => {
      const cred = new ClientSecret('alice', 'shh');
      expect(cred.getAuth()).toEqual({ clientId: 'alice', clientSecret: 'shh' });
      expect(cred.getAuth('any-zone')).toEqual({ clientId: 'alice', clientSecret: 'shh' });
    });
  });

  describe('tuple constructor', () => {
    it('returns the configured credentials regardless of zoneId', () => {
      const cred = new ClientSecret(['bob', 'secret']);
      expect(cred.getAuth()).toEqual({ clientId: 'bob', clientSecret: 'secret' });
      expect(cred.getAuth('zone-x')).toEqual({ clientId: 'bob', clientSecret: 'secret' });
    });
  });

  describe('multi-zone dict constructor', () => {
    const cred = new ClientSecret({
      'zone-a': ['id-a', 'sec-a'],
      'zone-b': ['id-b', 'sec-b'],
    });

    it('routes by zoneId', () => {
      expect(cred.getAuth('zone-a')).toEqual({ clientId: 'id-a', clientSecret: 'sec-a' });
      expect(cred.getAuth('zone-b')).toEqual({ clientId: 'id-b', clientSecret: 'sec-b' });
    });

    it('returns null for an unknown zone', () => {
      expect(cred.getAuth('zone-c')).toBeNull();
    });

    it('returns null when zoneId is missing', () => {
      expect(cred.getAuth()).toBeNull();
    });

    it('rejects an empty dict', () => {
      expect(() => new ClientSecret({})).toThrow();
    });
  });

  describe('prepareTokenExchangeRequest', () => {
    it('emits an access_token subject token type', async () => {
      const cred = new ClientSecret('alice', 'shh');
      const req = await cred.prepareTokenExchangeRequest('subj', 'https://api.example.com');
      expect(req.subjectTokenType).toBe('urn:ietf:params:oauth:token-type:access_token');
      expect(req.subjectToken).toBe('subj');
      expect(req.resource).toBe('https://api.example.com');
    });
  });

  describe('ApplicationCredential conformance', () => {
    it('compiles as ApplicationCredential', () => {
      const cred: ApplicationCredential = new ClientSecret('alice', 'shh');
      expect(typeof cred.getAuth).toBe('function');
      expect(typeof cred.prepareTokenExchangeRequest).toBe('function');
    });
  });
});
