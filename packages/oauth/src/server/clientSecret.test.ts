import { ClientSecret } from './clientSecret.js';
import type { ApplicationCredential } from '../credentials.js';

describe('ClientSecret', () => {
  describe('two-arg constructor (legacy)', () => {
    it('returns the configured credentials regardless of issuer', () => {
      const cred = new ClientSecret('alice', 'shh');
      expect(cred.getAuth()).toEqual({ clientId: 'alice', clientSecret: 'shh' });
      expect(cred.getAuth('https://any.keycard.cloud')).toEqual({ clientId: 'alice', clientSecret: 'shh' });
    });
  });

  describe('tuple constructor', () => {
    it('returns the configured credentials regardless of issuer', () => {
      const cred = new ClientSecret(['bob', 'secret']);
      expect(cred.getAuth()).toEqual({ clientId: 'bob', clientSecret: 'secret' });
      expect(cred.getAuth('https://zone-x.keycard.cloud')).toEqual({ clientId: 'bob', clientSecret: 'secret' });
    });
  });

  describe('multi-zone dict constructor (issuer-keyed)', () => {
    const cred = new ClientSecret({
      'https://zone-a.keycard.cloud': ['id-a', 'sec-a'],
      'https://zone-b.keycard.cloud/': ['id-b', 'sec-b'],
    });

    it('routes by issuer URL', () => {
      expect(cred.getAuth('https://zone-a.keycard.cloud')).toEqual({ clientId: 'id-a', clientSecret: 'sec-a' });
      expect(cred.getAuth('https://zone-b.keycard.cloud')).toEqual({ clientId: 'id-b', clientSecret: 'sec-b' });
    });

    it('normalizes trailing slashes on both stored keys and lookups', () => {
      expect(cred.getAuth('https://zone-a.keycard.cloud/')).toEqual({ clientId: 'id-a', clientSecret: 'sec-a' });
      expect(cred.getAuth('https://zone-b.keycard.cloud/')).toEqual({ clientId: 'id-b', clientSecret: 'sec-b' });
    });

    it('fails closed for an unknown issuer', () => {
      expect(cred.getAuth('https://zone-c.keycard.cloud')).toBeNull();
    });

    it('fails closed when issuer is missing', () => {
      expect(cred.getAuth()).toBeNull();
    });

    it('rejects an empty dict', () => {
      expect(() => new ClientSecret({})).toThrow();
    });
  });

  describe('construction validation', () => {
    it('rejects an empty client_id or client_secret (two-arg)', () => {
      expect(() => new ClientSecret('', 'shh')).toThrow(/non-empty/);
      expect(() => new ClientSecret('alice', '')).toThrow(/non-empty/);
    });

    it('rejects an empty client_id or client_secret (tuple)', () => {
      expect(() => new ClientSecret(['', 'secret'])).toThrow(/non-empty/);
      expect(() => new ClientSecret(['bob', ''])).toThrow(/non-empty/);
    });

    it('rejects empty credentials in a multi-zone dict and names the issuer', () => {
      expect(() => new ClientSecret({ 'https://zone-a.keycard.cloud': ['', 'sec-a'] })).toThrow(
        /non-empty.*zone-a/,
      );
      expect(() => new ClientSecret({ 'https://zone-b.keycard.cloud': ['id-b', ''] })).toThrow(/zone-b/);
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
