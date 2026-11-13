import { providesClientAuthentication, requireClientAuthentication, type ApplicationCredential } from './credentials.js';
import { ConfigurationError } from './errors.js';

const base: ApplicationCredential = {
  getAuth: () => null,
  prepareTokenExchangeRequest: async () => ({ subjectToken: 'unused' }),
};
const clientAuthentication = async () => ({ headers: {}, form: {} });
const misconfigured = new ConfigurationError('WebIdentity: clientId is required');

describe('requireClientAuthentication', () => {
  it.each([
    {
      name: 'a credential without clientAuthentication',
      credential: base,
      provides: false,
      error: 'refresh requires a credential that provides clientAuthentication',
    },
    {
      name: 'a credential whose checkClientAuthentication throws',
      credential: { ...base, clientAuthentication, checkClientAuthentication: () => { throw misconfigured; } },
      provides: true,
      error: misconfigured.message,
    },
    {
      name: 'a credential without checkClientAuthentication',
      credential: { ...base, clientAuthentication },
      provides: true,
      error: undefined,
    },
    {
      name: 'a credential whose checkClientAuthentication passes',
      credential: { ...base, clientAuthentication, checkClientAuthentication: () => {} },
      provides: true,
      error: undefined,
    },
  ])('$name', ({ credential, provides, error }) => {
    expect(providesClientAuthentication(credential)).toBe(provides);
    if (error) {
      expect(() => requireClientAuthentication(credential, 'refresh')).toThrow(new ConfigurationError(error));
    } else {
      expect(requireClientAuthentication(credential, 'refresh')).toBe(credential);
    }
  });
});
