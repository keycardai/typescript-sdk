import { PERMANENT_ERROR_CODES, isPermanentErrorCode } from './errors.js';

describe('PERMANENT_ERROR_CODES', () => {
  it('lists the permanent codes and cannot be changed', () => {
    expect(PERMANENT_ERROR_CODES).toEqual(['access_denied', 'expired_token', 'insufficient_authorization', 'invalid_client']);
    expect(Object.isFrozen(PERMANENT_ERROR_CODES)).toBe(true);
  });

  it.each([
    ...PERMANENT_ERROR_CODES.map((code) => ({ code, permanent: true })),
    { code: 'invalid_grant', permanent: false },
    { code: 'server_error', permanent: false },
    { code: 'invalid_response', permanent: false },
  ])('isPermanentErrorCode($code) is $permanent', ({ code, permanent }) => {
    expect(isPermanentErrorCode(code)).toBe(permanent);
  });
});
