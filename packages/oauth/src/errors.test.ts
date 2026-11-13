import { DeviceGrantError, PERMANENT_ERROR_CODES, isPermanentErrorCode } from './errors.js';

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

  // Classifying a code by membership in PERMANENT_ERROR_CODES must match
  // DeviceGrantError.retryable.
  it.each([...PERMANENT_ERROR_CODES, 'authorization_pending', 'server_error', 'invalid_response'])(
    'agrees with DeviceGrantError.retryable for %s',
    (code) => {
      expect(new DeviceGrantError(code).retryable).toBe(!isPermanentErrorCode(code));
    },
  );
});
