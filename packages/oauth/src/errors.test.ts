import { DeviceGrantError, PERMANENT_ERROR_CODES, isPermanentErrorCode } from './errors.js';

describe('PERMANENT_ERROR_CODES', () => {
  it('lists the permanent codes and cannot be changed', () => {
    expect(PERMANENT_ERROR_CODES).toEqual(['access_denied', 'expired_token', 'insufficient_authorization', 'invalid_client']);
    expect(Object.isFrozen(PERMANENT_ERROR_CODES)).toBe(true);
  });

  // A consumer that has only the code classifies it by membership. That must
  // agree with the typed error's `retryable`.
  it.each([...PERMANENT_ERROR_CODES, 'authorization_pending', 'server_error', 'invalid_response'])(
    'agrees with DeviceGrantError.retryable for %s',
    (code) => {
      expect(isPermanentErrorCode(code)).toBe(PERMANENT_ERROR_CODES.includes(code));
      expect(new DeviceGrantError(code).retryable).toBe(!isPermanentErrorCode(code));
    },
  );
});
