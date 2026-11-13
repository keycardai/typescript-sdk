/**
 * The HTTP Basic `Authorization` header value that authenticates a client
 * (RFC 6749 §2.3.1). The client ID and secret are each encoded with
 * `encodeURIComponent` before base64. Letters, digits and `-_.!~*'()` are
 * kept. Every other byte of the UTF-8 encoding becomes `%HH`, and a space
 * becomes `%20`. Each half decodes to the original value with an RFC 6749
 * Appendix B form decoder, and with the `decodeURIComponent` that Keycard
 * zones use.
 */
export function basicAuthorization(clientId: string, clientSecret: string): string {
  return `Basic ${btoa(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`)}`;
}
