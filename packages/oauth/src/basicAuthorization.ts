/**
 * The HTTP Basic `Authorization` header value that authenticates a client
 * (RFC 6749 §2.3.1). The client ID and secret are percent-encoded with
 * `encodeURIComponent` before base64. It never emits `+`, so a server that
 * form-decodes and a server that only percent-decodes read the same values.
 */
export function basicAuthorization(clientId: string, clientSecret: string): string {
  return `Basic ${btoa(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`)}`;
}
