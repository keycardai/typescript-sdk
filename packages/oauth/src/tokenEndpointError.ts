import { OAuthError, isPermanentErrorCode } from "./errors.js";

export async function tokenEndpointError(response: Response, operation: string, bodyText?: string): Promise<OAuthError> {
  const status = response.status;
  const transient = status === 429 || status >= 500;
  let body: Record<string, unknown> | null;
  try {
    body = (bodyText === undefined ? await response.json() : JSON.parse(bodyText)) as Record<string, unknown> | null;
  } catch {
    body = null;
  }
  if (typeof body?.error === "string") {
    const errorDescription = typeof body.error_description === "string" ? body.error_description : undefined;
    const reason = typeof body.reason === "string" ? body.reason : undefined;
    const errorUri = typeof body.error_uri === "string" ? body.error_uri : undefined;
    return new OAuthError(body.error, errorDescription ?? body.error, errorUri, {
      errorDescription, reason, retryable: transient || !isPermanentErrorCode(body.error), status,
    });
  }
  return new OAuthError("invalid_response", `${operation} failed (HTTP ${status})`, undefined, {
    retryable: transient, status,
  });
}
