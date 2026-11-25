import { OAuthError, ResponseBodyTooLargeError, isPermanentErrorCode } from "./errors.js";
import { readResponseText } from "./responseBody.js";

export async function tokenEndpointError(response: Response, operation: string, bodyText?: string): Promise<OAuthError> {
  const status = response.status;
  const transient = status === 429 || status >= 500;
  let text: string;
  if (bodyText !== undefined) {
    text = bodyText;
  } else {
    try {
      text = await readResponseText(response);
    } catch (e) {
      if (e instanceof ResponseBodyTooLargeError) return e;
      return new OAuthError("invalid_response", `${operation} failed (HTTP ${status})`, undefined, {
        retryable: transient, status,
      });
    }
  }
  let body: Record<string, unknown> | null = null;
  try {
    const parsed: unknown = JSON.parse(text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      body = parsed as Record<string, unknown>;
    }
  } catch {
    // non-JSON: fall through
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
