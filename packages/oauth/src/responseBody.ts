import { MAX_RESPONSE_BODY_BYTES, ResponseBodyTooLargeError } from "./errors.js";

/**
 * Read a Fetch `Response` body as UTF-8 text while enforcing a cap on decoded
 * bytes (`limit`, default 1 MiB). Stops reading and cancels the stream as soon
 * as the decoded byte count exceeds `limit`, before buffering or parsing a
 * larger body.
 */
export async function readResponseText(
  response: Response,
  limit: number = MAX_RESPONSE_BODY_BYTES,
): Promise<string> {
  const body = response.body;
  if (body && typeof body.getReader === "function") {
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        if (value) {
          total += value.byteLength;
          if (total > limit) {
            await reader.cancel().catch(() => {});
            throw new ResponseBodyTooLargeError(response.status, limit);
          }
          chunks.push(value);
        }
      }
    } finally {
      try {
        reader.releaseLock();
      } catch {
        // Reader may already be released or stream errored.
      }
    }

    const combined = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      combined.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new TextDecoder().decode(combined);
  }

  // Fallback for test doubles that mock `response.text()` or `response.json()`
  // without providing a `ReadableStream` body.
  if (typeof response.text === "function") {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > limit) {
      throw new ResponseBodyTooLargeError(response.status, limit);
    }
    return text;
  }

  if (typeof response.json === "function") {
    const value = await response.json();
    const text = JSON.stringify(value);
    if (text !== undefined && new TextEncoder().encode(text).byteLength > limit) {
      throw new ResponseBodyTooLargeError(response.status, limit);
    }
    return text ?? "";
  }

  return "";
}

/**
 * Cancel an unread response body stream so the underlying connection can be
 * released without buffering an arbitrarily large payload.
 */
export function discardResponseBody(response: Response): void {
  const body = response.body;
  if (body && typeof body.cancel === "function") {
    void body.cancel().catch(() => {});
  }
}
