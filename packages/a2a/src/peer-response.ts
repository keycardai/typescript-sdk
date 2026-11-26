import { ResponseBodyTooLargeError } from "@keycardai/oauth";

const DEFAULT_PEER_RESPONSE_BYTES = 64 * 1024 * 1024;

class InvocationResponseTooLargeError extends ResponseBodyTooLargeError {
  override readonly retryable = false;
}

export function peerResponseLimit(limit = DEFAULT_PEER_RESPONSE_BYTES): number {
  if (!Number.isSafeInteger(limit) || limit <= 0) {
    throw new RangeError("maxPeerResponseBytes must be a positive safe integer");
  }
  return limit;
}

export function boundedPeerFetch(limit: number, invocation = false): typeof fetch {
  return async (input, init) => {
    const response = await fetch(input, init);
    if (!response.body) return response;

    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > limit) {
          void reader.cancel().catch(() => {});
          const ErrorType = invocation && response.ok
            ? InvocationResponseTooLargeError
            : ResponseBodyTooLargeError;
          throw new ErrorType(response.status, limit);
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }

    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(chunk);
        controller.close();
      },
    });
    return new Response(body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  };
}
