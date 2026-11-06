/** Default timeout for one request to the authorization server. */
export const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;

/**
 * Signal for one request to the zone: the caller's `signal`, if any, combined
 * with a timeout of `timeoutMs` (default 10 seconds), so a request can never
 * wait forever while a caller's own abort still wins. `timeoutMs: 0` disables
 * the timeout and uses the caller's signal alone.
 */
export function requestSignal(
  signal: AbortSignal | undefined,
  timeoutMs: number = DEFAULT_REQUEST_TIMEOUT_MS,
): AbortSignal | undefined {
  if (!(timeoutMs > 0)) return signal;
  const timeout = AbortSignal.timeout(timeoutMs);
  if (!signal) return timeout;
  return anySignal([signal, timeout]);
}

function anySignal(signals: AbortSignal[]): AbortSignal {
  const any = (AbortSignal as unknown as { any?: (s: AbortSignal[]) => AbortSignal }).any;
  if (typeof any === "function") return any.call(AbortSignal, signals);
  const controller = new AbortController();
  for (const s of signals) {
    if (s.aborted) {
      controller.abort(s.reason);
      break;
    }
    s.addEventListener("abort", () => controller.abort(s.reason), { once: true });
  }
  return controller.signal;
}
