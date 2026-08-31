/**
 * The part of eve's tool context this helper needs.
 *
 * Declared structurally rather than imported so nothing here loads eve at
 * runtime. `ctx.requireAuth` never returns: it aborts the tool call and hands
 * the connection's authorization strategy back to the runtime.
 */
export interface RequireAuthContext<Provider> {
  requireAuth(provider: Provider, options?: { readonly reason?: string }): never;
}

/**
 * Maps a provider's rejection of the current credential onto
 * `ctx.requireAuth`.
 *
 * A token that verified when it was minted can still be refused downstream
 * after a revocation or a scope change. eve treats `requireAuth` as the signal
 * to drop its cached bearer, call the strategy's `evict`, and re-run
 * authorization, so an authored tool wrapping a `fetch` only needs to forward
 * the status:
 *
 * ```ts
 * const response = await fetch(url, { headers });
 * requireAuthOnUnauthorized(response, ctx, auth);
 * ```
 *
 * Returns for every other status, so the tool keeps handling its own errors.
 */
export function requireAuthOnUnauthorized<Provider>(
  response: { readonly status: number },
  ctx: RequireAuthContext<Provider>,
  provider: Provider,
  options?: { readonly reason?: string },
): void {
  if (response.status !== 401 && response.status !== 403) return;
  ctx.requireAuth(provider, {
    reason:
      options?.reason ??
      `The provider rejected the connection credential with ${response.status}.`,
  });
}
