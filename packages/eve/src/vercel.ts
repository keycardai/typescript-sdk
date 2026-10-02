import {
  WorkloadIdentity,
  WorkloadIdentityRuntimeError,
  type IdentityTokenFetcher,
  type WorkloadIdentityOptions,
} from "@keycardai/oauth/server";

/** The `source` a missing Vercel OIDC token reports on its runtime error. */
export const VERCEL_OIDC_SOURCE = "vercel-oidc";

/**
 * The agent's Keycard credential on Vercel: the deployment's OIDC token, sent
 * as a jwt-bearer client assertion on every zone request.
 *
 * The token is read per request, never cached: in a function it comes from
 * the request's `x-vercel-oidc-token` header, and locally from
 * `VERCEL_OIDC_TOKEN` (written by `vercel env pull`), which `@vercel/oidc`
 * refreshes through the Vercel CLI when it has expired. The deployment holds
 * no secret.
 *
 * This is the credential every connection factory uses when none is given.
 * Call it yourself only to set `clientId`, which a token-federation
 * application credential is resolved by; a credential resolved by the OIDC
 * subject takes none.
 */
export function vercelWorkloadIdentity(options?: WorkloadIdentityOptions): WorkloadIdentity {
  return new WorkloadIdentity(vercelOidcTokenSource(loadVercelOidcToken), options);
}

let defaultCredential: WorkloadIdentity | undefined;

/** One shared default credential per process, built on first use. */
export function defaultApplicationCredential(): WorkloadIdentity {
  defaultCredential ??= vercelWorkloadIdentity();
  return defaultCredential;
}

/**
 * Wraps a token fetcher so a missing token names its fixes instead of
 * surfacing `@vercel/oidc`'s header message on a host that has no headers.
 *
 * @internal Exported for tests, which inject the fetcher.
 */
export function vercelOidcTokenSource(fetchToken: IdentityTokenFetcher): IdentityTokenFetcher {
  return async () => {
    try {
      return await fetchToken();
    } catch (cause) {
      throw new WorkloadIdentityRuntimeError(
        "No Vercel OIDC token is available, so the agent cannot authenticate to the Keycard " +
          "zone. On Vercel, enable OIDC federation for the project; locally, run " +
          "`vercel env pull` to refresh VERCEL_OIDC_TOKEN; on any other host, pass " +
          "`applicationCredential`. Vercel said: " +
          (cause instanceof Error ? cause.message : String(cause)),
        { source: VERCEL_OIDC_SOURCE, cause },
      );
    }
  };
}

/** Loaded on first use, so an agent that passes its own credential never imports it. */
async function loadVercelOidcToken(): Promise<string> {
  const { getVercelOidcToken } = await import("@vercel/oidc");
  return getVercelOidcToken();
}
