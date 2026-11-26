import { resolveCredentialType } from "../credentialDiscovery.js";
import type { CredentialEnvironment } from "../credentialDiscovery.js";
import type { ApplicationCredential } from "../credentials.js";
import { ClientSecret } from "./clientSecret.js";
import { WebIdentity } from "./webIdentity.js";
import { DEFAULT_FILE_TOKEN_ENV_VARS, FileTokenSource, WorkloadIdentity } from "./workloadIdentity.js";

export interface DiscoverCredentialOptions {
  /** Environment to inspect instead of the Node.js process environment. */
  env?: CredentialEnvironment;
  /** Stable server name a discovered WebIdentity uses for its key id. */
  webIdentityServerName?: string;
}

/**
 * Constructs the application credential described by the environment.
 * @throws {CredentialDiscoveryError} When the environment does not describe a single usable credential.
 * @throws {WorkloadIdentityConfigurationError} When the selected token file is missing or empty.
 */
export function discoverCredential(
  { env = process.env, webIdentityServerName }: DiscoverCredentialOptions = {},
): ApplicationCredential {
  const resolved = resolveCredentialType(env, { tokenFileEnvVars: DEFAULT_FILE_TOKEN_ENV_VARS });
  switch (resolved.type) {
    case "client_secret":
      return new ClientSecret(resolved.clientId, resolved.clientSecret);
    case "workload_identity":
      return new WorkloadIdentity(new FileTokenSource({ tokenFilePath: resolved.tokenFilePath }),
        resolved.clientId ? { clientId: resolved.clientId } : undefined);
    case "web_identity":
      return new WebIdentity({
        ...(resolved.storageDir === undefined ? {} : { storageDir: resolved.storageDir }),
        ...(webIdentityServerName === undefined ? {} : { serverName: webIdentityServerName }),
      });
  }
}
