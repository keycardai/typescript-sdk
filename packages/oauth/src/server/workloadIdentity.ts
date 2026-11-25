import * as fs from "node:fs";
import type { ApplicationCredential, ClientAuthentication } from "../credentials.js";
import { ConfigurationError } from "../errors.js";
import {
  fetchIdentityToken,
  validateIdentityTokenSource,
  WorkloadIdentityConfigurationError,
  WorkloadIdentityRuntimeError,
  type IdentityTokenFetcher,
  type IdentityTokenSource,
} from "../identityTokenSource.js";
import type { TokenExchangeRequest } from "../tokenExchange.js";

export {
  WORKLOAD_IDENTITY_SOURCE_CUSTOM,
  WorkloadIdentityConfigurationError,
  WorkloadIdentityRuntimeError,
} from "../identityTokenSource.js";
export type { IdentityTokenFetcher, IdentityTokenSource } from "../identityTokenSource.js";

/**
 * Source identifiers carried on WorkloadIdentityConfigurationError and
 * WorkloadIdentityRuntimeError, for branching on which token source failed.
 */
export const WORKLOAD_IDENTITY_SOURCE_FILE = "file";
export const WORKLOAD_IDENTITY_SOURCE_GCP_METADATA = "gcp-metadata";
export const WORKLOAD_IDENTITY_SOURCE_FLY = "fly";

export const DEFAULT_FILE_TOKEN_ENV_VARS = [
  "KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
  "AWS_WEB_IDENTITY_TOKEN_FILE",
  "AZURE_FEDERATED_TOKEN_FILE",
];

export interface FileTokenSourceOptions {
  /** Explicit token file path, skipping env-var discovery. */
  tokenFilePath?: string;
  /** An environment variable to consult first during discovery. */
  envVarName?: string;
}

/** @internal Shared by FileTokenSource and the deprecated EKSWorkloadIdentity. */
export function resolveTokenFilePath(
  discoveryEnvVars: string[],
  options?: FileTokenSourceOptions,
): string {
  if (options?.tokenFilePath) {
    return options.tokenFilePath;
  }
  const envNames = options?.envVarName
    ? [options.envVarName, ...discoveryEnvVars]
    : discoveryEnvVars;
  const found = envNames.find((name) => process.env[name]);
  if (!found || !process.env[found]) {
    throw new WorkloadIdentityConfigurationError(
      `Could not find token file path in environment variables; checked: ${envNames.join(", ")}`,
      { source: WORKLOAD_IDENTITY_SOURCE_FILE },
    );
  }
  return process.env[found] as string;
}

function readTokenFile(
  tokenFilePath: string,
  errorClass:
    | typeof WorkloadIdentityConfigurationError
    | typeof WorkloadIdentityRuntimeError,
): string {
  let contents: string;
  try {
    contents = fs.readFileSync(tokenFilePath, "utf-8");
  } catch (error) {
    throw new errorClass(`Error reading token file: ${tokenFilePath}`, {
      source: WORKLOAD_IDENTITY_SOURCE_FILE,
      cause: error,
    });
  }
  const token = contents.trim();
  if (!token) {
    throw new errorClass(`Token file is empty: ${tokenFilePath}`, {
      source: WORKLOAD_IDENTITY_SOURCE_FILE,
    });
  }
  return token;
}

/**
 * Reads a platform-projected OIDC token from a mounted file, fresh on every
 * call (platforms rotate projected tokens). Covers EKS pod identity, AKS
 * workload identity, any Kubernetes projected service-account token, and CI
 * providers that write the token to a file.
 *
 * When no explicit path is given, the path is discovered from the first set
 * environment variable: the variable named by `envVarName` when given, then
 * KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE, AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE,
 * AWS_WEB_IDENTITY_TOKEN_FILE, and AZURE_FEDERATED_TOKEN_FILE.
 *
 * **Requires Node.js.** Validates at construction that the resolved file
 * exists and is non-empty.
 */
export class FileTokenSource implements IdentityTokenSource {
  #tokenFilePath: string;

  constructor(options?: FileTokenSourceOptions) {
    this.#tokenFilePath = resolveTokenFilePath(DEFAULT_FILE_TOKEN_ENV_VARS, options);
    readTokenFile(this.#tokenFilePath, WorkloadIdentityConfigurationError);
  }

  /** Re-reads the token file and returns its trimmed contents. */
  async identityToken(): Promise<string> {
    return readTokenFile(this.#tokenFilePath, WorkloadIdentityRuntimeError);
  }
}

export interface GCPMetadataTokenSourceOptions {
  /** The token audience, typically the Keycard zone URL. Required. */
  audience: string;
  /** Metadata server base URL override (for testing). */
  metadataUrl?: string;
  /** Per-call deadline in milliseconds. */
  timeoutMs?: number;
}

const DEFAULT_GCP_METADATA_URL = "http://metadata.google.internal";
const DEFAULT_GCP_TIMEOUT_MS = 5000;
const GCP_IDENTITY_PATH = "/computeMetadata/v1/instance/service-accounts/default/identity";

/**
 * Fetches an OIDC identity token for the default service account from the
 * GCP metadata server. Covers GKE, GCE, and Cloud Run.
 */
export class GCPMetadataTokenSource implements IdentityTokenSource {
  #audience: string;
  #metadataUrl: string;
  #timeoutMs: number;

  constructor(options: GCPMetadataTokenSourceOptions) {
    if (!options.audience || !options.audience.trim()) {
      throw new WorkloadIdentityConfigurationError("audience must not be empty", {
        source: WORKLOAD_IDENTITY_SOURCE_GCP_METADATA,
      });
    }
    this.#audience = options.audience;
    this.#metadataUrl = (options.metadataUrl ?? DEFAULT_GCP_METADATA_URL).replace(/\/$/, "");
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_GCP_TIMEOUT_MS;
  }

  /** Requests a GCP-signed OIDC JWT from the metadata server. */
  async identityToken(): Promise<string> {
    const url =
      `${this.#metadataUrl}${GCP_IDENTITY_PATH}` +
      `?audience=${encodeURIComponent(this.#audience)}&format=full`;

    let response: Response;
    let body: string;
    try {
      response = await fetch(url, {
        headers: { "Metadata-Flavor": "Google" },
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
      body = await response.text();
    } catch (error) {
      throw new WorkloadIdentityRuntimeError(
        `Error calling metadata server at ${this.#metadataUrl} (is this running on GCP?)`,
        { source: WORKLOAD_IDENTITY_SOURCE_GCP_METADATA, cause: error },
      );
    }

    if (!response.ok) {
      throw new WorkloadIdentityRuntimeError(
        `Metadata server returned status ${response.status}`,
        {
          source: WORKLOAD_IDENTITY_SOURCE_GCP_METADATA,
          retryable: response.status >= 500 && response.status < 600,
        },
      );
    }
    const token = body.trim();
    if (!token) {
      throw new WorkloadIdentityRuntimeError("Metadata server returned an empty token", {
        source: WORKLOAD_IDENTITY_SOURCE_GCP_METADATA,
      });
    }
    return token;
  }
}

export interface FlyTokenSourceOptions {
  /** The token audience claim, typically the Keycard zone URL. */
  audience?: string;
  /** Machines API socket path override (default /.fly/api). */
  socketPath?: string;
}

const DEFAULT_FLY_SOCKET_PATH = "/.fly/api";
const FLY_TOKEN_PATH = "/v1/tokens/oidc";
const FLY_TIMEOUT_MS = 5000;

/**
 * Fetches an OIDC token from the Fly.io Machines API over the local Unix
 * socket. Covers workloads running on Fly Machines.
 *
 * **Requires Node.js** (Unix domain sockets). The socket is not probed at
 * construction; an unreachable Machines API surfaces as a
 * WorkloadIdentityRuntimeError at the first fetch.
 */
export class FlyTokenSource implements IdentityTokenSource {
  #audience?: string;
  #socketPath: string;

  constructor(options?: FlyTokenSourceOptions) {
    this.#audience = options?.audience;
    this.#socketPath = options?.socketPath ?? DEFAULT_FLY_SOCKET_PATH;
  }

  /** Requests a Fly-signed OIDC JWT from the Machines API. */
  async identityToken(): Promise<string> {
    const http = await import("node:http");
    const payload = JSON.stringify(this.#audience ? { aud: this.#audience } : {});

    return new Promise<string>((resolve, reject) => {
      const request = http.request(
        {
          socketPath: this.#socketPath,
          path: FLY_TOKEN_PATH,
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(payload),
          },
          timeout: FLY_TIMEOUT_MS,
        },
        (response) => {
          const chunks: Buffer[] = [];
          response.on("data", (chunk: Buffer) => chunks.push(chunk));
          response.on("end", () => {
            if (response.statusCode !== 200) {
              reject(
                new WorkloadIdentityRuntimeError(
                  `Machines API returned status ${response.statusCode}`,
                  {
                    source: WORKLOAD_IDENTITY_SOURCE_FLY,
                    retryable: response.statusCode !== undefined && response.statusCode >= 500 && response.statusCode < 600,
                  },
                ),
              );
              return;
            }
            const token = Buffer.concat(chunks).toString("utf-8").trim();
            if (!token) {
              reject(
                new WorkloadIdentityRuntimeError("Machines API returned an empty token", {
                  source: WORKLOAD_IDENTITY_SOURCE_FLY,
                }),
              );
              return;
            }
            resolve(token);
          });
        },
      );
      request.on("error", (error) => {
        if (error instanceof WorkloadIdentityRuntimeError) {
          reject(error);
          return;
        }
        reject(
          new WorkloadIdentityRuntimeError(
            `Error calling Machines API socket ${this.#socketPath} (is this running on a Fly Machine?)`,
            { source: WORKLOAD_IDENTITY_SOURCE_FLY, cause: error, retryable: true },
          ),
        );
      });
      request.on("timeout", () => {
        request.destroy(
          new WorkloadIdentityRuntimeError(
            `Machines API request timed out after ${FLY_TIMEOUT_MS}ms`,
            { source: WORKLOAD_IDENTITY_SOURCE_FLY, retryable: true },
          ),
        );
      });
      request.write(payload);
      request.end();
    });
  }
}

export interface WorkloadIdentityOptions {
  /**
   * Public ID of the Keycard application credential this workload
   * authenticates as, sent as the `client_id` form parameter alongside the
   * client assertion on every grant. A v2 token credential is resolved by
   * this ID and requires it, as do the interactive grants. A v1 token
   * credential (deprecated) is resolved by the assertion's issuer and
   * subject and rejects it.
   */
  clientId?: string;
}

/**
 * Workload identity credential using a platform-signed OIDC token obtained
 * from a {@link IdentityTokenSource}. On every token request, whatever the
 * grant, it fetches the current token from the source and attaches it as a
 * jwt-bearer client assertion. It holds no shared secret and never caches the token across
 * requests.
 *
 * @example
 * // EKS / AKS / Kubernetes projected token (path discovered from env)
 * const credential = new WorkloadIdentity(new FileTokenSource());
 *
 * // GKE / GCE / Cloud Run
 * const credential = new WorkloadIdentity(
 *   new GCPMetadataTokenSource({ audience: "https://zone.keycard.cloud" }),
 * );
 *
 * // Custom fetch
 * const credential = new WorkloadIdentity(() => fetchMyToken());
 */
export class WorkloadIdentity implements ApplicationCredential {
  #source: IdentityTokenSource | IdentityTokenFetcher;
  #clientId?: string;

  constructor(
    source: IdentityTokenSource | IdentityTokenFetcher,
    options?: WorkloadIdentityOptions,
  ) {
    validateIdentityTokenSource(source);
    this.#source = source;
    this.#clientId = options?.clientId;
  }

  /** The configured client ID, if any. */
  get clientId(): string | undefined {
    return this.#clientId;
  }

  getAuth(): null {
    return null;
  }

  async prepareTokenExchangeRequest(
    subjectToken: string,
    resource: string,
  ): Promise<TokenExchangeRequest> {
    const assertion = await fetchIdentityToken(this.#source, this);

    return {
      subjectToken,
      resource,
      subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
      clientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      clientAssertion: assertion,
      clientId: this.#clientId,
    };
  }

  /**
   * Fetches the current token from the source and returns it as
   * `client_assertion`, with `client_assertion_type` and, when configured,
   * `client_id`. `headers` is empty. Typed workload identity errors pass
   * through, and other source failures surface as workload identity runtime errors.
   */
  async clientAuthentication(_issuer: string, _endpoint: string): Promise<ClientAuthentication> {
    const form: Record<string, string> = {
      client_assertion: await fetchIdentityToken(this.#source, this),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    };
    if (this.#clientId) form.client_id = this.#clientId;
    return { headers: {}, form };
  }

  /**
   * Throws `ConfigurationError` when `clientId` is not set. The interactive
   * grants (authorization code, refresh, device) need a v2 token credential,
   * which the zone resolves by `client_id`.
   */
  checkClientAuthentication(): void {
    if (!this.#clientId) {
      throw new ConfigurationError(
        "WorkloadIdentity: clientId is required for interactive grants (the public ID of a v2 token credential)",
      );
    }
  }
}
