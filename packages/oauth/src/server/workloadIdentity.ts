import * as fs from "node:fs";
import type { ApplicationCredential } from "../credentials.js";
import type { TokenExchangeRequest } from "../tokenExchange.js";

/**
 * Source identifiers carried on WorkloadIdentityConfigurationError and
 * WorkloadIdentityRuntimeError, for branching on which token source failed.
 */
export const WORKLOAD_IDENTITY_SOURCE_FILE = "file";
export const WORKLOAD_IDENTITY_SOURCE_GCP_METADATA = "gcp-metadata";
export const WORKLOAD_IDENTITY_SOURCE_FLY = "fly";
export const WORKLOAD_IDENTITY_SOURCE_CUSTOM = "custom";

/**
 * A workload identity credential or token source was misconfigured at
 * construction: a missing or empty token file, no discovery environment
 * variable set, a missing required audience, or an invalid source.
 *
 * `source` identifies the token source ("file", "gcp-metadata", "fly");
 * undefined when the fault is in the credential itself. The underlying cause,
 * when any, is on `cause`.
 */
export class WorkloadIdentityConfigurationError extends Error {
  readonly source?: string;
  readonly cause?: unknown;

  constructor(message: string, options?: { source?: string; cause?: unknown }) {
    super(message);
    this.name = "WorkloadIdentityConfigurationError";
    this.source = options?.source;
    this.cause = options?.cause;
  }
}

/**
 * The subject token could not be obtained at request time: the token file was
 * rotated away or emptied after construction, or the platform endpoint was
 * unreachable. Distinct from WorkloadIdentityConfigurationError, which is a
 * construction-time fault.
 *
 * `source` identifies the token source ("file", "gcp-metadata", "fly", or
 * "custom" for a source whose error is not one of this module's typed
 * errors). The underlying cause, when any, is on `cause`.
 */
export class WorkloadIdentityRuntimeError extends Error {
  readonly source?: string;
  readonly cause?: unknown;

  constructor(message: string, options?: { source?: string; cause?: unknown }) {
    super(message);
    this.name = "WorkloadIdentityRuntimeError";
    this.source = options?.source;
    this.cause = options?.cause;
  }
}

/**
 * Supplies a platform-signed OIDC token for use as a client assertion during
 * token exchange. The only per-platform piece of a workload identity
 * credential: {@link FileTokenSource} covers platforms that project the token
 * to a file (EKS, AKS, Kubernetes projected service-account tokens),
 * {@link GCPMetadataTokenSource} covers platforms that serve it from the GCP
 * metadata endpoint (GKE, GCE, Cloud Run), {@link FlyTokenSource} covers Fly
 * Machines, and any bare function returning the token is accepted as a source.
 *
 * `identityToken` is called on every token exchange. Implementations must
 * return the current token; platforms rotate these tokens, so returning a
 * stale cached value risks an expired assertion.
 */
export interface IdentityTokenSource {
  identityToken(): Promise<string>;
}

/** A bare function accepted anywhere a IdentityTokenSource is. */
export type IdentityTokenFetcher = () => Promise<string> | string;

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
        { source: WORKLOAD_IDENTITY_SOURCE_GCP_METADATA },
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
                  { source: WORKLOAD_IDENTITY_SOURCE_FLY },
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
            { source: WORKLOAD_IDENTITY_SOURCE_FLY, cause: error },
          ),
        );
      });
      request.on("timeout", () => {
        request.destroy(
          new WorkloadIdentityRuntimeError(
            `Machines API request timed out after ${FLY_TIMEOUT_MS}ms`,
            { source: WORKLOAD_IDENTITY_SOURCE_FLY },
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
   * ID of the Keycard application credential this workload authenticates as,
   * sent as the `client_id` form parameter alongside the client assertion.
   * Token-federation application credentials are resolved by this ID, so
   * they require it; legacy token credentials are resolved by the
   * assertion's subject and do not use it.
   */
  clientId?: string;
}

/**
 * Workload identity credential using a platform-signed OIDC token obtained
 * from a {@link IdentityTokenSource}. On every token exchange it fetches the
 * current token from the source and attaches it as a jwt-bearer client
 * assertion. It holds no shared secret and never caches the token across
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
    if (source == null) {
      throw new WorkloadIdentityConfigurationError("identity token source must not be null");
    }
    if (
      typeof source !== "function" &&
      typeof (source as IdentityTokenSource).identityToken !== "function"
    ) {
      throw new WorkloadIdentityConfigurationError(
        "identity token source must provide identityToken() or be a function",
      );
    }
    this.#source = source;
    this.#clientId = options?.clientId;
  }

  getAuth(): null {
    return null;
  }

  async prepareTokenExchangeRequest(
    subjectToken: string,
    resource: string,
  ): Promise<TokenExchangeRequest> {
    const assertion = await this.#fetchIdentityToken();

    return {
      subjectToken,
      resource,
      subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
      clientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      clientAssertion: assertion,
      clientId: this.#clientId,
    };
  }

  async #fetchIdentityToken(): Promise<string> {
    let token: string;
    try {
      token =
        typeof this.#source === "function"
          ? await this.#source()
          : await this.#source.identityToken();
    } catch (error) {
      if (
        error instanceof WorkloadIdentityConfigurationError ||
        error instanceof WorkloadIdentityRuntimeError
      ) {
        throw error;
      }
      throw new WorkloadIdentityRuntimeError("Error fetching identity token", {
        source: WORKLOAD_IDENTITY_SOURCE_CUSTOM,
        cause: error,
      });
    }
    if (typeof token !== "string" || !token.trim()) {
      throw new WorkloadIdentityRuntimeError("Identity token source returned an empty token", {
        source: WORKLOAD_IDENTITY_SOURCE_CUSTOM,
      });
    }
    return token;
  }
}
