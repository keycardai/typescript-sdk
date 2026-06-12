import { existsSync } from "node:fs";
import type { ApplicationCredential } from "../credentials.js";
import type { TokenExchangeRequest } from "../tokenExchange.js";
import { PrivateKeyManager, FilePrivateKeyStorage } from "./privateKey.js";
import type { PrivateKeyStorage } from "./privateKey.js";

export type { PrivateKeyStorage } from "./privateKey.js";

const DEFAULT_STORAGE_DIR = "./server_keys";
const LEGACY_STORAGE_DIR = "./mcp_keys";

/**
 * Prefer `./server_keys`. Fall back to the pre-extraction `./mcp_keys` when it
 * exists and `./server_keys` does not, so a deployment that relied on the
 * implicit default keeps its keys after upgrade.
 */
function resolveDefaultStorageDir(): string {
  try {
    if (!existsSync(DEFAULT_STORAGE_DIR) && existsSync(LEGACY_STORAGE_DIR)) {
      return LEGACY_STORAGE_DIR;
    }
  } catch {
    // ignore filesystem probe errors; use the default
  }
  return DEFAULT_STORAGE_DIR;
}

export interface WebIdentityOptions {
  /**
   * The registered OAuth client identifier (the Keycard application-credential
   * `identifier`) signed as the `iss` and `sub` of the client assertion.
   * Required to perform a token exchange.
   */
  clientId?: string;
  serverName?: string;
  storage?: PrivateKeyStorage;
  storageDir?: string;
  keyId?: string;
  audienceConfig?: string | Record<string, string>;
}

/**
 * RFC 7523 private_key_jwt client assertion credential provider.
 *
 * Generates and persists an RSA key pair using the supplied storage
 * implementation (default: `FilePrivateKeyStorage("./server_keys")`, falling
 * back to `./mcp_keys` when that directory already exists).
 * On each token exchange the private key signs a client assertion JWT
 * that the authorization server verifies instead of a shared secret.
 *
 * **Requires Node.js.** Key generation and storage use Node.js crypto
 * and filesystem APIs.
 */
export class WebIdentity implements ApplicationCredential {
  #keyManager: PrivateKeyManager;
  #clientId?: string;
  #bootstrapPromise?: Promise<void>;

  constructor(options: WebIdentityOptions = {}) {
    this.#clientId = options.clientId;
    const storage =
      options.storage ??
      new FilePrivateKeyStorage(options.storageDir ?? resolveDefaultStorageDir());

    let keyId = options.keyId;
    if (!keyId && options.serverName) {
      keyId = options.serverName.replace(/[^a-zA-Z0-9\-_]/g, "_");
    }

    this.#keyManager = new PrivateKeyManager({
      storage,
      keyId,
      audienceConfig: options.audienceConfig,
    });
  }

  async bootstrap(): Promise<void> {
    if (!this.#bootstrapPromise) {
      this.#bootstrapPromise = this.#keyManager.bootstrapIdentity();
    }
    return this.#bootstrapPromise;
  }

  getAuth(): null {
    return null;
  }

  async prepareTokenExchangeRequest(
    subjectToken: string,
    resource: string,
    options?: { tokenEndpoint?: string; authInfo?: Record<string, string> },
  ): Promise<TokenExchangeRequest> {
    await this.bootstrap();
    const issuer = options?.authInfo?.resource_client_id ?? this.#clientId;
    if (!issuer) {
      throw new Error(
        "WebIdentity: clientId is required (the registered credential identifier used as the assertion iss and sub)",
      );
    }
    const audience = options?.tokenEndpoint;
    if (!audience) {
      throw new Error(
        "WebIdentity: token endpoint is required for the client assertion audience (aud)",
      );
    }
    const clientAssertion = await this.#keyManager.createClientAssertion(issuer, audience);
    return {
      subjectToken,
      resource,
      subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
      clientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      clientAssertion,
    };
  }

  getPublicJwks(): { keys: Record<string, unknown>[] } {
    return this.#keyManager.getPublicJwks();
  }

  getClientJwksUrl(resourceServerUrl: string): string {
    return this.#keyManager.getClientJwksUrl(resourceServerUrl);
  }
}
