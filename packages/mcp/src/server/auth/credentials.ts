import * as fs from "node:fs";
import type { TokenExchangeRequest } from "@keycardai/oauth/tokenExchange";
import type { ApplicationCredential } from "@keycardai/oauth/credentials";
import { PrivateKeyManager, FilePrivateKeyStorage } from "./privateKey.js";
import type { PrivateKeyStorage } from "./privateKey.js";
import { EKSWorkloadIdentityConfigurationError } from "./errors.js";

export type { ApplicationCredential } from "@keycardai/oauth/credentials";

// =============================================================================
// ClientSecret
// =============================================================================

export class ClientSecret implements ApplicationCredential {
  #clientId: string;
  #clientSecret: string;

  constructor(clientId: string, clientSecret: string) {
    this.#clientId = clientId;
    this.#clientSecret = clientSecret;
  }

  getAuth(): { clientId: string; clientSecret: string } {
    return { clientId: this.#clientId, clientSecret: this.#clientSecret };
  }

  async prepareTokenExchangeRequest(
    subjectToken: string,
    resource: string,
  ): Promise<TokenExchangeRequest> {
    return {
      subjectToken,
      resource,
      subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
    };
  }
}

// =============================================================================
// WebIdentity (private_key_jwt - RFC 7523)
// =============================================================================

export interface WebIdentityOptions {
  serverName?: string;
  storage?: PrivateKeyStorage;
  storageDir?: string;
  keyId?: string;
  audienceConfig?: string | Record<string, string>;
}

export class WebIdentity implements ApplicationCredential {
  #keyManager: PrivateKeyManager;
  #bootstrapPromise?: Promise<void>;

  constructor(options: WebIdentityOptions = {}) {
    const storage = options.storage ?? new FilePrivateKeyStorage(options.storageDir ?? "./mcp_keys");

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

    const issuer = options?.authInfo?.resource_client_id ?? this.#keyManager.getClientId();
    const audience = options?.tokenEndpoint ?? issuer;

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

// =============================================================================
// EKSWorkloadIdentity
// =============================================================================

const DEFAULT_EKS_ENV_VARS = [
  "KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
  "AWS_WEB_IDENTITY_TOKEN_FILE",
];

export interface EKSWorkloadIdentityOptions {
  tokenFilePath?: string;
  envVarName?: string;
}

export class EKSWorkloadIdentity implements ApplicationCredential {
  #tokenFilePath: string;

  constructor(options?: EKSWorkloadIdentityOptions) {
    if (options?.tokenFilePath) {
      this.#tokenFilePath = options.tokenFilePath;
    } else {
      const envNames = options?.envVarName
        ? [options.envVarName, ...DEFAULT_EKS_ENV_VARS]
        : DEFAULT_EKS_ENV_VARS;

      const found = envNames.find((name) => process.env[name]);
      if (!found || !process.env[found]) {
        throw new EKSWorkloadIdentityConfigurationError(
          "Could not find token file path in environment variables. " +
          `Checked: ${envNames.join(", ")}`,
        );
      }
      this.#tokenFilePath = process.env[found]!;
    }

    this.#validateTokenFile();
  }

  getAuth(): null {
    return null;
  }

  async prepareTokenExchangeRequest(
    subjectToken: string,
    resource: string,
  ): Promise<TokenExchangeRequest> {
    const eksToken = this.#readToken();

    return {
      subjectToken,
      resource,
      subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
      clientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      clientAssertion: eksToken,
    };
  }

  #validateTokenFile(): void {
    try {
      const token = fs.readFileSync(this.#tokenFilePath, "utf-8").trim();
      if (!token) {
        throw new EKSWorkloadIdentityConfigurationError(
          `Token file is empty: ${this.#tokenFilePath}`,
        );
      }
    } catch (error) {
      if (error instanceof EKSWorkloadIdentityConfigurationError) throw error;
      throw new EKSWorkloadIdentityConfigurationError(
        `Error reading token file "${this.#tokenFilePath}": ${error}`,
      );
    }
  }

  #readToken(): string {
    try {
      const token = fs.readFileSync(this.#tokenFilePath, "utf-8").trim();
      if (!token) {
        throw new Error(`Token file is empty: ${this.#tokenFilePath}`);
      }
      return token;
    } catch (error) {
      throw new Error(
        `Failed to read EKS token from "${this.#tokenFilePath}": ${error}`,
      );
    }
  }
}
