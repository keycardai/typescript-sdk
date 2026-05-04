import * as fs from "node:fs";
import type { ApplicationCredential } from "../credentials.js";
import type { TokenExchangeRequest } from "../tokenExchange.js";

const DEFAULT_EKS_ENV_VARS = [
  "KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
  "AWS_WEB_IDENTITY_TOKEN_FILE",
];

export interface EKSWorkloadIdentityOptions {
  tokenFilePath?: string;
  envVarName?: string;
}

/**
 * EKS pod identity credential provider. Reads the workload identity token
 * from the mounted file path (resolved from the standard EKS environment
 * variables or the explicit `tokenFilePath` option) and uses it as a
 * client assertion in RFC 8693 token exchange requests.
 *
 * **Requires Node.js** — reads the token file synchronously from the
 * filesystem at construction and exchange time.
 */
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
        throw new Error(
          `EKSWorkloadIdentity: could not find token file path in environment variables. ` +
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
    return {
      subjectToken,
      resource,
      subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
      clientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      clientAssertion: this.#readToken(),
    };
  }

  #validateTokenFile(): void {
    try {
      const token = fs.readFileSync(this.#tokenFilePath, "utf-8").trim();
      if (!token) {
        throw new Error(`EKSWorkloadIdentity: token file is empty: ${this.#tokenFilePath}`);
      }
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("EKSWorkloadIdentity:")) throw error;
      throw new Error(
        `EKSWorkloadIdentity: error reading token file "${this.#tokenFilePath}": ${error}`,
      );
    }
  }

  #readToken(): string {
    const token = fs.readFileSync(this.#tokenFilePath, "utf-8").trim();
    if (!token) {
      throw new Error(`EKSWorkloadIdentity: token file is empty: ${this.#tokenFilePath}`);
    }
    return token;
  }
}
