import {
  FileTokenSource,
  resolveTokenFilePath,
  WorkloadIdentity,
} from "./workloadIdentity.js";

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
 * **Requires Node.js.** Reads the token file synchronously from the
 * filesystem at construction and exchange time.
 *
 * @deprecated Use {@link WorkloadIdentity} with {@link FileTokenSource},
 * which also covers AKS and other platforms that project token files.
 * Failures throw WorkloadIdentityConfigurationError /
 * WorkloadIdentityRuntimeError (both Error subclasses).
 */
export class EKSWorkloadIdentity extends WorkloadIdentity {
  constructor(options?: EKSWorkloadIdentityOptions) {
    // Discovery limited to the EKS environment variables; FileTokenSource's
    // default list additionally includes AZURE_FEDERATED_TOKEN_FILE.
    const tokenFilePath = resolveTokenFilePath(DEFAULT_EKS_ENV_VARS, options);
    super(new FileTokenSource({ tokenFilePath }));
  }
}
