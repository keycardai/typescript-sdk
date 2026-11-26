import { CredentialDiscoveryError } from "./errors.js";

export const CLIENT_ID_ENV_VAR = "KEYCARD_CLIENT_ID";
export const CLIENT_SECRET_ENV_VAR = "KEYCARD_CLIENT_SECRET";
export const WEB_IDENTITY_KEY_STORAGE_DIR_ENV_VAR = "KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR";
export const CREDENTIAL_TYPE_ENV_VAR = "KEYCARD_APPLICATION_CREDENTIAL_TYPE";

export const CLIENT_SECRET_TYPE = "client_secret";
export const WORKLOAD_IDENTITY_TYPE = "workload_identity";
export const WEB_IDENTITY_TYPE = "web_identity";
/** @deprecated Use WORKLOAD_IDENTITY_TYPE. */
export const LEGACY_WORKLOAD_IDENTITY_TYPE = "eks_workload_identity";

const credentialTypes = [CLIENT_SECRET_TYPE, WORKLOAD_IDENTITY_TYPE, WEB_IDENTITY_TYPE] as const;

export type CredentialType = (typeof credentialTypes)[number];
export type CredentialEnvironment = Readonly<Record<string, string | undefined>>;

export type ResolvedCredential =
  | { type: typeof CLIENT_SECRET_TYPE; clientId: string; clientSecret: string }
  | { type: typeof WORKLOAD_IDENTITY_TYPE; tokenFilePath: string; clientId?: string }
  | { type: typeof WEB_IDENTITY_TYPE; storageDir?: string; clientId?: string };

/**
 * Selects a credential from an explicit environment mapping without constructing it.
 * The runtime supplies the ordered list of token-file variables it supports.
 */
export function resolveCredentialType(
  env: CredentialEnvironment,
  { tokenFileEnvVars }: { tokenFileEnvVars: readonly string[] },
): ResolvedCredential {
  const clientId = env[CLIENT_ID_ENV_VAR] || undefined;
  const clientSecret = env[CLIENT_SECRET_ENV_VAR] || undefined;
  const tokenFilePath = tokenFileEnvVars.map((name) => env[name]).find(Boolean);
  const storageDir = env[WEB_IDENTITY_KEY_STORAGE_DIR_ENV_VAR] || undefined;
  const selector = env[CREDENTIAL_TYPE_ENV_VAR];

  const candidates: ResolvedCredential[] = [];
  if (clientId && clientSecret) {
    candidates.push({ type: CLIENT_SECRET_TYPE, clientId, clientSecret });
  }
  if (tokenFilePath) {
    candidates.push({ type: WORKLOAD_IDENTITY_TYPE, tokenFilePath, clientId });
  }
  if (storageDir) {
    candidates.push({ type: WEB_IDENTITY_TYPE, storageDir, clientId });
  }
  const resolvable = candidates.map(({ type }) => type);

  if (selector) {
    const type = selector === LEGACY_WORKLOAD_IDENTITY_TYPE ? WORKLOAD_IDENTITY_TYPE : selector;
    if (!credentialTypes.some((credentialType) => credentialType === type)) {
      throw new CredentialDiscoveryError(
        `${CREDENTIAL_TYPE_ENV_VAR} must name one of: ${credentialTypes.join(", ")}.`,
        "unknown_type",
        resolvable,
      );
    }
    if (type === WEB_IDENTITY_TYPE) {
      return { type, storageDir, clientId };
    }
    const selected = candidates.find((candidate) => candidate.type === type);
    if (selected) {
      return selected;
    }
    const requirement = type === CLIENT_SECRET_TYPE
      ? `requires both ${CLIENT_ID_ENV_VAR} and ${CLIENT_SECRET_ENV_VAR}`
      : tokenFileEnvVars.length
        ? `requires a token file path in one of: ${tokenFileEnvVars.join(", ")}`
        : "requires a token file, which this runtime does not support";
    throw new CredentialDiscoveryError(
      `${CREDENTIAL_TYPE_ENV_VAR}=${type} ${requirement}.`,
      "not_satisfiable",
      resolvable,
    );
  }

  if (clientSecret && !clientId) {
    throw new CredentialDiscoveryError(
      `${CLIENT_SECRET_ENV_VAR} is set without ${CLIENT_ID_ENV_VAR}.`,
      "incomplete",
      resolvable,
    );
  }
  if (candidates.length === 0) {
    throw new CredentialDiscoveryError(
      `No Keycard application credential is configured. Set ${CLIENT_ID_ENV_VAR} and ${CLIENT_SECRET_ENV_VAR}, ` +
        `a token-file variable, or ${WEB_IDENTITY_KEY_STORAGE_DIR_ENV_VAR}.`,
      "absent",
      resolvable,
    );
  }
  if (candidates.length > 1) {
    throw new CredentialDiscoveryError(
      `The environment configures ${resolvable.join(" and ")}. Set ${CREDENTIAL_TYPE_ENV_VAR} to choose one.`,
      "ambiguous",
      resolvable,
    );
  }
  return candidates[0];
}
