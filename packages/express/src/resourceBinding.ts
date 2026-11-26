import { ConfigurationError } from "@keycardai/oauth/errors";

export interface ResourceBindingOptions {
  resourceIdentifier?: string;
  resourceIdentifiersByZone?: Readonly<Record<string, string>>;
  multiResource?: boolean;
  allowAnyAudience?: boolean;
}

export const PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource";
export const AUTHORIZATION_SERVER_PATH = "/.well-known/oauth-authorization-server";

export interface ResourceIdentifier {
  value: string;
  target?: string;
  metadataTarget?: string;
  metadataUrl?: string;
}

export type ResourceBinding =
  | { mode: "legacy" | "any" | "multi" }
  | { mode: "single"; identifier: ResourceIdentifier }
  | { mode: "perZone"; entries: ReadonlyMap<string, ResourceIdentifier> }
  | { mode: "shared"; entries: ReadonlyMap<string, ResourceIdentifier>; identifier: ResourceIdentifier };

function parseIdentifier(value: string): ResourceIdentifier {
  if (typeof value === "string" && /^[\x21-\x7e]+$/.test(value) &&
      !/[\\#"<>`{}|^]/u.test(value) && !/%(?![a-f0-9]{2})/i.test(value)) {
    if (/^urn:[a-z0-9][a-z0-9-]{0,30}[a-z0-9]:\S+$/i.test(value)) return { value };

    const parts = /^(https?:\/\/[^/?]+)([^?]*)(\?.*)?$/i.exec(value);
    if (parts) {
      const [, authority, path, query = ""] = parts;
      try {
        const url = new URL(authority);
        if (url.hostname && !authority.includes("@") && url.pathname === "/") {
          const metadataTarget = PROTECTED_RESOURCE_PATH + (path === "/" ? "" : path) + query;
          return { value, target: (path || "/") + query, metadataTarget, metadataUrl: authority + metadataTarget };
        }
      } catch {
        // A malformed authority is reported as invalid configuration.
      }
    }
  }
  throw new ConfigurationError("resourceIdentifier must be an absolute HTTP(S) URL without user info or a fragment, or a URN");
}

export function resolveResourceBinding(options: ResourceBindingOptions): ResourceBinding {
  const { resourceIdentifier, resourceIdentifiersByZone, multiResource, allowAnyAudience } = options;
  if ((multiResource && allowAnyAudience) ||
      (resourceIdentifier !== undefined && (resourceIdentifiersByZone !== undefined || multiResource || allowAnyAudience)) ||
      (resourceIdentifiersByZone !== undefined && allowAnyAudience)) {
    throw new ConfigurationError("Conflicting resource identifier and audience modes");
  }

  if (resourceIdentifier !== undefined) return { mode: "single", identifier: parseIdentifier(resourceIdentifier) };
  if (resourceIdentifiersByZone !== undefined) {
    if (!resourceIdentifiersByZone || typeof resourceIdentifiersByZone !== "object" || Array.isArray(resourceIdentifiersByZone)) {
      throw new ConfigurationError("resourceIdentifiersByZone must be a nonempty map");
    }
    const entries = new Map(Object.entries(resourceIdentifiersByZone).map(([zone, identifier]) => {
      if (!/^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$/i.test(zone)) {
        throw new ConfigurationError("Resource bindings require zone IDs valid in a host label");
      }
      return [zone, parseIdentifier(identifier)];
    }));
    const first = entries.values().next().value;
    if (!first) throw new ConfigurationError("resourceIdentifiersByZone must not be empty");
    if (multiResource) {
      if (!first.metadataUrl || [...entries.values()].some(entry => entry.value !== first.value)) {
        throw new ConfigurationError("Shared discovery requires the same HTTP(S) resourceIdentifier in every zone");
      }
      return { mode: "shared", entries, identifier: first };
    }
    const urls = [...entries.values()].flatMap(entry =>
      entry.metadataUrl ? [new URL(entry.metadataUrl).host + entry.metadataTarget] : [],
    );
    if (new Set(urls).size !== urls.length) {
      throw new ConfigurationError("Each per-zone protected-resource metadata URL must identify one zone");
    }
    return { mode: "perZone", entries };
  }
  if (multiResource) return { mode: "multi" };
  if (allowAnyAudience) return { mode: "any" };
  return { mode: "legacy" };
}

export type Audience = string | readonly string[] | Readonly<Record<string, string>>;

export function validateAudience(binding: ResourceBinding, audience?: Audience): void {
  if (binding.mode === "multi" || binding.mode === "shared") {
    if (!Array.isArray(audience) || audience.length === 0 ||
        audience.some(value => typeof value !== "string" || value.length === 0)) {
      throw new ConfigurationError("multiResource requires a nonempty audience list");
    }
    if (binding.mode === "shared" && (audience.length !== 1 || audience[0] !== binding.identifier.value)) {
      throw new ConfigurationError("Shared discovery requires its resourceIdentifier as the sole audience");
    }
  } else if (binding.mode !== "legacy" && audience !== undefined) {
    throw new ConfigurationError("An explicit resource identifier or allowAnyAudience cannot be combined with a separate audience");
  } else if (Array.isArray(audience) && audience.length === 0) {
    throw new ConfigurationError("The configured audience must not be an empty list");
  }
}

export function warnLegacy(component: string, audience?: Audience): void {
  const map = audience !== undefined && typeof audience === "object" && !Array.isArray(audience);
  console.warn(
    `${component}: legacy resource configuration is deprecated; set resourceIdentifier (resource_identifier)` +
      (map ? " or resourceIdentifiersByZone (resource_identifiers_by_zone)." : "."),
  );
}

export function zoneIssuers(binding: ResourceBinding, issuer?: string): ReadonlyMap<string, string> {
  const issuers = new Map<string, string>();
  if (binding.mode !== "perZone" && binding.mode !== "shared") return issuers;
  if (!issuer && [...binding.entries.values()].some(entry => entry.metadataUrl)) {
    throw new ConfigurationError("A base issuer is required for zone-scoped discovery");
  }
  if (issuer) {
    let url: URL;
    try {
      url = new URL(issuer);
      if (!url.hostname || !["https:", "http:"].includes(url.protocol) || url.hostname.startsWith("[")) throw new Error();
    } catch {
      throw new ConfigurationError("Zone resource bindings require an HTTP(S) base issuer with a DNS host");
    }
    for (const zone of binding.entries.keys()) issuers.set(zone, `${url.protocol}//${zone}.${url.host}`);
    if (new Set(issuers.values()).size !== issuers.size) {
      throw new ConfigurationError("Each configured zone must have a distinct issuer");
    }
  }
  return issuers;
}

export function metadataChallenge(target: string, identifier?: ResourceIdentifier): string | undefined {
  return identifier?.target === target ? identifier.metadataUrl : undefined;
}

export function requestTarget(url: string): string {
  const target = url.replace(/^[a-z][a-z\d+.-]*:\/\/[^/?#]*/i, "");
  return !target || target.startsWith("?") ? "/" + target : target;
}

export function bearerChallenge(metadataUrl?: string, error?: string, description?: string): string {
  const params = error ? [`error="${error}"`, `error_description="${description}"`] : [];
  if (metadataUrl) params.push(`resource_metadata="${metadataUrl}"`);
  return params.length ? `Bearer ${params.join(", ")}` : "Bearer";
}
