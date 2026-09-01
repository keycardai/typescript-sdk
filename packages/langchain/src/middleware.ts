import { createMiddleware } from "langchain";
import { interrupt } from "@langchain/langgraph";
import { ToolMessage } from "@langchain/core/messages";
import {
  AccessContext,
  AuthProviderConfigurationError,
  ClientSecret,
  OAuthError,
  TokenType,
  type ApplicationCredential,
  type ClientCredentialsRequest,
  type ErrorDetail,
  type TokenExchangeRequest,
} from "@keycardai/oauth";
import { runWithAccessContext } from "./accessStore.js";
import { subjectTokenExpired } from "./expiry.js";
import { hasPattern, keycardIdentitySchema, type KeycardIdentity } from "./identity.js";
import { callerFromRuntime } from "./servedCaller.js";
import { KeycardZoneClient, type ZoneClient } from "./zoneClient.js";

/** Scopes requested from the zone, globally or per resource. */
export type RequestScopes = string | string[] | Record<string, string | string[]>;

/** Where the identity for a tool call comes from. */
export type IdentitySource = "context" | "auth_user";

/** Identity used when the runtime context carries none. */
export type FallbackIdentity =
  | KeycardIdentity
  | (() => KeycardIdentity | null | undefined);

export interface KeycardGrantMiddlewareOptions {
  /** Keycard zone URL (issuer). Required unless `client` is given. */
  zoneUrl?: string;
  /**
   * Where the identity for a tool call comes from. `"context"` (the default)
   * reads the agent's runtime context, which the caller supplies per
   * invocation. `"auth_user"` reads the verified caller the LangGraph server
   * put on the run, for an agent served behind `@keycardai/langchain/serve`:
   * identity and subject token then come only from a verified bearer, never
   * from the request body, and a run with no verified caller resolves to no
   * identity. Mutually exclusive with `fallbackIdentity`.
   */
  identitySource?: IdentitySource;
  /** Resource URLs granted for every tool call. */
  resources: string[];
  /**
   * How the agent authenticates to the zone: `ClientSecret` for Keycard-issued
   * client credentials, or any other `ApplicationCredential`. Mutually
   * exclusive with `clientId` / `clientSecret`.
   */
  applicationCredential?: ApplicationCredential;
  /** Shorthand for `applicationCredential: new ClientSecret(clientId, clientSecret)`. */
  clientId?: string;
  /** Shorthand for `applicationCredential: new ClientSecret(clientId, clientSecret)`. */
  clientSecret?: string;
  /**
   * Per-tool override, tool name to resource URLs. Tools absent from the map
   * get `resources`; an empty array grants nothing for that tool.
   */
  toolResources?: Record<string, string[]>;
  /** Outbound scopes for the exchange and the client-credentials grant. */
  requestScopes?: RequestScopes;
  /**
   * When set, an ungranted resource pauses the run with an
   * `authorization_required` interrupt instead of recording a silent error.
   * The callable form receives the failed resource URLs. Requires a
   * checkpointer unless `interruptOnAuth` is `false`.
   */
  authorizationUrl?: string | ((resources: string[]) => string);
  /**
   * When set, a run that carries no identity, or whose subject token has
   * already expired, pauses with a `sign_in_required` interrupt instead of
   * recording an error. Requires a checkpointer unless
   * `interruptOnAuth` is `false`.
   */
  signInUrl?: string;
  /**
   * Identity used when the runtime context carries none. Pass a function to
   * resolve it per tool call, so a sign-in that happens mid-run is picked up
   * on resume without a restart.
   */
  fallbackIdentity?: FallbackIdentity;
  /**
   * How an unmet authorization requirement reaches the user. `true` (the
   * default) pauses the run with a LangGraph interrupt, which requires a
   * checkpointer. `false` sends the same payload to the model as failed tool
   * output instead, so the model relays the URL in its reply; the user
   * authorizes out of band and their next turn retries the tool. No
   * checkpointer involved, and no in-run resume.
   */
  interruptOnAuth?: boolean;
  /**
   * Injectable zone client (tests). When set, `zoneUrl` is unused and the
   * client is reused as-is.
   */
  client?: ZoneClient;
}

/** Selection options for the {@link KeycardGrantMiddleware.grant} escape hatch. */
export interface GrantOptions {
  /** The identity to acquire under. Defaults to `fallbackIdentity`. */
  identity?: KeycardIdentity;
  /** Grant that tool's `toolResources` override. Mutually exclusive with `resources`. */
  toolName?: string;
  /** Grant exactly these resources. Mutually exclusive with `toolName`. */
  resources?: string[];
}

/** The interrupt payload for a run that needs a user to sign in. */
export interface SignInRequiredInterrupt {
  type: "sign_in_required";
  sign_in_url: string;
  reason: "missing_identity" | "subject_token_expired";
  message: string;
}

/** The interrupt payload for resources the user has not granted yet. */
export interface AuthorizationRequiredInterrupt {
  type: "authorization_required";
  authorization_url: string;
  resources: string[];
  errors: Record<string, ErrorDetail | null>;
  message: string;
}

export type KeycardInterrupt = SignInRequiredInterrupt | AuthorizationRequiredInterrupt;

/** The interrupt fields carried by fallback tool output, for a model to relay. */
interface AuthFallbackFields {
  kind: KeycardInterrupt["type"];
  reason: SignInRequiredInterrupt["reason"] | "consent_required";
  url: string;
  tool: string;
}

/**
 * A LangChain middleware that grants delegated access on every tool call,
 * plus the {@link KeycardGrantMiddleware.grant} escape hatch for code that
 * runs outside an agent.
 */
export type KeycardGrantMiddleware = ReturnType<typeof buildMiddleware> & {
  /**
   * Serve `getAccessContext()` to code that runs outside an agent.
   *
   * Lets the same governed tools back non-agent surfaces, e.g. seeding a
   * dashboard panel on page load with the tool the agent uses in chat:
   *
   * ```ts
   * await keycard.grant({ identity: Access.onBehalfOf(sessionToken) }, () =>
   *   listRequests.invoke({}),
   * );
   * ```
   *
   * Also serves resources that have no tool at all, e.g. fetching a vaulted
   * model key under the agent's own identity:
   *
   * ```ts
   * const key = await keycard.grant(
   *   { identity: Access.asSelf(), resources: [LLM_KEY] },
   *   (access) => access.access(LLM_KEY).accessToken,
   * );
   * ```
   *
   * There is no run to pause, so nothing interrupts here: failures stay on
   * the access context, exactly as tools see them.
   */
  grant<T>(options: GrantOptions, fn: (access: AccessContext) => T): Promise<Awaited<T>>;
  grant<T>(fn: (access: AccessContext) => T): Promise<Awaited<T>>;
};

/**
 * Resumes are bounded: `interrupt()` returns the resume value when the tool
 * call re-executes, so a user who resumes without authorizing would otherwise
 * fall straight through to an unauthorized call. Each attempt re-resolves the
 * identity and retries acquisition; after the cap the failure stays on the
 * access context as an error the tool sees.
 */
const MAX_AUTHORIZATION_ATTEMPTS = 3;

/**
 * Exchange the caller's identity for resource tokens on every tool call.
 *
 * ```ts
 * const keycard = keycardGrantMiddleware({
 *   zoneUrl: "https://your-zone.keycard.cloud",
 *   resources: [CALENDAR],
 *   clientId: "your-agent",
 *   clientSecret: process.env.KEYCARD_CLIENT_SECRET,
 * });
 *
 * const agent = createAgent({ model, tools: [listEvents], middleware: [keycard] });
 *
 * await agent.invoke(
 *   { messages: [...] },
 *   { context: Access.onBehalfOf(callerToken) },
 * );
 * ```
 *
 * The middleware carries the identity context schema, so nothing else has to
 * declare it. Identity is never construction state: it rides the runtime
 * context of each run, so one deployment serves many users.
 */
export function keycardGrantMiddleware(
  options: KeycardGrantMiddlewareOptions,
): KeycardGrantMiddleware {
  if (!options.client && !options.zoneUrl) {
    throw new AuthProviderConfigurationError(
      "keycardGrantMiddleware requires zoneUrl (or an injected client)",
    );
  }
  if (options.applicationCredential && (options.clientId || options.clientSecret)) {
    throw new AuthProviderConfigurationError(
      "Pass applicationCredential or clientId/clientSecret, not both",
    );
  }
  const identitySource = options.identitySource ?? "context";
  if (identitySource !== "context" && identitySource !== "auth_user") {
    throw new AuthProviderConfigurationError(
      `identitySource must be "context" or "auth_user", got ${JSON.stringify(
        options.identitySource,
      )}`,
    );
  }
  if (identitySource === "auth_user" && options.fallbackIdentity !== undefined) {
    throw new AuthProviderConfigurationError(
      'identitySource "auth_user" takes its identity from the verified caller ' +
        "on the run, so fallbackIdentity would be a second, unverified source. " +
        "Pass one or the other.",
    );
  }

  const grant = new Grant(options);
  const middleware = buildMiddleware(grant);

  return Object.assign(middleware, {
    grant<T>(
      optionsOrFn: GrantOptions | ((access: AccessContext) => T),
      maybeFn?: (access: AccessContext) => T,
    ): Promise<Awaited<T>> {
      const [grantOptions, fn] =
        typeof optionsOrFn === "function"
          ? [{} as GrantOptions, optionsOrFn]
          : [optionsOrFn, maybeFn!];
      return grant.runOutsideAgent(grantOptions, fn);
    },
  }) as KeycardGrantMiddleware;
}

/**
 * The tool-call boundary: acquire before the handler runs, install the access
 * context for the duration of the handler, and remove it when the call
 * returns. The credential reaches the tool out of band, so the tool's schema
 * carries only the tool's own arguments.
 */
function buildMiddleware(grant: Grant) {
  return createMiddleware({
    name: "KeycardGrantMiddleware",
    contextSchema: keycardIdentitySchema,
    wrapToolCall: async (request, handler) => {
      const toolName = request.toolCall.name;
      const context = grant.callContext(request.runtime);

      let access = await grant.acquire(context, toolName);
      if (grant.interruptOnAuth) {
        for (let attempt = 0; attempt < MAX_AUTHORIZATION_ATTEMPTS; attempt++) {
          const payload = grant.pendingInterrupt(access, context);
          if (payload === null) break;
          interrupt(payload);
          access = await grant.acquire(context, toolName);
        }
      } else {
        const fallback = grant.authFallbackMessage(access, context, request.toolCall);
        if (fallback !== null) return fallback;
      }

      return runWithAccessContext(access, () => handler(request));
    },
  });
}

/** Acquisition, interrupt routing, and resource selection for one middleware. */
class Grant {
  /** Whether an unmet authorization requirement pauses the run. */
  readonly interruptOnAuth: boolean;

  #options: KeycardGrantMiddlewareOptions;
  #identitySource: IdentitySource;
  #credential?: ApplicationCredential;
  #client?: ZoneClient;

  constructor(options: KeycardGrantMiddlewareOptions) {
    this.#options = options;
    this.#identitySource = options.identitySource ?? "context";
    this.interruptOnAuth = options.interruptOnAuth ?? true;
    if (options.applicationCredential) {
      this.#credential = options.applicationCredential;
    } else if (options.clientId && options.clientSecret) {
      this.#credential = new ClientSecret(options.clientId, options.clientSecret);
    }
    this.#client = options.client;
  }

  /**
   * The warm zone client for this middleware.
   *
   * Built once and reused: the underlying clients cache the zone's token
   * endpoint after their first call, so the hot path pays neither client
   * construction nor rediscovery.
   */
  #zoneClient(): ZoneClient {
    if (!this.#client) {
      this.#client = new KeycardZoneClient(this.#options.zoneUrl!, this.#credential);
    }
    return this.#client;
  }

  /**
   * The effective identity for this tool call: runtime context first, then
   * the fallback. Resolved per call, so a sign-in that happens mid-run (via
   * the `sign_in_required` interrupt) is picked up on resume.
   */
  #resolveIdentity(context: KeycardIdentity | undefined): KeycardIdentity | null {
    if (this.#identitySource === "auth_user") {
      return hasPattern(context) ? context! : null;
    }
    if (hasPattern(context)) {
      return {
        subjectToken: context!.subjectToken,
        userIdentifier: context!.userIdentifier,
        asSelf: context!.asSelf,
      };
    }
    const fallback = this.#options.fallbackIdentity;
    const resolved = typeof fallback === "function" ? fallback() : fallback;
    return hasPattern(resolved) ? resolved! : null;
  }

  /**
   * The identity this tool call runs under, before fallback resolution.
   *
   * Under `identitySource: "auth_user"` the runtime context is ignored
   * entirely and the verified caller the server put on the run is the only
   * source, so a caller cannot name an identity in the request body.
   */
  callContext(runtime: unknown): KeycardIdentity | undefined {
    if (this.#identitySource !== "auth_user") {
      return (runtime as { context?: KeycardIdentity } | undefined)?.context;
    }
    const caller = callerFromRuntime(runtime);
    return caller === null ? undefined : { subjectToken: caller.subjectToken };
  }

  #resourcesFor(toolName: string): string[] {
    return this.#options.toolResources?.[toolName] ?? this.#options.resources;
  }

  #scopeFor(resource: string): string | undefined {
    const scopes = this.#options.requestScopes;
    if (scopes === undefined) return undefined;
    const value =
      typeof scopes === "string" || Array.isArray(scopes) ? scopes : scopes[resource];
    if (value === undefined) return undefined;
    return (Array.isArray(value) ? value.join(" ") : value) || undefined;
  }

  /** Acquire the resources this tool call needs, under the resolved identity. */
  acquire(
    context: KeycardIdentity | undefined,
    toolName: string,
  ): Promise<AccessContext> {
    return this.#acquireFor(this.#resolveIdentity(context), this.#resourcesFor(toolName));
  }

  async #acquireFor(
    identity: KeycardIdentity | null,
    resources: string[],
  ): Promise<AccessContext> {
    const access = new AccessContext();

    if (identity === null) {
      access.setError({
        message: this.#options.signInUrl
          ? "No Keycard identity for this run. Sign in to continue."
          : "No Keycard identity on the runtime context. Invoke the agent with " +
            "context: Access.onBehalfOf(...), Access.impersonate(...), or " +
            "Access.asSelf().",
        code: "missing_identity",
      });
      return access;
    }

    if (identity.subjectToken && subjectTokenExpired(identity.subjectToken)) {
      access.setError({
        message:
          "The subject token for this run has expired. Sign in again to continue.",
        code: "subject_token_expired",
      });
      return access;
    }

    for (const resource of resources) {
      try {
        access.setToken(resource, await this.#acquireOne(identity, resource));
      } catch (e) {
        access.setResourceError(resource, describeFailure(e, identity, resource));
      }
    }
    return access;
  }

  async #acquireOne(identity: KeycardIdentity, resource: string) {
    const client = this.#zoneClient();
    const scope = this.#scopeFor(resource);

    if (identity.asSelf) {
      const request: ClientCredentialsRequest = { resource };
      if (scope) request.scope = scope;
      return client.clientCredentialsGrant({
        ...request,
        ...(await this.#clientAuthFields(resource)),
      });
    }

    if (identity.userIdentifier) {
      return client.impersonate({
        userIdentifier: identity.userIdentifier,
        resource,
        ...(scope ? { scope } : {}),
      });
    }

    let request: TokenExchangeRequest;
    if (this.#credential) {
      request = await this.#credential.prepareTokenExchangeRequest(
        identity.subjectToken!,
        resource,
      );
    } else {
      request = {
        subjectToken: identity.subjectToken!,
        resource,
        subjectTokenType: TokenType.ACCESS_TOKEN,
      };
    }
    if (scope) request = { ...request, scope };
    return client.exchangeToken(request);
  }

  /**
   * Client-authentication fields the credential puts in the request body.
   *
   * Assertion-based credentials carry no HTTP-level auth; their proof rides in
   * the request as a jwt-bearer client assertion. The credential protocol only
   * exposes request preparation for token exchange, so this prepares one and
   * lifts the auth fields for the client-credentials call. `ClientSecret`
   * authenticates at the HTTP layer and contributes nothing here.
   *
   * The subject token below is a placeholder: client credentials has no
   * subject, and only the client-auth fields of the prepared request are read.
   */
  async #clientAuthFields(resource: string): Promise<Partial<ClientCredentialsRequest>> {
    if (!this.#credential) return {};
    const prepared = await this.#credential.prepareTokenExchangeRequest(
      "client-credentials",
      resource,
    );
    if (!prepared.clientAssertion) return {};
    const fields: Partial<ClientCredentialsRequest> = {
      clientAssertion: prepared.clientAssertion,
      clientAssertionType: prepared.clientAssertionType,
    };
    if (prepared.clientId) fields.clientId = prepared.clientId;
    return fields;
  }

  /**
   * The interrupt this access context calls for, if any.
   *
   * As-itself runs never pause: there is no user to send to a sign-in or
   * consent page, so failures stay on the access context as errors for the
   * tool (and the operator's logs) to surface.
   */
  pendingInterrupt(
    access: AccessContext,
    context: KeycardIdentity | undefined,
  ): KeycardInterrupt | null {
    const identity = this.#resolveIdentity(context);
    if (identity?.asSelf) return null;

    const signInUrl = this.#options.signInUrl;
    if (access.hasError() && signInUrl) {
      const reason =
        access.getError()?.code === "subject_token_expired"
          ? "subject_token_expired"
          : "missing_identity";
      return {
        type: "sign_in_required",
        sign_in_url: signInUrl,
        reason,
        message:
          reason === "subject_token_expired"
            ? "Your session has expired. Sign in again, then resume the run."
            : "Sign in with Keycard to continue. Open the link, sign in, then " +
              "resume the run.",
      };
    }

    const failed = access.getFailedResources();
    const authorizationUrl = this.#options.authorizationUrl;
    if (failed.length > 0 && authorizationUrl !== undefined) {
      return {
        type: "authorization_required",
        authorization_url:
          typeof authorizationUrl === "function"
            ? authorizationUrl(failed)
            : authorizationUrl,
        resources: failed,
        errors: Object.fromEntries(
          failed.map((resource) => [resource, access.getResourceError(resource)]),
        ),
        message:
          "Access to the resources above has not been granted yet. Open the " +
          "authorization URL to grant it, then resume the run.",
      };
    }
    return null;
  }

  /**
   * The interrupt payload reduced to the fields tool output carries.
   *
   * `reason` is already on a `sign_in_required` payload; a consent payload has
   * one implicit kind of failure, so it reads as `consent_required`.
   */
  #authFallbackFields(payload: KeycardInterrupt, toolName: string): AuthFallbackFields {
    return payload.type === "sign_in_required"
      ? {
          kind: payload.type,
          reason: payload.reason,
          url: payload.sign_in_url,
          tool: toolName,
        }
      : {
          kind: payload.type,
          reason: "consent_required",
          url: payload.authorization_url,
          tool: toolName,
        };
  }

  /**
   * Failed tool output standing in for the interrupt, or `null` if none is due.
   *
   * Written for a model that must hand the URL to the user: the URL sits on its
   * own line, and the instruction is to reproduce it verbatim, because a
   * paraphrased or shortened authorization URL does not authorize anything.
   */
  authFallbackMessage(
    access: AccessContext,
    context: KeycardIdentity | undefined,
    toolCall: { name: string; id?: string },
  ): ToolMessage | null {
    const payload = this.pendingInterrupt(access, context);
    if (payload === null) return null;

    const fields = this.#authFallbackFields(payload, toolCall.name);
    const action = fields.kind === "sign_in_required" ? "sign in" : "grant this access";
    return new ToolMessage({
      content:
        `${fields.kind}: the tool ${fields.tool} cannot run yet ` +
        `(reason: ${fields.reason}).\n` +
        `${fields.url}\n` +
        `Tell the user to open the URL above to ${action}. Copy it into your ` +
        "reply exactly as written, character for character: do not shorten it, " +
        "rewrite it, wrap it in other text, or describe it in words. Then ask " +
        `the user to tell you once they are done, and call ${fields.tool} again.`,
      name: fields.tool,
      tool_call_id: toolCall.id ?? "",
      status: "error",
    });
  }

  /** The escape hatch: acquire and install a context outside an agent run. */
  async runOutsideAgent<T>(
    options: GrantOptions,
    fn: (access: AccessContext) => T,
  ): Promise<Awaited<T>> {
    if (options.toolName !== undefined && options.resources !== undefined) {
      throw new AuthProviderConfigurationError(
        "Pass toolName or resources, not both",
      );
    }
    const identity = options.identity ?? undefined;
    const resources =
      options.resources ??
      (options.toolName !== undefined
        ? this.#resourcesFor(options.toolName)
        : this.#options.resources);
    const access = await this.#acquireFor(this.#resolveIdentity(identity), resources);
    return await runWithAccessContext(access, () => fn(access));
  }
}

/** The recorded error for a resource whose acquisition failed. */
function describeFailure(
  error: unknown,
  identity: KeycardIdentity,
  resource: string,
): ErrorDetail {
  const detail: ErrorDetail = {
    message: identity.asSelf
      ? `Client credentials grant failed for ${resource}`
      : `Token exchange failed for ${resource}`,
  };
  if (error instanceof OAuthError) {
    detail.code = error.errorCode;
    detail.description = error.message;
  } else {
    detail.rawError = String(error);
  }
  return detail;
}
