import base64url from "./base64url.js";
import { fetchAuthorizationServerMetadata } from "./discovery.js";
import { OAuthError } from "./errors.js";
import { deserializeTokenResponse, type TokenResponse } from "./tokenExchange.js";

// =============================================================================
// PKCE primitives (RFC 7636)
// =============================================================================

export interface Pkce {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: "S256" | "plain";
}

/**
 * Generate a cryptographically random PKCE code verifier (RFC 7636 §4.1).
 *
 * Returns a base64url string of the requested length (43-128 characters,
 * default 128). Runtime-agnostic: uses the global `crypto.getRandomValues`
 * which is available in Node 19+, Cloudflare Workers, and browsers.
 */
export function generateCodeVerifier(length = 128): string {
  if (length < 43 || length > 128) {
    throw new RangeError("Code verifier length must be between 43 and 128 characters");
  }
  // base64url yields 4 characters per 3 bytes; generate enough bytes to
  // cover the requested length, then trim.
  const bytes = new Uint8Array(Math.ceil((length * 3) / 4));
  crypto.getRandomValues(bytes);
  return base64url.encode(bytes.buffer as ArrayBuffer).slice(0, length);
}

/**
 * Derive a PKCE code challenge from a code verifier (RFC 7636 §4.2).
 *
 * S256 (default): `BASE64URL(SHA-256(ASCII(code_verifier)))`
 * plain: returns the verifier unchanged (not recommended; use only when
 * the AS does not support S256).
 */
export async function generateCodeChallenge(
  verifier: string,
  method: "S256" | "plain" = "S256",
): Promise<string> {
  if (method === "plain") {
    return verifier;
  }
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return base64url.encode(digest);
}

/**
 * Generate a PKCE pair (verifier + challenge) in one call.
 */
export async function generatePkcePair(
  method: "S256" | "plain" = "S256",
  verifierLength = 128,
): Promise<Pkce> {
  const codeVerifier = generateCodeVerifier(verifierLength);
  const codeChallenge = await generateCodeChallenge(codeVerifier, method);
  return { codeVerifier, codeChallenge, codeChallengeMethod: method };
}

// =============================================================================
// Authorization code exchange
// =============================================================================

export interface ExchangeAuthorizationCodeOptions {
  codeVerifier: string;
  redirectUri: string;
  clientId?: string;
  clientSecret?: string;
  /** RFC 8707 resource indicator. When set, restricts the issued token's audience to this resource. */
  resource?: string;
  signal?: AbortSignal;
}

/**
 * Exchange an authorization code for tokens (RFC 6749 §4.1.3 + RFC 7636).
 *
 * Discovers `token_endpoint` from the AS metadata, then POSTs
 * `grant_type=authorization_code` with the code verifier.
 */
export async function exchangeAuthorizationCode(
  issuer: string,
  code: string,
  options: ExchangeAuthorizationCodeOptions,
): Promise<TokenResponse> {
  const metadata = await fetchAuthorizationServerMetadata(issuer, {
    signal: options.signal,
  });
  if (!metadata.token_endpoint) {
    throw new Error(
      `Authorization server "${issuer}" does not advertise a token_endpoint`,
    );
  }

  const params = new URLSearchParams();
  params.set("grant_type", "authorization_code");
  params.set("code", code);
  params.set("code_verifier", options.codeVerifier);
  params.set("redirect_uri", options.redirectUri);
  if (options.resource) params.set("resource", options.resource);
  if (options.clientId) params.set("client_id", options.clientId);

  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
  };
  if (options.clientId && options.clientSecret) {
    headers["Authorization"] = `Basic ${btoa(`${options.clientId}:${options.clientSecret}`)}`;
    params.delete("client_id");
  }

  const response = await fetch(metadata.token_endpoint, {
    method: "POST",
    headers,
    body: params.toString(),
    signal: options.signal,
  });

  if (!response.ok) {
    let errorBody: Record<string, unknown> | null = null;
    try {
      const json = await response.json() as unknown;
      if (json && typeof json === "object" && !Array.isArray(json)) {
        errorBody = json as Record<string, unknown>;
      }
    } catch {
      // non-JSON error body — fall through to generic error
    }
    if (errorBody && typeof errorBody.error === "string") {
      const description = typeof errorBody.error_description === "string"
        ? errorBody.error_description
        : errorBody.error;
      const errorUri = typeof errorBody.error_uri === "string" ? errorBody.error_uri : undefined;
      throw new OAuthError(errorBody.error, description, errorUri);
    }
    throw new OAuthError(
      "invalid_response",
      `Authorization code exchange failed (HTTP ${response.status})`,
    );
  }

  const json = await response.json() as unknown;
  if (!json || typeof json !== "object" || Array.isArray(json)) {
    throw new OAuthError("invalid_response", "Token endpoint response is not a valid JSON object");
  }
  return deserializeTokenResponse(json as Record<string, unknown>);
}

// =============================================================================
// Authorization URL builder
// =============================================================================

export interface AuthorizeUrlParams {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  /** Default: "S256" */
  codeChallengeMethod?: "S256" | "plain";
  /** CSRF binding value, echoed back on the redirect (RFC 6749 §10.12). */
  state?: string;
  /** Space-separated scopes. */
  scope?: string;
  /** RFC 8707 resource indicator. */
  resource?: string;
}

/**
 * Build an authorization-endpoint URL for the authorization-code grant with
 * PKCE (RFC 6749 §4.1.1 + RFC 7636 §4.3). For callers that manage the
 * redirect themselves instead of using `authenticate()`.
 */
export function buildAuthorizeUrl(
  authorizationEndpoint: string,
  params: AuthorizeUrlParams,
): string {
  const url = new URL(authorizationEndpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", params.clientId);
  url.searchParams.set("redirect_uri", params.redirectUri);
  url.searchParams.set("code_challenge", params.codeChallenge);
  url.searchParams.set("code_challenge_method", params.codeChallengeMethod ?? "S256");
  if (params.state) url.searchParams.set("state", params.state);
  if (params.scope) url.searchParams.set("scope", params.scope);
  if (params.resource) url.searchParams.set("resource", params.resource);
  return url.toString();
}

// =============================================================================
// High-level authenticate() flow (Node.js only)
// =============================================================================

export interface AuthenticateOptions {
  clientId: string;
  /** Default: "http://localhost:{port}/callback" */
  redirectUri?: string;
  /** Default: 8765 */
  port?: number;
  scopes?: readonly string[];
  clientSecret?: string;
  /** Default: 300_000 ms */
  timeoutMs?: number;
  /** RFC 8707 resource indicator. Scopes the issued token's audience to this resource URL, enabling token exchange against it. */
  resource?: string;
  /** Opens the authorization URL. Default: the platform browser launcher. */
  openBrowser?: (url: string) => void | Promise<void>;
}

/**
 * Full authorization-code-with-PKCE flow for local/CLI contexts.
 *
 * Generates a PKCE pair, builds the authorization URL, opens the user's
 * browser, starts a local loopback HTTP server to receive the redirect,
 * and exchanges the authorization code for tokens.
 *
 * **Requires Node.js.** Uses `node:http` and `node:child_process` via
 * dynamic import. Importing this module is safe in any runtime; only
 * *calling* `authenticate()` requires Node.js.
 */
export async function authenticate(
  issuer: string,
  options: AuthenticateOptions,
): Promise<TokenResponse> {
  const port = options.port ?? 8765;
  const redirectUri = options.redirectUri ?? `http://localhost:${port}/callback`;
  const timeoutMs = options.timeoutMs ?? 300_000;

  const { codeVerifier, codeChallenge } = await generatePkcePair("S256");

  // CSRF protection (RFC 6749 §10.12): bind the loopback callback to this
  // authorization request.
  const stateBytes = new Uint8Array(32);
  crypto.getRandomValues(stateBytes);
  const state = base64url.encode(stateBytes.buffer as ArrayBuffer);

  const metadata = await fetchAuthorizationServerMetadata(issuer);
  if (!metadata.authorization_endpoint) {
    throw new Error(
      `Authorization server "${issuer}" does not advertise an authorization_endpoint`,
    );
  }

  const authUrl = buildAuthorizeUrl(metadata.authorization_endpoint, {
    clientId: options.clientId,
    redirectUri,
    codeChallenge,
    state,
    scope: options.scopes && options.scopes.length > 0 ? options.scopes.join(" ") : undefined,
    resource: options.resource,
  });

  await (options.openBrowser ?? openBrowser)(authUrl);

  const code = await waitForCode(port, redirectUri, timeoutMs, state);

  return exchangeAuthorizationCode(issuer, code, {
    codeVerifier,
    redirectUri,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    resource: options.resource,
  });
}

async function openBrowser(url: string): Promise<void> {
  const { execFile } = await import("node:child_process");
  if (process.platform === "darwin") {
    execFile("open", [url]);
  } else if (process.platform === "win32") {
    // `start` is a cmd.exe built-in, not a standalone executable.
    execFile("cmd", ["/c", "start", "", url]);
  } else {
    execFile("xdg-open", [url]);
  }
}

async function waitForCode(
  port: number,
  redirectUri: string,
  timeoutMs: number,
  expectedState: string,
): Promise<string> {
  // Import before entering the Promise constructor to avoid the async-executor
  // anti-pattern: if the dynamic import throws, the rejection propagates through
  // this async function rather than escaping an async Promise constructor.
  const { createServer } = await import("node:http");

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      server.close();
      reject(new Error(`PKCE authentication timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    const server = createServer((req, res) => {
      try {
        const reqUrl = new URL(req.url ?? "/", redirectUri);
        const code = reqUrl.searchParams.get("code");
        const error = reqUrl.searchParams.get("error");

        res.writeHead(200, { "Content-Type": "text/html" });
        res.end("<html><body><p>Authentication complete. You can close this tab.</p></body></html>");

        server.close();
        clearTimeout(timer);

        if (error) {
          reject(new OAuthError(error, reqUrl.searchParams.get("error_description") ?? error));
        } else if (reqUrl.searchParams.get("state") !== expectedState) {
          reject(new Error("State mismatch in redirect: possible CSRF attack"));
        } else if (code) {
          resolve(code);
        } else {
          reject(new Error("No authorization code in redirect"));
        }
      } catch (e) {
        server.close();
        clearTimeout(timer);
        reject(e);
      }
    });

    server.listen(port, "localhost");
    server.on("error", (err) => {
      clearTimeout(timer);
      reject(new Error(`Failed to start loopback server on port ${port}: ${err.message}`));
    });
  });
}
