import base64url from "./base64url.js";
import { fetchAuthorizationServerMetadata } from "./discovery.js";
import { OAuthError } from "./errors.js";
import type { TokenResponse } from "./tokenExchange.js";

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
 * Returns a 43-character base64url string (32 random bytes). Runtime-agnostic:
 * uses the global `crypto.getRandomValues` which is available in Node 19+,
 * Cloudflare Workers, and browsers.
 */
export function generateCodeVerifier(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64url.encode(bytes.buffer as ArrayBuffer);
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
export async function generatePkcePair(method: "S256" | "plain" = "S256"): Promise<Pkce> {
  const codeVerifier = generateCodeVerifier();
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
  signal?: AbortSignal;
}

/**
 * Exchange an authorization code for tokens (RFC 6749 §4.1.3 + RFC 7636).
 *
 * Discovers `token_endpoint` from the AS metadata, then POSTs
 * `grant_type=authorization_code` with the code verifier.
 */
export async function exchangeAuthorizationCode(
  issuerUrl: string,
  code: string,
  options: ExchangeAuthorizationCodeOptions,
): Promise<TokenResponse> {
  const metadata = await fetchAuthorizationServerMetadata(issuerUrl, {
    signal: options.signal,
  });
  if (!metadata.token_endpoint) {
    throw new Error(
      `Authorization server "${issuerUrl}" does not advertise a token_endpoint`,
    );
  }

  const params = new URLSearchParams();
  params.set("grant_type", "authorization_code");
  params.set("code", code);
  params.set("code_verifier", options.codeVerifier);
  params.set("redirect_uri", options.redirectUri);
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
    throw new Error(`Authorization code exchange failed (HTTP ${response.status})`);
  }

  const json = await response.json() as unknown;
  if (!json || typeof json !== "object" || Array.isArray(json)) {
    throw new Error("Token endpoint response is not a valid JSON object");
  }
  const body = json as Record<string, unknown>;

  const accessToken = body.access_token;
  if (typeof accessToken !== "string" || !accessToken) {
    throw new Error("Token endpoint response missing access_token");
  }

  const tokenResponse: TokenResponse = {
    accessToken,
    tokenType: typeof body.token_type === "string" ? body.token_type : "bearer",
  };
  if (typeof body.expires_in === "number") tokenResponse.expiresIn = body.expires_in;
  if (typeof body.refresh_token === "string") tokenResponse.refreshToken = body.refresh_token;
  if (typeof body.scope === "string") {
    tokenResponse.scope = body.scope.split(" ").filter(Boolean);
  }
  return tokenResponse;
}

// =============================================================================
// High-level authenticate() flow (Node.js only)
// =============================================================================

export interface AuthenticateOptions {
  clientId: string;
  /** Default: "http://localhost:{port}/callback" */
  redirectUri?: string;
  /** Default: 8080 */
  port?: number;
  scopes?: readonly string[];
  clientSecret?: string;
  /** Default: 60_000 ms */
  timeoutMs?: number;
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
  issuerUrl: string,
  options: AuthenticateOptions,
): Promise<TokenResponse> {
  const port = options.port ?? 8080;
  const redirectUri = options.redirectUri ?? `http://localhost:${port}/callback`;
  const timeoutMs = options.timeoutMs ?? 60_000;

  const { codeVerifier, codeChallenge } = await generatePkcePair("S256");

  const metadata = await fetchAuthorizationServerMetadata(issuerUrl);
  if (!metadata.authorization_endpoint) {
    throw new Error(
      `Authorization server "${issuerUrl}" does not advertise an authorization_endpoint`,
    );
  }

  const authUrl = new URL(metadata.authorization_endpoint);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", options.clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  if (options.scopes && options.scopes.length > 0) {
    authUrl.searchParams.set("scope", options.scopes.join(" "));
  }

  await openBrowser(authUrl.toString());

  const code = await waitForCode(port, redirectUri, timeoutMs);

  return exchangeAuthorizationCode(issuerUrl, code, {
    codeVerifier,
    redirectUri,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
  });
}

async function openBrowser(url: string): Promise<void> {
  const { exec } = await import("node:child_process");
  const cmd = process.platform === "darwin" ? `open "${url}"`
            : process.platform === "win32"  ? `start "" "${url}"`
            : `xdg-open "${url}"`;
  exec(cmd);
}

function waitForCode(port: number, redirectUri: string, timeoutMs: number): Promise<string> {
  return new Promise(async (resolve, reject) => {
    const { createServer } = await import("node:http");

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
