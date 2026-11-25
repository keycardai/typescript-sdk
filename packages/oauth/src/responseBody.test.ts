import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { gzipSync } from "node:zlib";
import {
  ClientCredentialsClient,
  DeviceGrantError,
  DevicePollError,
  fetchAuthorizationServerMetadata,
  fetchUserInfo,
  JWKSDiscoveryError,
  JWKSFetchError,
  JWKSOAuthKeyring,
  MAX_RESPONSE_BODY_BYTES,
  OAuthError,
  pollDeviceToken,
  refreshAuthorization,
  RefreshGrantError,
  registerClient,
  ResponseBodyTooLargeError,
  TokenEndpointDiscoveryError,
  TokenExchangeClient,
  waitForDeviceToken,
  type Clock,
  type DeviceAuthorization,
  type OAuthAuthorizationServerMetadata,
} from "./index.js";

async function catchError(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn();
  } catch (err) {
    return err;
  }
  throw new Error("Expected promise to reject");
}

function startServer(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<{ url: string; close: () => Promise<void> }> {
  return new Promise((resolve, reject) => {
    const server: Server = createServer(handler);
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("Unexpected server address"));
        return;
      }
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close: () =>
          new Promise<void>((resClose, rejClose) => {
            server.close((err) => (err ? rejClose(err) : resClose()));
          }),
      });
    });
  });
}

function makeOversizedJson(extra = 64): string {
  const prefix = '{"access_token":"tok","token_type":"Bearer","pad":"';
  const suffix = '"}';
  const padLen = MAX_RESPONSE_BODY_BYTES - prefix.length - suffix.length + extra;
  return prefix + "a".repeat(padLen) + suffix;
}

function makeExactLimitJson(): string {
  const prefix = '{"access_token":"tok","token_type":"Bearer","pad":"';
  const suffix = '"}';
  const padLen = MAX_RESPONSE_BODY_BYTES - prefix.length - suffix.length;
  return prefix + "a".repeat(padLen) + suffix;
}

function fakeClock(startMs = 1_000_000): Clock {
  let now = startMs;
  return {
    now: () => now,
    sleep: async (ms: number) => {
      now += ms;
    },
  };
}

describe("Response body size limit (specs/base.md rows 1, 1a, 1b, 1c; device row 36)", () => {
  it("base row 1: gzip token response inflating above 1 MiB fails with invalid_response", async () => {
    const compressed = gzipSync(Buffer.from(makeOversizedJson(1024), "utf8"));
    expect(compressed.byteLength).toBeLessThan(MAX_RESPONSE_BODY_BYTES);

    const server = await startServer((req, res) => {
      if (req.url === "/.well-known/oauth-authorization-server") {
        res.writeHead(200, { "Content-Type": "application/json", Connection: "close" });
        res.end(JSON.stringify({ issuer: server.url, token_endpoint: `${server.url}/token` }));
        return;
      }
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
        Connection: "close",
      });
      res.end(compressed);
    });

    try {
      const client = new ClientCredentialsClient(server.url, {
        clientId: "cid",
        clientSecret: "csec",
      });
      const err = await catchError(() => client.requestToken());
      expect(err).toBeInstanceOf(ResponseBodyTooLargeError);
      const e = err as ResponseBodyTooLargeError;
      expect(e.errorCode).toBe("invalid_response");
      expect(e.status).toBe(200);
      expect(e.retryable).toBe(true);
    } finally {
      await server.close();
    }
  });

  it("base row 1: exact 1 MiB decoded body succeeds and 1 MiB + 1 byte fails", async () => {
    let oversized = false;
    const exact = makeExactLimitJson();
    expect(Buffer.byteLength(exact, "utf8")).toBe(MAX_RESPONSE_BODY_BYTES);
    const over = makeOversizedJson(1);
    expect(Buffer.byteLength(over, "utf8")).toBe(MAX_RESPONSE_BODY_BYTES + 1);

    const server = await startServer((req, res) => {
      if (req.url === "/.well-known/oauth-authorization-server") {
        res.writeHead(200, { "Content-Type": "application/json", Connection: "close" });
        res.end(JSON.stringify({ issuer: server.url, token_endpoint: `${server.url}/token` }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json", Connection: "close" });
      res.end(oversized ? over : exact);
    });

    try {
      const client = new ClientCredentialsClient(server.url, {
        clientId: "cid",
        clientSecret: "csec",
      });
      const tok = await client.requestToken();
      expect(tok.accessToken).toBe("tok");

      oversized = true;
      await expect(client.requestToken()).rejects.toBeInstanceOf(ResponseBodyTooLargeError);
    } finally {
      await server.close();
    }
  });

  it.each([
    [200, true, false],
    [429, true, false],
    [503, true, false],
    [400, false, true],
  ])(
    "base row 1a: cached discovery with oversized status %i (retryable=%s, negativelyCached=%s)",
    async (status, expectedRetryable, expectNegativelyCached) => {
      let calls = 0;
      let failFirst = true;

      const server = await startServer((_req, res) => {
        calls += 1;
        if (failFirst) {
          res.writeHead(status, { "Content-Type": "application/json", Connection: "close" });
          res.end(makeOversizedJson(2048));
          return;
        }
        res.writeHead(200, { "Content-Type": "application/json", Connection: "close" });
        res.end(JSON.stringify({ issuer: server.url, token_endpoint: `${server.url}/token` }));
      });

      try {
        const client = new TokenExchangeClient(server.url, {
          clientId: "cid",
          clientSecret: "csec",
          negativeTtlMs: 60_000,
        });

        const err = await catchError(() => client.getTokenEndpoint());
        expect(err).toBeInstanceOf(TokenEndpointDiscoveryError);
        expect((err as TokenEndpointDiscoveryError).retryable).toBe(expectedRetryable);
        expect(calls).toBe(1);

        failFirst = false;
        if (expectNegativelyCached) {
          await expect(client.getTokenEndpoint()).rejects.toBeInstanceOf(
            TokenEndpointDiscoveryError,
          );
          expect(calls).toBe(1);
        } else {
          const ep = await client.getTokenEndpoint();
          expect(ep).toBe(`${server.url}/token`);
          expect(calls).toBe(2);
        }
      } finally {
        await server.close();
      }
    },
  );

  it("base row 1a: JWKS discovery overflow maps to JWKSDiscoveryError and JWKS fetch overflow maps to JWKSFetchError", async () => {
    let mode: "oversized_discovery" | "oversized_jwks" = "oversized_discovery";

    const server = await startServer((req, res) => {
      if (req.url === "/.well-known/oauth-authorization-server") {
        res.writeHead(200, { "Content-Type": "application/json", Connection: "close" });
        if (mode === "oversized_discovery") {
          res.end(makeOversizedJson(1024));
        } else {
          res.end(JSON.stringify({ issuer: server.url, jwks_uri: `${server.url}/jwks.json` }));
        }
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json", Connection: "close" });
      res.end(makeOversizedJson(1024));
    });

    try {
      const keyring = new JWKSOAuthKeyring();
      await expect(keyring.key(server.url, "k1")).rejects.toBeInstanceOf(JWKSDiscoveryError);

      mode = "oversized_jwks";
      await expect(keyring.key(server.url, "k1")).rejects.toBeInstanceOf(JWKSFetchError);
    } finally {
      await server.close();
    }
  });

  it("base row 1c: token endpoint 400 with oversized body raises invalid_response without parsing OAuth error", async () => {
    const prefix = '{"error":"invalid_grant","error_description":"';
    const suffix = '"}';
    const body = prefix + "x".repeat(MAX_RESPONSE_BODY_BYTES - prefix.length - suffix.length + 256) + suffix;

    const server = await startServer((req, res) => {
      if (req.url === "/.well-known/oauth-authorization-server") {
        res.writeHead(200, { "Content-Type": "application/json", Connection: "close" });
        res.end(JSON.stringify({ issuer: server.url, token_endpoint: `${server.url}/token` }));
        return;
      }
      res.writeHead(400, { "Content-Type": "application/json", Connection: "close" });
      res.end(body);
    });

    try {
      const client = new TokenExchangeClient(server.url, {
        clientId: "cid",
        clientSecret: "csec",
      });
      const teErr = await catchError(() =>
        client.exchangeToken({ subjectToken: "sub-tok", resource: "https://api.example" }),
      );
      expect(teErr).toBeInstanceOf(ResponseBodyTooLargeError);
      const te = teErr as ResponseBodyTooLargeError;
      expect(te.errorCode).toBe("invalid_response");
      expect(te.status).toBe(400);
      expect(te.retryable).toBe(false);

      const meta: OAuthAuthorizationServerMetadata = {
        issuer: server.url,
        token_endpoint: `${server.url}/token`,
      };
      const rfErr = await catchError(() =>
        refreshAuthorization(server.url, {
          refreshToken: "rt-1",
          clientId: "cid",
          metadata: meta,
        }),
      );
      expect(rfErr).toBeInstanceOf(RefreshGrantError);
      const rf = rfErr as RefreshGrantError;
      expect(rf.errorCode).toBe("invalid_response");
      expect(rf.status).toBe(400);
      expect(rf.retryable).toBe(false);
    } finally {
      await server.close();
    }
  });

  it.each([
    [429, true],
    [503, true],
  ])(
    "base row 1b & device row 36: waitForDeviceToken wraps oversized %i in DevicePollError with undoubled interval",
    async (status) => {
      let pollCount = 0;
      const server = await startServer((_req, res) => {
        pollCount += 1;
        if (pollCount === 1) {
          res.writeHead(400, { "Content-Type": "application/json", Connection: "close" });
          res.end(JSON.stringify({ error: "slow_down" }));
          return;
        }
        res.writeHead(status, { "Content-Type": "application/json", Connection: "close" });
        res.end(makeOversizedJson(1024));
      });

      try {
        const clock = fakeClock();
        const auth: DeviceAuthorization = {
          deviceCode: "dev-1",
          userCode: "ABCD-1234",
          verificationUri: `${server.url}/verify`,
          expiresIn: 600,
          interval: 5,
          expiresAt: clock.now() + 600_000,
        };
        const metadata: OAuthAuthorizationServerMetadata = {
          issuer: server.url,
          token_endpoint: `${server.url}/token`,
        };

        const err = await catchError(() =>
          waitForDeviceToken(server.url, {
            clientId: "cid",
            authorization: auth,
            metadata,
            clock,
          }),
        );
        expect(err).toBeInstanceOf(DevicePollError);
        const pollErr = err as DevicePollError;
        // slow_down raised 5 -> 10; oversized 429/503 does NOT double to 20.
        expect(pollErr.interval).toBe(10);
        expect(pollErr.cause).toBeInstanceOf(DeviceGrantError);
        const cause = pollErr.cause as DeviceGrantError;
        expect(cause.errorCode).toBe("invalid_response");
        expect(cause.status).toBe(status);
        expect(cause.retryable).toBe(true);
      } finally {
        await server.close();
      }
    },
  );

  it.each([
    [200, true],
    [400, false],
    [429, true],
    [503, true],
  ])(
    "device row 36: pollDeviceToken oversized status %i throws DeviceGrantError invalid_response (retryable=%s)",
    async (status, expectedRetryable) => {
      const server = await startServer((_req, res) => {
        res.writeHead(status, { "Content-Type": "application/json", Connection: "close" });
        res.end(makeOversizedJson(512));
      });

      try {
        const auth: DeviceAuthorization = {
          deviceCode: "dev-1",
          userCode: "ABCD-1234",
          verificationUri: `${server.url}/verify`,
          expiresIn: 600,
          interval: 5,
          expiresAt: Date.now() + 600_000,
        };
        const metadata: OAuthAuthorizationServerMetadata = {
          issuer: server.url,
          token_endpoint: `${server.url}/token`,
        };

        const err = await catchError(() =>
          pollDeviceToken(server.url, {
            clientId: "cid",
            authorization: auth,
            metadata,
          }),
        );
        expect(err).toBeInstanceOf(DeviceGrantError);
        const e = err as DeviceGrantError;
        expect(e.errorCode).toBe("invalid_response");
        expect(e.status).toBe(status);
        expect(e.retryable).toBe(expectedRetryable);
      } finally {
        await server.close();
      }
    },
  );

  it("DCR, discovery, and UserInfo reject oversized 200 bodies with invalid_response", async () => {
    const server = await startServer((req, res) => {
      if (req.url === "/.well-known/oauth-authorization-server") {
        res.writeHead(200, { "Content-Type": "application/json", Connection: "close" });
        res.end(
          JSON.stringify({
            issuer: server.url,
            registration_endpoint: `${server.url}/register`,
            userinfo_endpoint: `${server.url}/userinfo`,
          }),
        );
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json", Connection: "close" });
      res.end(makeOversizedJson(1024));
    });

    try {
      const dcrErr = await catchError(() => registerClient(server.url, { clientName: "app" }));
      expect(dcrErr).toBeInstanceOf(OAuthError);
      expect((dcrErr as OAuthError).errorCode).toBe("invalid_response");

      const uiErr = await catchError(() => fetchUserInfo(server.url, "tok"));
      expect(uiErr).toBeInstanceOf(OAuthError);
      expect((uiErr as OAuthError).errorCode).toBe("invalid_response");
    } finally {
      await server.close();
    }

    const oversizedMetaServer = await startServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json", Connection: "close" });
      res.end(makeOversizedJson(1024));
    });
    try {
      await expect(fetchAuthorizationServerMetadata(oversizedMetaServer.url)).rejects.toBeInstanceOf(
        ResponseBodyTooLargeError,
      );
    } finally {
      await oversizedMetaServer.close();
    }
  });
});
