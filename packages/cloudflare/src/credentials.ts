import { basicAuthorization } from "@keycardai/oauth/credentials";
import type { ApplicationCredential, ClientAuthentication } from "@keycardai/oauth/credentials";
import { ConfigurationError } from "@keycardai/oauth/errors";
import type { PrivateKeyring, IdentifiableKey } from "@keycardai/oauth/keyring";
import { JWTSigner } from "@keycardai/oauth/jwt/signer";
import type { TokenExchangeRequest } from "@keycardai/oauth/tokenExchange";

export type { ApplicationCredential } from "@keycardai/oauth/credentials";

const JWT_BEARER_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

// =============================================================================
// WorkersClientSecret — Basic auth credential for Workers
// =============================================================================

export class WorkersClientSecret implements ApplicationCredential {
  #clientId: string;
  #clientSecret: string;

  constructor(clientId: string, clientSecret: string) {
    this.#clientId = clientId;
    this.#clientSecret = clientSecret;
  }

  getAuth(): { clientId: string; clientSecret: string } {
    return { clientId: this.#clientId, clientSecret: this.#clientSecret };
  }

  async clientAuthentication(_issuer: string, _endpoint: string): Promise<ClientAuthentication> {
    return {
      headers: { Authorization: basicAuthorization(this.#clientId, this.#clientSecret) },
      form: {},
    };
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
// WorkersWebIdentity — private_key_jwt credential for Workers (RFC 7523)
// =============================================================================

export class WorkersWebIdentity implements ApplicationCredential {
  #privateKeyPem: string;
  #keyId: string;
  #clientId?: string;
  #cryptoKey?: CryptoKey;
  #publicJwk?: Record<string, unknown>;
  #importPromise?: Promise<void>;

  constructor(privateKeyPem: string, options?: string | { keyId?: string; clientId?: string }) {
    this.#privateKeyPem = privateKeyPem;
    this.#keyId = (typeof options === "string" ? options : options?.keyId) ?? "worker-key";
    const clientId = typeof options === "string" ? undefined : options?.clientId;
    this.#clientId = clientId || undefined;
  }

  getAuth(): null {
    return null;
  }

  async prepareTokenExchangeRequest(
    subjectToken: string,
    resource: string,
    options?: { tokenEndpoint?: string; authInfo?: Record<string, string> },
  ): Promise<TokenExchangeRequest> {
    await this.#ensureImported();
    const issuer = options?.authInfo?.resource_client_id ?? this.#clientId ?? this.#keyId;
    const audience = options?.tokenEndpoint;
    if (!audience) {
      throw new ConfigurationError("WorkersWebIdentity: token endpoint is required for the assertion audience (aud)");
    }

    return {
      subjectToken,
      resource,
      subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
      clientAssertionType: JWT_BEARER_ASSERTION_TYPE,
      clientAssertion: await this.#signAssertion(issuer, audience),
    };
  }

  async clientAuthentication(_issuer: string, endpoint: string): Promise<ClientAuthentication> {
    const clientId = this.#requireClientId();
    if (!endpoint) {
      throw new ConfigurationError("WorkersWebIdentity: endpoint is required for the assertion audience (aud)");
    }
    await this.#ensureImported();
    return {
      headers: {},
      form: {
        client_assertion_type: JWT_BEARER_ASSERTION_TYPE,
        client_assertion: await this.#signAssertion(clientId, endpoint),
      },
    };
  }

  checkClientAuthentication(): void {
    this.#requireClientId();
  }

  #requireClientId(): string {
    if (!this.#clientId) {
      throw new ConfigurationError(
        "WorkersWebIdentity: clientId is required for client authentication (the assertion iss and sub)",
      );
    }
    return this.#clientId;
  }

  #signAssertion(issuer: string, audience: string): Promise<string> {
    const keyring = new WorkersPrivateKeyring(this.#cryptoKey!, this.#keyId, issuer);
    const signer = new JWTSigner(keyring);

    const now = Math.floor(Date.now() / 1000);
    return signer.sign({
      iss: issuer,
      sub: issuer,
      aud: audience,
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + 300,
    });
  }

  /**
   * Returns the public JWKS for serving at /.well-known/jwks.json.
   * Must call after at least one prepareTokenExchangeRequest or importKey.
   */
  async getPublicJwks(): Promise<{ keys: Record<string, unknown>[] }> {
    await this.#ensureImported();
    return { keys: [this.#publicJwk!] };
  }

  async #ensureImported(): Promise<void> {
    if (this.#cryptoKey) return;
    if (!this.#importPromise) {
      this.#importPromise = this.#importKey();
    }
    return this.#importPromise;
  }

  async #importKey(): Promise<void> {
    // WebCrypto only imports PKCS#8 ("BEGIN PRIVATE KEY"). A PKCS#1 key
    // ("BEGIN RSA PRIVATE KEY", the OpenSSL 1.x `openssl genrsa` default)
    // would fail deep inside crypto.subtle.importKey with an opaque
    // DataError, so detect it up front and explain how to convert.
    if (this.#privateKeyPem.includes("-----BEGIN RSA PRIVATE KEY-----")) {
      throw new Error(
        'Private key is in PKCS#1 format ("BEGIN RSA PRIVATE KEY"), which WebCrypto cannot import. ' +
          "Convert it to unencrypted PKCS#8: " +
          "openssl pkcs8 -topk8 -nocrypt -in private-key.pem -out private-key-pkcs8.pem " +
          "(openssl prompts for the passphrase if the key is encrypted)",
      );
    }
    if (this.#privateKeyPem.includes("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
      throw new Error(
        'Private key is encrypted PKCS#8 ("BEGIN ENCRYPTED PRIVATE KEY"), which WebCrypto cannot import. ' +
          "Decrypt it to unencrypted PKCS#8: " +
          "openssl pkcs8 -topk8 -nocrypt -in private-key.pem -out private-key-pkcs8.pem",
      );
    }

    // Strip PEM headers and decode
    const pemBody = this.#privateKeyPem
      .replace(/-----BEGIN PRIVATE KEY-----/g, "")
      .replace(/-----END PRIVATE KEY-----/g, "")
      .replace(/\s/g, "");

    const binaryDer = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));

    // Import as private key for signing
    this.#cryptoKey = await crypto.subtle.importKey(
      "pkcs8",
      binaryDer.buffer,
      { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
      true, // extractable — needed to export public JWK
      ["sign"],
    );

    // Export public key as JWK
    const jwk = await crypto.subtle.exportKey("jwk", this.#cryptoKey);
    this.#publicJwk = {
      kty: jwk.kty,
      n: jwk.n,
      e: jwk.e,
      kid: this.#keyId,
      alg: "RS256",
      use: "sig",
    };
  }
}

// =============================================================================
// WorkersPrivateKeyring — adapts a CryptoKey for JWTSigner
// =============================================================================

class WorkersPrivateKeyring implements PrivateKeyring {
  #key: CryptoKey;
  #kid: string;
  #issuer: string;

  constructor(key: CryptoKey, kid: string, issuer: string) {
    this.#key = key;
    this.#kid = kid;
    this.#issuer = issuer;
  }

  async key(_usage: string): Promise<IdentifiableKey> {
    return {
      key: this.#key,
      kid: this.#kid,
      issuer: this.#issuer,
    };
  }
}
