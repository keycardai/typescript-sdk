import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { PrivateKeyring, IdentifiableKey } from "@keycardai/oauth/keyring";
import { JWTSigner } from "@keycardai/oauth/jwt/signer";
import base64url from "@keycardai/oauth/base64url";

// =============================================================================
// Storage Interface
// =============================================================================

export interface JsonWebKey {
  kty: string;
  alg?: string;
  use?: string;
  kid?: string;
  n?: string;
  e?: string;
  [key: string]: unknown;
}

export interface PrivateKeyStorage {
  exists(keyId: string): Promise<boolean>;
  storeKeyPair(keyId: string, privateKeyPem: string, publicKeyJwk: JsonWebKey): Promise<void>;
  loadKeyPair(keyId: string): Promise<{ privateKeyPem: string; publicKeyJwk: JsonWebKey }>;
  deleteKeyPair(keyId: string): Promise<boolean>;
  listKeyIds(): Promise<string[]>;
}

// =============================================================================
// File-Based Storage
// =============================================================================

export class FilePrivateKeyStorage implements PrivateKeyStorage {
  #storageDir: string;

  constructor(storageDir: string) {
    this.#storageDir = storageDir;
  }

  async exists(keyId: string): Promise<boolean> {
    try {
      await fs.access(this.#keyPath(keyId));
      await fs.access(this.#metadataPath(keyId));
      return true;
    } catch {
      return false;
    }
  }

  async storeKeyPair(keyId: string, privateKeyPem: string, publicKeyJwk: JsonWebKey): Promise<void> {
    await fs.mkdir(this.#storageDir, { recursive: true });

    const metadata = {
      key_id: keyId,
      public_key_jwk: publicKeyJwk,
      created_at: Date.now() / 1000,
      algorithm: "RS256",
    };

    await fs.writeFile(this.#keyPath(keyId), privateKeyPem, { encoding: "utf-8", mode: 0o600 });
    await fs.writeFile(this.#metadataPath(keyId), JSON.stringify(metadata, null, 2), { encoding: "utf-8", mode: 0o644 });
  }

  async loadKeyPair(keyId: string): Promise<{ privateKeyPem: string; publicKeyJwk: JsonWebKey }> {
    const [privateKeyPem, metadataRaw] = await Promise.all([
      fs.readFile(this.#keyPath(keyId), "utf-8"),
      fs.readFile(this.#metadataPath(keyId), "utf-8"),
    ]);

    const metadata = JSON.parse(metadataRaw);
    return { privateKeyPem, publicKeyJwk: metadata.public_key_jwk };
  }

  async deleteKeyPair(keyId: string): Promise<boolean> {
    let deleted = false;
    try { await fs.unlink(this.#keyPath(keyId)); deleted = true; } catch { /* ignore */ }
    try { await fs.unlink(this.#metadataPath(keyId)); deleted = true; } catch { /* ignore */ }
    return deleted;
  }

  async listKeyIds(): Promise<string[]> {
    try {
      const files = await fs.readdir(this.#storageDir);
      const jsonFiles = files.filter((f) => f.endsWith(".json"));
      const keyIds: string[] = [];
      for (const file of jsonFiles) {
        const keyId = file.replace(/\.json$/, "");
        if (await this.exists(keyId)) {
          keyIds.push(keyId);
        }
      }
      return keyIds.sort();
    } catch {
      return [];
    }
  }

  #keyPath(keyId: string): string {
    return path.join(this.#storageDir, `${keyId}.pem`);
  }

  #metadataPath(keyId: string): string {
    return path.join(this.#storageDir, `${keyId}.json`);
  }
}

// =============================================================================
// Private Key Manager
// =============================================================================

export class PrivateKeyManager {
  #storage: PrivateKeyStorage;
  #keyId: string;
  #audienceConfig?: string | Record<string, string>;
  #privateKeyPem?: string;
  #publicKeyJwk?: JsonWebKey;

  constructor(options: {
    storage: PrivateKeyStorage;
    keyId?: string;
    audienceConfig?: string | Record<string, string>;
  }) {
    this.#storage = options.storage;
    this.#keyId = options.keyId ?? crypto.randomUUID();
    this.#audienceConfig = options.audienceConfig;
  }

  async bootstrapIdentity(): Promise<void> {
    if (await this.#storage.exists(this.#keyId)) {
      const { privateKeyPem, publicKeyJwk } = await this.#storage.loadKeyPair(this.#keyId);
      this.#privateKeyPem = privateKeyPem;
      this.#publicKeyJwk = publicKeyJwk;
    } else {
      await this.#generateAndStoreKeyPair();
    }
  }

  async createClientAssertion(issuer: string, audience: string, expirySeconds = 300): Promise<string> {
    if (!this.#privateKeyPem || !this.#publicKeyJwk) {
      throw new Error("Identity not bootstrapped. Call bootstrapIdentity() first.");
    }

    const keyring = new PemPrivateKeyring(this.#privateKeyPem, this.#keyId, issuer);
    const signer = new JWTSigner(keyring);

    const now = Math.floor(Date.now() / 1000);
    return signer.sign({
      iss: issuer,
      sub: issuer,
      aud: audience,
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + expirySeconds,
    });
  }

  getPublicJwks(): { keys: JsonWebKey[] } {
    if (!this.#publicKeyJwk) {
      throw new Error("Identity not bootstrapped. Call bootstrapIdentity() first.");
    }
    return { keys: [this.#publicKeyJwk] };
  }

  getClientId(): string {
    return this.#keyId;
  }

  getClientJwksUrl(resourceServerUrl: string): string {
    const url = new URL(resourceServerUrl);
    return `${url.protocol}//${url.host}/.well-known/jwks.json`;
  }

  async #generateAndStoreKeyPair(): Promise<void> {
    const keyPair = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const privateKeyPem = String(keyPair.privateKey);
    const publicKeyPem = String(keyPair.publicKey);

    // Convert public key PEM to JWK format
    const publicKeyObj = crypto.createPublicKey(publicKeyPem);
    const jwk = publicKeyObj.export({ format: "jwk" });

    const publicKeyJwk: JsonWebKey = {
      kty: jwk.kty!,
      n: jwk.n!,
      e: jwk.e!,
      kid: this.#keyId,
      alg: "RS256",
      use: "sig",
    };

    await this.#storage.storeKeyPair(this.#keyId, privateKeyPem, publicKeyJwk);

    this.#privateKeyPem = privateKeyPem;
    this.#publicKeyJwk = publicKeyJwk;
  }
}

// =============================================================================
// PEM-based PrivateKeyring adapter (implements PrivateKeyring from @keycardai/oauth)
// =============================================================================

class PemPrivateKeyring implements PrivateKeyring {
  #pem: string;
  #kid: string;
  #issuer: string;

  constructor(pem: string, kid: string, issuer: string) {
    this.#pem = pem;
    this.#kid = kid;
    this.#issuer = issuer;
  }

  async key(_usage: string): Promise<IdentifiableKey> {
    // Import PEM private key as CryptoKey
    const keyObj = crypto.createPrivateKey(this.#pem);
    const jwk = keyObj.export({ format: "jwk" });

    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
      false,
      ["sign"],
    );

    return {
      // node:crypto.webcrypto.CryptoKey and global CryptoKey are identical at runtime
      // but TypeScript treats them as separate declarations
      key: cryptoKey as CryptoKey,
      kid: this.#kid,
      issuer: this.#issuer,
    };
  }
}
