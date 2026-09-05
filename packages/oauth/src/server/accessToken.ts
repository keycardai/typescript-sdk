/**
 * Verified access token, populated from the token's claims.
 *
 * The identity fields answer different questions, so key on the right one:
 *
 * - `clientId`: the OAuth client that authenticated. Names the credential,
 *   which rotates, not the application.
 * - `keycardAppId`: the stable Keycard application identifier. Key on this to
 *   identify the calling application regardless of grant type or which
 *   credential authenticated.
 * - `sub`: the user on a user-present token, the application on an
 *   application token (equal to `keycardAppId` when `subProfile` is `"app"`).
 * - `subProfile`: `"user"` when a user authorized access, `"app"` when an
 *   application acts on its own behalf.
 *
 * `subProfile` and `keycardAppId` are Keycard claims and are undefined on a
 * token from another issuer.
 */
export interface AccessToken {
  token: string;
  clientId: string;
  scopes: string[];
  expiresAt?: number;
  resource?: string;
  sub?: string;
  subProfile?: string;
  keycardAppId?: string;
}
