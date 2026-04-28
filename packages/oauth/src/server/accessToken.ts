export interface AccessToken {
  token: string;
  clientId: string;
  scopes: string[];
  expiresAt?: number;
  resource?: string;
}
