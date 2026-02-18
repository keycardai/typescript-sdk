import { OAuthProtectedResourceMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";

export type InferredOAuthProtectedResourceMetadata = Omit<OAuthProtectedResourceMetadata, "resource">;
