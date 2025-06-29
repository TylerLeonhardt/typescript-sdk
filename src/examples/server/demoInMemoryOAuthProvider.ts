import { randomUUID } from 'node:crypto';
import { AuthorizationParams, OAuthServerProvider } from '../../server/auth/provider.js';
import { OAuthRegisteredClientsStore } from '../../server/auth/clients.js';
import { OAuthClientInformationFull, OAuthMetadata, OAuthTokens } from 'src/shared/auth.js';
import express, { Request, Response } from "express";
import { AuthInfo } from 'src/server/auth/types.js';
import { createOAuthMetadata, mcpAuthRouter } from 'src/server/auth/router.js';


export class DemoInMemoryClientsStore implements OAuthRegisteredClientsStore {
  private clients = new Map<string, OAuthClientInformationFull>();

  async getClient(clientId: string) {
    return this.clients.get(clientId);
  }

  async registerClient(clientMetadata: OAuthClientInformationFull) {
    this.clients.set(clientMetadata.client_id, clientMetadata);
    return clientMetadata;
  }
}

/**
 * 🚨 DEMO ONLY - NOT FOR PRODUCTION
 *
 * This example demonstrates MCP OAuth flow but lacks some of the features required for production use,
 * for example:
 * - Persistent token storage
 * - Rate limiting
 */
export class DemoInMemoryAuthProvider implements OAuthServerProvider {
  clientsStore = new DemoInMemoryClientsStore();
  private codes = new Map<string, {
    params: AuthorizationParams,
    client: OAuthClientInformationFull}>();
  private tokens = new Map<string, AuthInfo>();
  private refreshTokens = new Map<string, AuthInfo>();

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response
  ): Promise<void> {
    const code = randomUUID();

    const searchParams = new URLSearchParams({
      code,
    });
    if (params.state !== undefined) {
      searchParams.set('state', params.state);
    }

    this.codes.set(code, {
      client,
      params
    });

    const targetUrl = new URL(params.redirectUri);
    targetUrl.search = searchParams.toString();
    res.redirect(targetUrl.toString());
  }

  async challengeForAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {

    // Store the challenge with the code data
    const codeData = this.codes.get(authorizationCode);
    if (!codeData) {
      throw new Error('Invalid authorization code');
    }

    return codeData.params.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    // Note: code verifier is checked in token.ts by default
    // it's unused here for that reason.
    _codeVerifier?: string
  ): Promise<OAuthTokens> {
    const codeData = this.codes.get(authorizationCode);
    if (!codeData) {
      throw new Error('Invalid authorization code');
    }

    if (codeData.client.client_id !== client.client_id) {
      throw new Error(`Authorization code was not issued to this client, ${codeData.client.client_id} != ${client.client_id}`);
    }

    this.codes.delete(authorizationCode);
    const accessToken = randomUUID();
    const refreshToken = randomUUID();

    const tokenData = {
      token: accessToken,
      clientId: client.client_id,
      scopes: codeData.params.scopes || [],
      expiresAt: Math.floor((Date.now() + 600000) / 1000), // 10 minutes
    };

    const refreshTokenData = {
      token: refreshToken,
      clientId: client.client_id,
      scopes: codeData.params.scopes || [],
      expiresAt: Math.floor((Date.now() + 7 * 24 * 3600000) / 1000), // 7 days
    };

    this.tokens.set(accessToken, tokenData);
    this.refreshTokens.set(refreshToken, refreshTokenData);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'bearer',
      expires_in: 600, // 10 minutes
      scope: (codeData.params.scopes || []).join(' '),
    };
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[]
  ): Promise<OAuthTokens> {
    // Check if refresh token exists and is valid
    const existingTokenData = this.refreshTokens.get(refreshToken);
    if (!existingTokenData) {
      throw new Error('Invalid refresh token');
    }

    if (existingTokenData.clientId !== client.client_id) {
      throw new Error('Refresh token was not issued to this client');
    }

    // Check if refresh token is expired
    if (existingTokenData.expiresAt && existingTokenData.expiresAt < Math.floor(Date.now() / 1000)) {
      this.refreshTokens.delete(refreshToken);
      throw new Error('Refresh token has expired');
    }

    // Remove the old refresh token
    this.refreshTokens.delete(refreshToken);

    // Generate new access token
    const newAccessToken = randomUUID();
    const newRefreshToken = randomUUID();

    // Use provided scopes or fall back to existing scopes
    const tokenScopes = scopes || existingTokenData.scopes;

    // Store new access token
    this.tokens.set(newAccessToken, {
      token: newAccessToken,
      clientId: client.client_id,
      scopes: tokenScopes,
      expiresAt: Math.floor((Date.now() + 600000) / 1000), // 10 minutes
    });

    // Store new refresh token
    this.refreshTokens.set(newRefreshToken, {
      token: newRefreshToken,
      clientId: client.client_id,
      scopes: tokenScopes,
      expiresAt: Math.floor((Date.now() + 7 * 24 * 3600000) / 1000), // 7 days
    });

    return {
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
      token_type: 'bearer',
      expires_in: 600, // 10 minutes
      scope: tokenScopes.join(' '),
    };
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const tokenData = this.tokens.get(token);
    if (!tokenData || (tokenData.expiresAt && tokenData.expiresAt < Math.floor(Date.now() / 1000))) {
      throw new Error('Invalid or expired token');
    }

    return {
      token,
      clientId: tokenData.clientId,
      scopes: tokenData.scopes,
      expiresAt: tokenData.expiresAt,
    };
  }
}


export const setupAuthServer = (authServerUrl: URL): OAuthMetadata => {
  // Create separate auth server app
  // NOTE: This is a separate app on a separate port to illustrate
  // how to separate an OAuth Authorization Server from a Resource
  // server in the SDK. The SDK is not intended to be provide a standalone
  // authorization server.
  const provider = new DemoInMemoryAuthProvider();
  const authApp = express();
  authApp.use(express.json());
  // For introspection requests
  authApp.use(express.urlencoded());

  // Add OAuth routes to the auth server
  // NOTE: this will also add a protected resource metadata route,
  // but it won't be used, so leave it.
  authApp.use(mcpAuthRouter({
    provider,
    issuerUrl: authServerUrl,
    scopesSupported: ['mcp:tools'],
  }));

  authApp.post('/introspect', async (req: Request, res: Response) => {
    try {
      const { token } = req.body;
      if (!token) {
        res.status(400).json({ error: 'Token is required' });
        return;
      }

      const tokenInfo = await provider.verifyAccessToken(token);
      res.json({
        active: true,
        client_id: tokenInfo.clientId,
        scope: tokenInfo.scopes.join(' '),
        exp: tokenInfo.expiresAt
      });
      return
    } catch (error) {
      res.status(401).json({
        active: false,
        error: 'Unauthorized',
        error_description: `Invalid token: ${error}`
      });
    }
  });

  const auth_port = authServerUrl.port;
  // Start the auth server
  authApp.listen(auth_port, () => {
    console.log(`OAuth Authorization Server listening on port ${auth_port}`);
  });

  // Note: we could fetch this from the server, but then we end up
  // with some top level async which gets annoying.
  const oauthMetadata: OAuthMetadata = createOAuthMetadata({
    provider,
    issuerUrl: authServerUrl,
    scopesSupported: ['mcp:tools'],
  })

  oauthMetadata.introspection_endpoint = new URL("/introspect", authServerUrl).href;

  return oauthMetadata;
}
