/**
 * OAuth 2.1 Handler for MCP Server
 * Enables ChatGPT and other clients to authenticate using OAuth tokens
 */

import { IncomingMessage, ServerResponse } from 'node:http';
import * as jwt from 'jsonwebtoken';
import jwksClient, { JwksClient, SigningKey } from 'jwks-rsa';
import { logger } from '../monitoring/logger.js';

/**
 * OAuth configuration
 */
export interface OAuthConfig {
  domain: string;
  audience: string;
  issuer?: string;
  required?: boolean;
}

/**
 * Token payload from JWT
 */
export interface TokenPayload {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  scope?: string;
  [key: string]: unknown;
}

/**
 * Authentication result
 */
export interface AuthResult {
  authenticated: boolean;
  userId?: string;
  scopes?: string[];
  error?: string;
  errorCode?: 'invalid_token' | 'missing_token' | 'insufficient_scope';
}

// JWKS client cache
let jwksClientInstance: JwksClient | null = null;

/**
 * Get or create JWKS client
 */
function getJwksClient(domain: string): JwksClient {
  if (!jwksClientInstance) {
    jwksClientInstance = jwksClient({
      jwksUri: `https://${domain}/.well-known/jwks.json`,
      cache: true,
      cacheMaxAge: 600000, // 10 minutes
      rateLimit: true,
      jwksRequestsPerMinute: 10,
    });
  }
  return jwksClientInstance;
}

/**
 * Get signing key from JWKS
 */
async function getSigningKey(client: JwksClient, kid: string): Promise<string> {
  return new Promise((resolve, reject) => {
    client.getSigningKey(kid, (err: Error | null, key?: SigningKey) => {
      if (err) {
        reject(err);
        return;
      }
      if (!key) {
        reject(new Error('No signing key found'));
        return;
      }
      resolve(key.getPublicKey());
    });
  });
}

/**
 * Extract Bearer token from Authorization header
 */
export function extractBearerToken(req: IncomingMessage): string | null {
  const authHeader = req.headers.authorization;
  if (!authHeader) return null;

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return null;
  }
  return parts[1];
}

/**
 * Validate OAuth token from request
 */
export async function validateToken(
  req: IncomingMessage,
  config: OAuthConfig
): Promise<AuthResult> {
  const token = extractBearerToken(req);

  if (!token) {
    return {
      authenticated: false,
      error: 'No bearer token provided',
      errorCode: 'missing_token',
    };
  }

  const {
    domain,
    audience,
    issuer = `https://${domain}/`,
  } = config;

  try {
    // Decode token header to get key ID
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded === 'string') {
      return {
        authenticated: false,
        error: 'Invalid token format',
        errorCode: 'invalid_token',
      };
    }

    const { header } = decoded;
    if (!header.kid) {
      return {
        authenticated: false,
        error: 'Token missing key ID',
        errorCode: 'invalid_token',
      };
    }

    // Get signing key from JWKS
    const client = getJwksClient(domain);
    const signingKey = await getSigningKey(client, header.kid);

    // Verify token
    const payload = jwt.verify(token, signingKey, {
      algorithms: ['RS256'],
      issuer,
      audience,
    }) as TokenPayload;

    // Parse scopes
    const scopes = payload.scope ? payload.scope.split(' ') : [];

    logger.info(`OAuth: Authenticated user ${payload.sub}`);

    return {
      authenticated: true,
      userId: payload.sub,
      scopes,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    logger.warn(`OAuth: Token validation failed - ${message}`);

    return {
      authenticated: false,
      error: message,
      errorCode: 'invalid_token',
    };
  }
}

/**
 * Check if request is for OAuth metadata endpoint
 */
export function isOAuthMetadataRequest(req: IncomingMessage): boolean {
  return req.url === '/.well-known/oauth-protected-resource';
}

/**
 * Serve OAuth Protected Resource metadata
 */
export function serveOAuthMetadata(
  req: IncomingMessage,
  res: ServerResponse,
  resourceUrl: string,
  authServerUrl: string
): void {
  if (req.method !== 'GET') {
    res.writeHead(405, { 'Content-Type': 'application/json', 'Allow': 'GET' });
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  const metadata = {
    resource: resourceUrl,
    authorization_servers: [authServerUrl],
    bearer_methods_supported: ['header'],
  };

  res.writeHead(200, {
    'Content-Type': 'application/json',
    'Cache-Control': 'public, max-age=3600',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  });
  res.end(JSON.stringify(metadata));
}

/**
 * Send 401 Unauthorized response with WWW-Authenticate header
 */
export function send401Response(
  res: ServerResponse,
  resourceUrl: string,
  errorCode?: 'invalid_token' | 'missing_token' | 'insufficient_scope',
  errorDescription?: string
): void {
  const metadataUrl = `${resourceUrl.replace(/\/mcp$/, '')}/.well-known/oauth-protected-resource`;

  const parts = [
    `Bearer realm="${resourceUrl}"`,
    `resource_metadata="${metadataUrl}"`,
  ];

  if (errorCode) {
    const oauthError = errorCode === 'missing_token' ? 'invalid_request' : errorCode;
    parts.push(`error="${oauthError}"`);
  }

  if (errorDescription) {
    parts.push(`error_description="${errorDescription}"`);
  }

  res.writeHead(401, {
    'WWW-Authenticate': parts.join(', '),
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-session-id, Accept',
    'Access-Control-Expose-Headers': 'WWW-Authenticate',
  });

  res.end(JSON.stringify({
    error: errorCode === 'missing_token' ? 'invalid_request' : errorCode,
    error_description: errorDescription || 'Authentication required',
  }));
}
