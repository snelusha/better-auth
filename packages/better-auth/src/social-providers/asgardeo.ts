import { betterFetch } from "@better-fetch/fetch";

import {
  createAuthorizationURL,
  validateAuthorizationCode,
  refreshAccessToken,
} from "../oauth2";

import type { OAuthProvider, ProviderOptions } from "../oauth2";

export interface AsgardeoProfile {
  sub: string;
  email: string;
  email_verified: boolean;
  given_name: string;
  family_name: string;
  picture: string;
}

export interface AsgardeoOptions extends ProviderOptions {
  issuer: string;
}

const issuerToEndpoints = (issuer: string) => ({
  authorizationEndpoint: `${issuer}/oauth2/authorize`,
  tokenEndpoint: `${issuer}/oauth2/token`,
  userInfoEndpoint: `${issuer}/oauth2/userinfo`,
});

export const asgardeo = (options: AsgardeoOptions) => {
  const { authorizationEndpoint, tokenEndpoint, userInfoEndpoint } =
    issuerToEndpoints(options.issuer);

  const issuerId = "asgardeo";
  const issuerName = "Asgardeo";

  return {
    id: issuerId,
    name: issuerName,
    createAuthorizationURL: async ({
      state,
      scopes,
      codeVerifier,
      loginHint,
      redirectURI,
    }) => {
      const _scopes = options.disableDefaultScope
        ? []
        : ["openid", "profile", "email"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);

      return createAuthorizationURL({
        id: issuerId,
        options,
        authorizationEndpoint,
        scopes: _scopes,
        state,
        redirectURI,
        codeVerifier,
        loginHint,
      });
    },
    validateAuthorizationCode: async ({ code, codeVerifier, redirectURI }) => {
      return validateAuthorizationCode({
        options,
        tokenEndpoint,
        code,
        codeVerifier,
        redirectURI,
      });
    },
    refreshAccessToken: options.refreshAccessToken
      ? options.refreshAccessToken
      : async (refreshToken) =>
          refreshAccessToken({
            refreshToken,
            options: {
              clientId: options.clientId,
              clientKey: options.clientKey,
              clientSecret: options.clientSecret,
            },
            tokenEndpoint,
          }),
    async getUserInfo(token) {
      if (options.getUserInfo) return options.getUserInfo(token);
      const { data: profile, error } = await betterFetch<AsgardeoProfile>(
        userInfoEndpoint,
        { headers: { Authorization: `Bearer ${token}` } },
      );
      if (error) return null;

      console.log("[better-auth]:getUserInfo:profile", profile);

      return {
        user: {
          id: profile.sub,
          email: profile.email,
          emailVerified: profile.email_verified,
          name: `${profile.given_name} ${profile.family_name}`,
          image: profile.picture,
        },
        data: profile,
      };
    },
    options,
  } satisfies OAuthProvider<AsgardeoProfile>;
};
