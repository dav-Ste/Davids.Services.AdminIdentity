# Davids Admin Identity API (`Davids.Services.AdminIdentity`)

[![Pull Request CI — Security Gate](https://github.com/dav-Ste/Davids.Services.AdminIdentity/actions/workflows/pull-request-ci.yml/badge.svg?branch=main)](https://github.com/dav-Ste/Davids.Services.AdminIdentity/actions/workflows/pull-request-ci.yml)
[![Pull Request CI — CodeQL SAST](https://github.com/dav-Ste/Davids.Services.AdminIdentity/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/dav-Ste/Davids.Services.AdminIdentity/actions/workflows/codeql.yml)

Dedicated `.NET 10` **Self-Hosted Administrator OpenID Connect (OIDC) Provider** (`OpenIddict` `7.7.2`) and administrator account-provisioning service.

## Security & Data Isolation

- **Physical database isolation (`adminidentitydb`)**: Administrator credentials, OpenIddict applications/authorizations/tokens, and revoked access tokens are stored exclusively in `adminidentitydb`. Customer logins remain isolated in `Davids.Services.Identity` (`identitydb`), and customer domain profiles remain in `Davids.Services.Customers` (`customersdb`).
- **Asymmetric RS256 OIDC authority**: Publishes `/.well-known/openid-configuration` and `/.well-known/jwks`, issuing short-lived (`15 min`) RS256 JWTs (`aud: davids-admin`, `role: admin`) signed with a dedicated 2048-bit+ RSA private key (`secret/data/davids/admin-identity` in Vault) completely separate from `Davids.Services.Identity`. Resource servers (`Davids.APIGateway` and `Davids.Services.Customers`) verify signatures using public JWKS discovery without holding signing keys.
- **Confidential PKCE BFF Client (`davids-admin-bff`)**: Enforces OAuth 2.1 **Authorization Code + PKCE (`S256`)** with a confidential client secret (`Oidc:BffClientSecret`) for the Gateway Backend-for-Frontend (`Davids.APIGateway`). Resource Owner Password Credentials (`grant_type=password`) and legacy JSON `/sign-in` endpoints are disabled.
- **No public registration**: `/sign-up` does not exist. Initial bootstrap in local development is controlled by `SeedAdmin:Enabled` (strictly `Development`-only, backed by user-secrets); additional administrators can only be provisioned by an authenticated administrator via `POST /users`.
- **Single-use rotating refresh tokens with zero-leeway replay detection**: Refresh tokens (`8 hour` lifetime) rotate on every renewal (`SetRefreshTokenReuseLeeway(TimeSpan.Zero)`) and revoke the entire authorization token chain if a rotated token is replayed.
- **Tighter rate limiting & RFC 7009 Redis revocation**: Authentication commands default to `5` requests/minute per IP (`RateLimiting:AuthPermitLimit`), and `POST /connect/revocation` synchronizes revoked access-token `jti`s to `RevokedAdminAccessTokens` and Redis (`davids:admin-identity:revoked:<jti>`) for immediate edge rejection at `Davids.APIGateway`.

## Build & Test

Clone the sibling `Davids.Shared` repository (`../Davids.Shared`) alongside `Davids.Services.AdminIdentity` (the `Davids` Aspire infrastructure repository is not required for standalone builds/tests):

```powershell
dotnet restore .\Davids.Services.AdminIdentity.slnx --locked-mode
dotnet build .\Davids.Services.AdminIdentity.slnx -c Release --no-restore
dotnet test .\Davids.Services.AdminIdentity.slnx -c Release --no-build
```
