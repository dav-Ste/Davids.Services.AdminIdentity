# Davids.Services.AdminIdentity

| Pull Request CI | CodeQL SAST | Platform Architecture & Orchestration |
|---|---|---|
| [![Pull Request CI — Security Gate](https://github.com/dav-Ste/Davids.Services.AdminIdentity/actions/workflows/pull-request-ci.yml/badge.svg?branch=main)](https://github.com/dav-Ste/Davids.Services.AdminIdentity/actions/workflows/pull-request-ci.yml) | [![Pull Request CI — CodeQL SAST](https://github.com/dav-Ste/Davids.Services.AdminIdentity/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/dav-Ste/Davids.Services.AdminIdentity/actions/workflows/codeql.yml) | [**`Davids` — Architecture & Security Diagram**](https://github.com/dav-Ste/Davids#architecture-project-relationships--security-posture) |

`Davids.Services.AdminIdentity` is the standalone `.NET 10` **Self-Hosted Administrator OpenID Connect (OIDC) Provider** (`OpenIddict` `7.7.2`, default local port `:17325`) and administrator account-provisioning microservice (`Davids.Services.AdminIdentity.slnx`).

## Projects

- `src/Davids.Services.AdminIdentity.Core`: Administrator domain entities (`role: "admin"` only), `AdminLoginAuditLog` records, revoked admin access-token tracking, and password/email invariants.
- `src/Davids.Services.AdminIdentity.Application`: Administrator provisioning commands, DTOs, and login-audit query handlers.
- `src/Davids.Services.AdminIdentity.Infrastructure`: SQL Server (`adminidentitydb`) EF Core + OpenIddict stores, dedicated 2048-bit+ RSA signing/encryption keys, confidential PKCE BFF client seeder (`davids-admin-bff`), Vault KV-v2 loader (`secret/data/davids/admin-identity`), `SeedAdmin` development bootstrapper, and Redis revocation sync (`davids:admin-identity:revoked:<jti>`).
- `src/Davids.Services.AdminIdentity.Api`: Minimal HTTP API exposing OpenIddict protocol endpoints and `AdminOnly`-protected administrator management & audit routes (`/me`, `GET/POST /users`, `GET /login-audits`).
- `tests/Davids.Services.AdminIdentity.Tests`: Clean Architecture boundary tests plus SQLite-backed OIDC PKCE `S256`, `client_secret` enforcement, refresh-token replay cascade revocation, lockout, login-audit, and RFC 7009 revocation integration tests.

## Security & data isolation

- **Physical database isolation (`adminidentitydb`)**: Administrator credentials, OpenIddict applications/authorizations/tokens, `AdminLoginAuditLogs`, and `RevokedAdminAccessTokens` live exclusively in `adminidentitydb`. Customer logins remain isolated in [`Davids.Services.Identity`](https://github.com/dav-Ste/Davids.Services.Identity) (`identitydb`), and customer domain profiles remain in [`Davids.Services.Customers`](https://github.com/dav-Ste/Davids.Services.Customers) (`customersdb`).
- **Asymmetric `RS256` OIDC authority**: Publishes `/.well-known/openid-configuration` and `/.well-known/jwks`, issuing short-lived (`15 min`) `RS256` JWTs (`aud: davids-admin`, `role: admin`) signed with a dedicated 2048-bit+ RSA private key (`secret/data/davids/admin-identity` in Vault) completely separate from `Davids.Services.Identity`. Resource servers (`Davids.APIGateway` and `Davids.Services.Customers`) verify signatures via public JWKS discovery without holding signing keys.
- **Confidential PKCE BFF client (`davids-admin-bff`)**: Enforces OAuth 2.1 **Authorization Code + PKCE (`S256`)** with a confidential client secret (`Oidc:BffClientSecret`) for the Gateway Backend-for-Frontend (`Davids.APIGateway`). Resource Owner Password Credentials (`grant_type=password`) and legacy JSON `/sign-in` endpoints are disabled.
- **No public registration**: `/sign-up` does not exist (`404` / blocked at ingress). Initial bootstrap in local development is controlled by `SeedAdmin:Enabled` (`Development`-only, backed by `.NET user-secrets`); additional administrators can only be provisioned by an authenticated administrator via `POST /users`.
- **Single-use rotating refresh tokens with zero-leeway replay detection**: Refresh tokens (`8 hour` lifetime) rotate on every renewal (`SetRefreshTokenReuseLeeway(TimeSpan.Zero)`) and revoke the entire authorization token chain if a rotated token is replayed.
- **Tighter rate limiting, account lockout & RFC 7009 Redis revocation**: Authentication commands enforce per-IP rate limiting (`RateLimiting:AuthPermitLimit`) and per-account lockout (`Lockout:MaxFailedAccessAttempts` / `Lockout:DurationMinutes`), while `POST /connect/revocation` synchronizes revoked access-token `jti`s to `RevokedAdminAccessTokens` and Redis (`davids:admin-identity:revoked:<jti>`) for immediate edge rejection at `Davids.APIGateway`.

## OIDC & HTTP contract

Requests are routed through [`Davids.APIGateway`](https://github.com/dav-Ste/Davids.APIGateway) (`:17320`) by prefixing routes with `/admin-identity`:

| Method | Path | Access | Behaviour |
|---|---|---|---|
| `GET` | `/.well-known/openid-configuration` | Anonymous | Admin OIDC discovery metadata (`S256` PKCE, `RS256` signing, endpoints) |
| `GET` | `/.well-known/jwks` | Anonymous | Public Admin RSA JSON Web Key Set (`kty: RSA`, `use: sig`) |
| `GET` / `POST` | `/connect/authorize` | Anonymous | Interactive administrator sign-in for confidential client `davids-admin-bff` (`code_challenge_method=S256` + antiforgery `request_token`) |
| `POST` | `/connect/token` | Confidential client | Exchanges `authorization_code` + `code_verifier` + `client_secret` or rotates single-use `refresh_token` (`15 min` access token, `8 hour` refresh token) |
| `GET` / `POST` | `/connect/userinfo` | `AdminBearer` (`admin`) | Standard OIDC UserInfo endpoint for verified administrators |
| `POST` | `/connect/revocation` | Confidential client | RFC 7009 revocation; revokes grants and syncs access-token `jti` to SQL + Redis `davids:admin-identity:revoked:<jti>` |
| `GET` / `POST` | `/connect/logout` | Anonymous | OIDC End-Session logout endpoint |
| `GET` | `/me` | `AdminBearer` (`admin`) | Returns authenticated administrator identity claims |
| `GET` | `/users` | `AdminBearer` (`admin`) | Lists administrator accounts in `adminidentitydb` |
| `POST` | `/users` | `AdminBearer` (`admin`) | Provisions a new `admin` account in `adminidentitydb` |
| `GET` | `/login-audits` | `AdminBearer` (`admin`) | Returns append-only zero-secret administrator login audit logs (`AdminLoginAuditLogs`) |
| `GET` | `/health`, `/alive` | Probe | Readiness and liveness endpoints wired via `Davids.ServiceDefaults` |

## Build, test & container image

Clone [`Davids.Shared`](https://github.com/dav-Ste/Davids.Shared) (`../Davids.Shared`) alongside `Davids.Services.AdminIdentity` (or pass `/p:UseSharedPackageReference=true` to consume `Davids.ServiceDefaults` as a NuGet package without cloning `Davids.Shared`):

```powershell
dotnet restore Davids.Services.AdminIdentity.slnx --locked-mode
dotnet build Davids.Services.AdminIdentity.slnx --no-restore -c Release -warnaserror
dotnet test Davids.Services.AdminIdentity.slnx --no-build --no-restore -c Release
```

Build the hardened multi-stage container image (`USER 10001:10001`, `EXPOSE 8080`) from the parent workspace directory:

```powershell
docker build -f Davids.Services.AdminIdentity/Dockerfile -t davids-admin-identity:local ..
```

## Related repositories

- [`Davids`](https://github.com/dav-Ste/Davids) — `.NET 10` Aspire AppHost, Vault bootstrap, Kubernetes/Istio manifests, architecture diagram & lifecycle security suite
- [`Davids.Shared`](https://github.com/dav-Ste/Davids.Shared) — `Davids.ServiceDefaults` shared observability, Data Protection, and resilience defaults
- [`Davids.APIGateway`](https://github.com/dav-Ste/Davids.APIGateway) — YARP `2.3.0` edge reverse proxy & confidential Admin OIDC BFF
- [`Davids.Services.Identity`](https://github.com/dav-Ste/Davids.Services.Identity) — Customer OpenIddict `RS256` OIDC Provider (`identitydb`)
- [`Davids.Services.Customers`](https://github.com/dav-Ste/Davids.Services.Customers) — Customer profiles & order tracking API (`customersdb`)
- [`Davids.Frontend.Admin`](https://github.com/dav-Ste/Davids.Frontend.Admin) — Passwordless Admin customer search & editing web UI
