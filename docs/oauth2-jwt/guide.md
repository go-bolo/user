---
id: oauth2-jwt
title: OAuth2 JWT — stateless HS256 access tokens with rotating opaque refresh tokens
status: draft
created_at: 2026-09-11
updated_at: 2026-09-11
owner: TBD
affected_areas: [backend, http-api]
tags: [oauth2, jwt, authentication, access-token, refresh-token, hs256, redis, backend, http-api]
---

# OAuth2 JWT — stateless HS256 access tokens with rotating opaque refresh tokens

## Description

The `oauth2-jwt` feature is implemented by the `user_oauth2_jwt` package (directory `oauth2_jwt/`) of the `github.com/go-bolo/user` module. It is a **subplugin** (`Oauth2JWTPlugin`, plugin name `"AuthOauth2JWT"`, created with `NewPlugin`) that adds a JSON Web Token flavor to the OAuth2 password grant:

- **Stateless access token**: an HS256-signed JWT carrying `iss/aud/sub/jti/iat/nbf/exp` claims plus the user's `roles` and an `active`/`blocked` snapshot. It contains no PII, is **not** stored in Redis, and is validated cryptographically on every request — no database or Redis lookup is needed to authenticate a Bearer JWT.
- **Opaque rotating refresh token**: the refresh side keeps the hardened single-use rotation of the `oauth2_password` package (rotation with a reuse grace window, absolute lifetime cap per token family, and chained revocation when reuse is detected outside the grace). That logic is owned by the sibling feature — see [../authentication/guide.md](../authentication/guide.md) and the `oauth2_password` package docs; this document only covers the contract used here.
- **Two JSON endpoints** under `/auth/jwt`: `POST /auth/jwt/authenticate` (email + password in, token pair out) and `POST /auth/jwt/refresh-token` (refresh token in, new token pair out). Request/response contracts are identical to the legacy `/auth/grant-password/*` endpoints, so frontends can switch endpoints without any other change.
- **A global Echo middleware** that recognizes Bearer tokens in JWT compact format (`aaa.bbb.ccc`), validates them, and mounts an authenticated user stub from the claims. Opaque tokens and requests without an `Authorization` header pass through untouched to the legacy opaque middleware of `oauth2_password` — both formats work side by side in the same app.

Unlike browser flows based on cookie sessions (see [../sessions/guide.md](../sessions/guide.md)), the `/auth/jwt` flow authenticates clients exclusively through the `Authorization: Bearer` header.

## How to use

- **Install the subplugin in the Bolo app**, registered **before** the `oauth2_password` plugin (the `RegisterPlugin` order defines the middleware execution order):

  ```go
  app.RegisterPlugin(user_oauth2_jwt.NewPlugin(&user_oauth2_jwt.PluginCfgs{
      OnLoginActivity: func(userID uint64) error { /* e.g. record login activity */ return nil },
  }))
  app.RegisterPlugin(user_oauth2_password.NewPlugin(&user_oauth2_password.PluginCfgs{}))
  ```

  Uninstalling the subplugin is the kill-switch: the `/auth/jwt/*` routes disappear (404) and previously issued JWTs stop validating (they fall through to the opaque middleware, which rejects unknown tokens).

- **Configure the required environment variables** before startup (see the Configuration section):

  - `OAUTH2_JWT_SECRET` is **mandatory** — the process fails fast (`log.Fatal` on the `configuration` event) if it is empty; use a random secret of at least 32 bytes.
  - Optional: `OAUTH2_JWT_ISSUER`, `OAUTH2_JWT_AUDIENCE` (default `"mm"`), `OAUTH2_JWT_TTL` (default `10m`), `OAUTH2_JWT_LEEWAY` (default `30s`).
  - The refresh-token storage is shared with `oauth2_password` (`SITE_OAUTH2_ADDR_WRITER`, `SITE_OAUTH2_ADDR_READER`, `SITE_OAUTH2_DB`, `SITE_OAUTH2_PASSWORD`).

- **Login**: `POST /auth/jwt/authenticate` with JSON body `{"grant_type":"password","email":"...","password":"..."}`. On success the answer is `200` with `{"access_token","refresh_token","expires_in","user"}`. Send `Authorization: Bearer <access_token>` on subsequent calls; the JWT is accepted until `exp` (plus the configured leeway).

- **Refresh**: `POST /auth/jwt/refresh-token` with `{"refresh_token":"..."}`. The old refresh token is rotated (single-use); a replay of the old token inside the grace window returns the **same** pair, and a replay outside it revokes the whole family. Reusing a legacy opaque refresh token here migrates the session to the JWT format on the first rotation.

- **Logout / revocation**: unchanged — use the existing `POST /auth/grant-password/revoke` (RFC 7009) and `/auth/logout` endpoints owned by the sibling features. Revoking with `token_type_hint: "access_token"` is a no-op for JWTs (they are stateless and have no denylist): the JWT stays valid until it expires. Passing the refresh token kills the token family immediately.

- **Hook (Go code)**: `PluginCfgs.OnLoginActivity` is called after every successful authenticate and refresh (including grace replays). Hook failures are only logged — they never fail the login/refresh.

## Goals

- Issue short-lived, self-contained access tokens so that authenticated requests need no Redis read and no database query, cutting per-request cost compared with the opaque flow (see `BenchmarkJWTMiddleware` vs `BenchmarkOpaqueMiddleware` in `oauth2_jwt/benchmark_test.go`).
- Keep the JWT payload free of PII; roles and the `active`/`blocked` snapshot exist so the middleware can build the request user without storage access, accepting a staleness bounded by the token TTL.
- Preserve exactly the same HTTP contract (status codes and messages) as the legacy grant-password endpoints, including inactive/blocked account semantics.
- Reuse — not reimplement — the refresh-token security machinery of `oauth2_password`; the subplugin owns only the JWT format.
- Resist common JWT attacks: algorithm pinning (HS256 only), `kid` allow-listing, strict `iss`/`aud` matching, fail-closed claim validation with a configurable clock leeway, and no default secret.
- Allow incremental adoption: JWT and opaque tokens authenticate side by side, and legacy refresh sessions migrate to the JWT format on the next rotation.

## Affected areas

- **backend**: `oauth2_jwt/Oauth2JWTPlugin.go` (plugin wiring, route/middleware registration, `PluginCfgs`), `oauth2_jwt/config.go` (env parsing, fail-fast init, access-token generator registration), `oauth2_jwt/jwt.go` (claim model, issuance, validation, format sniffing), `oauth2_jwt/middleware.go` (Bearer JWT middleware and user stub), `oauth2_jwt/handlers.go` (authenticate/refresh handlers). Integration points in `oauth2_password` (`SetJWTAccessGenerator`, `Oauth2GenerateAndSaveTokenJWT`, `RotateRefreshTokenWithFormat`) belong to the sibling feature.
- **http-api**: `POST /auth/jwt/authenticate` and `POST /auth/jwt/refresh-token`; global middleware behavior for `Authorization: Bearer` on every non-public route.
- **data**: no migrations (`GetMigrations` returns empty). No new tables; the only persisted state is the refresh-token Redis keys owned by `oauth2_password`.

## Tags

[oauth2, jwt, authentication, access-token, refresh-token, hs256, redis, backend, http-api]

## Links

- Feature spec: [spec.md](./spec.md)
- Changelog: [changelog.md](./changelog.md)
- Authentication feature (login/logout, `/auth/grant-password/*`, opaque token flow shared with this one): [../authentication/guide.md](../authentication/guide.md)
- Sessions feature (Redis-backed browser sessions — the cookie flow this Bearer flow does not use): [../sessions/guide.md](../sessions/guide.md)
- OAuth2 password grant feature (owns the refresh/revocation machinery and the shared Redis storage): [../oauth2-password/guide.md](../oauth2-password/guide.md)
- JWT dependency: `github.com/golang-jwt/jwt/v5` (see [../../go.mod](../../go.mod))
