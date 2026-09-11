---
id: oauth2-password
title: OAuth2 password grant — token issuance, rotating refresh tokens and revocation
status: draft
created_at: 2026-09-11
updated_at: 2026-09-11
owner: TBD
affected_areas: [backend, http-api]
tags: [oauth2, password-grant, access-token, refresh-token, jwt, redis, revocation, security, backend, http-api]
---

# OAuth2 password grant — token issuance, rotating refresh tokens and revocation

## Description

The `oauth2-password` feature is provided by the `Oauth2PasswordPlugin` (plugin name `"AuthOauth2Password"`, package `user_oauth2_password`, directory `oauth2_password/`) of the `github.com/go-bolo/user` module. It implements an OAuth2-style **password grant** for JSON/API clients (SPAs, mobile apps, integration tests) on top of Redis:

- **Token issuance** — `POST /auth/grant-password/authenticate` exchanges `email` + `password` for an `access_token` / `refresh_token` pair plus the user record. Credentials are validated against the password model owned by the [authentication](../authentication/guide.md) feature (same bcrypt check as the cookie-session login).
- **Opaque access tokens (default)** — random opaque strings whose state lives in Redis; every request is authenticated by a global Bearer-token middleware that loads the token record and fills `RequestContext` with the authenticated user and roles.
- **Stateless JWT access tokens (optional)** — when the `oauth2_jwt` subplugin is installed, it registers a JWT access-token generator and the same issuance/refresh machinery emits JWT access tokens instead, keeping the refresh token opaque and stateful in Redis.
- **Rotating single-use refresh tokens** — refresh tokens are consumed on use (`GETDEL` atomic claim), organized in families with an idle TTL, an absolute lifetime cap and a short "reuse grace" window that makes concurrent replays idempotent; presenting a consumed token *after* the grace window revokes the whole family (theft containment).
- **Revocation (RFC 7009 style)** — `POST /auth/grant-password/revoke` revokes a refresh token (and its whole family) or a single access token, always answering `200` without revealing whether the token existed.

This plugin owns no database tables and no migrations — all token state lives in Redis. The HTTP refresh endpoint is **not registered by this plugin**: per the code comment in `BindRoutes`, consumers register their own route (e.g. `POST /grant-password/refresh-token`) calling the exported `RotateRefreshToken`/`RotateRefreshTokenWithFormat` library to avoid Echo route disputes. In this repository the `oauth2_jwt` subplugin registers `POST /auth/jwt/refresh-token` on top of the same library.

## How to use

- Register the plugin in the Bolo app (as done in `oauth2_password/setup_test.go`):

  ```go
  app.RegisterPlugin(user_oauth2_password.NewPlugin(&user_oauth2_password.PluginCfgs{}))
  ```

- Point the token Redis at `SITE_OAUTH2_ADDR_WRITER` / `SITE_OAUTH2_ADDR_READER` (optionally `SITE_OAUTH2_PASSWORD`, `SITE_OAUTH2_DB`). Clients are created on the `configuration` event; initialization is idempotent.
- **Authenticate** (password grant):

  ```
  POST /auth/grant-password/authenticate
  {"email": "user@example.com", "password": "secret"}

  200 {"access_token": "...", "refresh_token": "...", "expires_in": 1800, "user": {...}}
  ```

- **Call protected APIs** sending `Authorization: Bearer <access_token>`. The global middleware authenticates the request; unknown/expired tokens continue as anonymous requests unless `OAUTH2_STRICT_401=true` (then they get an explicit `401` with `WWW-Authenticate`).
- **Refresh** the session before the access token expires by posting the refresh token to a consumer-registered route backed by `RotateRefreshToken` / `RotateRefreshTokenWithFormat`. In this module the `oauth2_jwt` subplugin exposes `POST /auth/jwt/refresh-token` with body `{"refresh_token": "..."}`.
- **Revoke** (logout of one session, RFC 7009):

  ```
  POST /auth/grant-password/revoke
  {"token": "<refresh-or-access-token>", "token_type_hint": "refresh_token"}

  200 {}
  ```

  `token_type_hint` is optional (`refresh_token` is the default); `access_token` revokes only that access token. Unknown tokens still answer `200`.
- **Logout glue**: the authentication feature's `POST /auth/logout` accepts `X-Refresh-Token` (or body `refresh_token`) and `Authorization: Bearer <token>` to revoke tokens through this package (`RevokeByRefreshToken` / `DeleteAccessToken`). See [authentication](../authentication/guide.md).
- **Facebook login** reuses the same token machinery: `FacebookAuthController` issues the opaque pair via `Oauth2GenerateAndSaveToken` after a successful Facebook login.
- **JWT mode**: also register the `oauth2_jwt` subplugin *before* this plugin (middleware order follows `RegisterPlugin` order). It registers the JWT generator on the `configuration` event and its middleware validates Bearer JWTs before this plugin's opaque middleware runs.

## Goals

- Provide token-based authentication for JSON clients, complementing the cookie-session flow documented in [sessions](../sessions/guide.md).
- Reuse the existing password model (bcrypt) instead of duplicating credential logic (see [authentication](../authentication/guide.md)).
- Make refresh tokens single-use with atomic rotation, idempotent replay inside a short grace window, and family-wide revocation when reuse is detected outside it.
- Bound session lifetime twice: an idle TTL renewed on every rotation and an absolute cap for the whole token family.
- Support RFC 7009-style revocation that never reveals token existence and never fails the response.
- Keep the access-token format pluggable (opaque by default, stateless JWT via the `oauth2_jwt` subplugin) while the refresh-token semantics stay identical.
- Stay compatible with legacy unprefixed Redis keys: old tokens keep working, migrate to the new family format on first rotation, and remain revocable.

## Affected areas

- **backend**: `oauth2_password/` — plugin wiring (`Oauth2PasswordPlugin.go`), handlers (`handlers.go`, `revoke_handler.go`), authentication middleware (`middlewares.go`, `auth_oauth2_password.go`), refresh machinery (`refresh.go`), access-token formats (`token_format.go`), Redis storage (`storage.go`), TTL/flag configuration (`config.go`), HTTP error types (`http_response.go`). The `oauth2_jwt/` subplugin is a consumer of this package's exported API (generator registration, rotation, TTL parser) and is documented in its own feature.
- **http-api**: `POST /auth/grant-password/authenticate`, `POST /auth/grant-password/revoke` (registered by this plugin); refresh routes registered by consumers (in this repo: `POST /auth/jwt/refresh-token`); a global Bearer-token middleware applied to the whole router (public prefixes: `/health`, `/public`).
- **data**: Redis keys only — access-token keys (unprefixed), legacy refresh keys (unprefixed), and the `RT:`, `RTUSED:`, `RTTOMB:`, `RTFAM:` families of the rotating format. No SQL tables or migrations (`GetMigrations` returns empty); credentials live in the `passwords` table owned by [authentication](../authentication/guide.md).

## Tags

[oauth2, password-grant, access-token, refresh-token, jwt, redis, revocation, security, backend, http-api]

## Links

- Feature spec: [spec.md](./spec.md)
- Changelog: [changelog.md](./changelog.md)
- Authentication (password model, `/auth/logout` token revocation glue): [../authentication/guide.md](../authentication/guide.md)
- Sessions (cookie-based alternative for browser flows): [../sessions/guide.md](../sessions/guide.md)
- OAuth2 JWT subplugin (JWT access-token generator and consumer of this library): [../oauth2-jwt/guide.md](../oauth2-jwt/guide.md)
