---
id: oauth2-password-spec
title: OAuth2 password grant — technical specification
status: draft
created_at: 2026-09-11
updated_at: 2026-09-11
owner: TBD
affected_areas: [backend, http-api]
tags: [oauth2, password-grant, access-token, refresh-token, jwt, redis, revocation, security, backend, http-api]
---

# OAuth2 password grant — technical specification

## Overview & architecture

The feature lives in the `Oauth2PasswordPlugin` (`NewPlugin`, `GetName() == "AuthOauth2Password"`, package `user_oauth2_password`). `Init` wires the plugin to Bolo lifecycle events:

| Event | Handler | Effect |
| --- | --- | --- |
| `configuration` | `InitStorage` | Creates the Redis clients `StorageDBWriter` and `StorageDBReader` from `SITE_OAUTH2_ADDR_WRITER`, `SITE_OAUTH2_ADDR_READER`, `SITE_OAUTH2_DB` (default `1`) and `SITE_OAUTH2_PASSWORD` (default `""`). Idempotent via the `storageInitialized` flag (and per-client `nil` checks). |
| `bindMiddlewares` | `bindMiddlewares` | Installs `oauth2AuthenticationMiddleware()` globally on the router (`router.Use`). |
| `bindRoutes` | `BindRoutes` | Creates the router group `"auth"` at `/auth` and registers the authenticate and revoke endpoints (see API contract). No refresh route is registered here — the code comment states consumers register `/grant-password/refresh-token` themselves to avoid Echo route disputes. |
| — | `GetMigrations` | Returns an empty list: the feature owns no database migrations; all token state is in Redis. |

Components:

- **Handlers** — `AuthenticationOauth2PasswordHandler` (password grant) and `RevokeOauth2TokenHandler` (RFC 7009 revocation).
- **Authentication middleware** (`middlewares.go` + `auth_oauth2_password.go`) — resolves the authenticated user from the `Authorization: Bearer <token>` header for every non-public route (`/health*`, `/public*` are skipped by `IsPublicRoute`).
- **Token generation** (`auth_oauth2_password.go`, `token_format.go`) — `Oauth2GenerateToken`/`Oauth2GenerateAndSaveToken` for the opaque (legacy) format; `Oauth2GenerateAndSaveTokenJWT` for the JWT format; `generateAccessTokenForFormat` selects between them.
- **Refresh machinery** (`refresh.go`) — atomic rotation (`GETDEL` claim), token families, reuse-grace idempotency, tombstones, idle/absolute TTLs and family revocation. Error taxonomy via `RefreshError`/`RefreshErrKind`.
- **Storage** (`storage.go`) — thin Redis accessors (`GetAccessToken`, `SetAccessToken`, `DeleteAccessToken`, deprecated `GetRefreshToken`, `SetRefreshToken`). Key prefixes `accessTokenPrefix`/`refreshTokenPrefix` are currently empty strings (the old `"AT:"`/`"RT:"` literals are commented out).
- **Configuration** (`config.go`) — TTL parsing with day support (`ParseTTL`), TTL cascades (new unit-based env → legacy minutes env → default) and the `OAUTH2_STRICT_401` flag.
- **HTTP error types** (`http_response.go`) — `ForbiddenHTTPError` (401/403 JSON errors with `error`/`error_context` fields) and `UnauthorizedHTTPError` + `NewUnauthorizedTokenHTTPError` (strict-mode 401 with `WWW-Authenticate`).
- **Pluggable JWT generator** (`token_format.go`) — `JWTAccessGenerator` callback registered by the `oauth2_jwt` subplugin via `SetJWTAccessGenerator` on the `configuration` event; this package stays agnostic to signing/claims details.

Note on dependencies: the module's `golang.org/x/oauth2 v0.19.0` dependency is used only by the Facebook flow (`FacebookAuthController.go`). This feature implements the password grant natively over Echo + Redis and does not import it.

## API contract

Routes below are exactly those registered by `Oauth2PasswordPlugin.BindRoutes` (group `/auth`), plus the consumer-registered refresh paths for completeness. There is no route-level permission middleware; the global Bearer middleware authenticates but never blocks anonymous requests (except in strict-401 mode — see Flows).

| Method | Path | Auth / permission |
| --- | --- | --- |
| POST | `/auth/grant-password/authenticate` | Public (registered by this plugin). Body: `email` (required), `password` (required), `grant_type` (accepted, ignored). Malformed JSON body → `404` empty; validation error → error pipeline; unknown user/no password record → `400` messages `Usuário não encontrado ou não possuí senha cadastrada.`; wrong credentials → `400` `Email ou senha incorretos.`; inactive user → `403` warning `Conta não ativada. Por favor, verifique seu email para ativar sua conta.`; blocked user → `403` `Conta bloqueada. Entre em contato com o suporte.`; success → `200` `{access_token, refresh_token, expires_in, user}`. |
| POST | `/auth/grant-password/revoke` | Public (registered by this plugin). RFC 7009. Body: `token` (required), `token_type_hint` (optional; `access_token` revokes the access token, any other value or absence revokes the refresh token family). Malformed JSON body → `404` empty; missing `token` → validation error; always `200` `{}` otherwise, even for unknown tokens (revocation failures are only logged). |
| POST | `/grant-password/refresh-token` | **Not registered by this plugin.** Reserved for consumers (code comment names the `mm` consumer). Consumers call `RotateRefreshToken`/`RotateRefreshTokenWithFormat` with body `{"refresh_token": "..."}` and map `RefreshError.Kind` to their HTTP contract. |
| POST | `/auth/jwt/authenticate` | Registered by the `oauth2_jwt` subplugin (not this plugin): JWT-format variant of the password grant, reusing `ValidUsernamePassword` and `Oauth2GenerateAndSaveTokenJWT` from this package. |
| POST | `/auth/jwt/refresh-token` | Registered by the `oauth2_jwt` subplugin: refresh route backed by `RotateRefreshTokenWithFormat(..., FormatJWT)`. |

Global middleware applied to all routes: `oauth2AuthenticationMiddleware` skips paths prefixed `/health` or `/public`; other requests go through `HandleRequestAuthentication` → `oauth2TokenAuthentication`, which (a) short-circuits when the `oauth2_jwt` middleware already authenticated the request (`c.Get("auth.jwt")` guard), (b) parses `Authorization: Bearer <token>` (only the `Bearer` scheme; exactly one space), (c) loads the opaque token record from Redis and, when valid, loads the owner and fills the request context via `SetAuthenticatedUserAndFillRoles`. Unknown/expired tokens continue anonymous unless `OAUTH2_STRICT_401=true`, in which case they get `401` with `WWW-Authenticate: Bearer error="invalid_token", error_description="token expired"` and a `BaseErrorResponse`-shaped body. Non-Redis storage errors → `401` `invalid_grant`; unparsable token data → `403` `invalid token data`; blocked owner → `403` `user is blocked`.

## Data models

### `Oauth2TokenData` — access-token record (legacy/opaque format)

Stored as JSON under the unprefixed access-token key at issuance; the same JSON is also stored under the unprefixed refresh-token key by `Oauth2GenerateAndSaveToken`.

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | Same value as `access_token`. |
| `ownerId` | JSON number | User ID (`u.GetID()`). |
| `access_token` | string | `uuid v4` + 35 random chars (`helpers.RandStringBytes`). |
| `refresh_token` | string | Same construction as the access token. |
| `token_type` | string | Always `""` in this implementation. |
| `scopes` | `[]string` | Always `[]` in this implementation. |
| `expireDate` | time | `now + AccessTokenTTL`; validity is `now.Before(ExpireDate)` (`IsValid`). |
| `expiresIn` | int64 | `AccessTokenTTL` in seconds. |

### `RefreshTokenRecord` — rotating refresh-token record (new format)

Stored as JSON under `RT:<refresh token>` with the idle TTL.

| Field | Type | Notes |
| --- | --- | --- |
| `ownerId` | JSON number | Token owner. |
| `familyId` | string (uuid) | Identifies the token family (created at JWT login or at the first rotation of a legacy token). |
| `createdAt` | time | Diagnostic/forensic only; no flow decides on it. |
| `absoluteDeadline` | time | Family-wide cap; rotation past it revokes the family (`ErrExpiredAbsolute`). |

### `TokenPair` — rotation result

`{access_token, refresh_token, expires_in}` — same JSON shape as the token fields of the grant response.

### Redis key map

| Key | Constant / prefix | Value | TTL |
| --- | --- | --- | --- |
| `<access token>` | `accessTokenPrefix` (`""`) | `Oauth2TokenData` JSON | `OAUTH2_ACCESS_TOKEN_TTL` |
| `<refresh token>` (legacy) | `refreshTokenPrefix` (`""`) | `Oauth2TokenData` JSON | idle TTL (also used by legacy login) |
| `RT:<refresh token>` | `RefreshTokenKeyPrefix` | `RefreshTokenRecord` JSON | idle TTL (renewed each rotation) |
| `RTUSED:<old refresh token>` | `RefreshTokenUsedKeyPrefix` | issued `TokenPair` + `ownerId` (idempotent replay) | reuse-grace window (default 30s) |
| `RTTOMB:<used refresh token>` | `RefreshTokenTombKeyPrefix` | family ID (reuse detection) | remaining absolute lifetime |
| `RTFAM:<familyId>` | `RefreshTokenFamilyKeyPrefix` | SET of the family's refresh tokens | remaining absolute lifetime |

`RevokeRefreshFamily` deletes, for every family member, the `RT:`, `RTUSED:`, `RTTOMB:` and unprefixed legacy keys plus the `RTFAM:` index in a single multi-key `DEL`.

### Request/response bodies

- `oauth2PasswordRequestBody`: `{email* , password*, grant_type}` (JSON).
- Grant success response: `{access_token, refresh_token, expires_in, user}` where `user` is the serialized `user_models.UserModel`.
- Grant/revoke error responses use `bolo.BaseErrorResponse` (`messages[]` with `status`/`message`); internal errors use `ForbiddenHTTPError` (`code`, `message`, `error`, `error_context`).
- `RevokeTokenRequestBody`: `{token*, token_type_hint}` (JSON, RFC 7009 fields).

### Error taxonomy (`refresh.go`)

| `RefreshErrKind` | String label | Meaning | Storage effect |
| --- | --- | --- | --- |
| `ErrInternal` | `internal` | Infra failure (Redis down, corrupted data, invalid config). Caller should answer 500. | Nothing revoked; claimed key restored best-effort. |
| `ErrExpiredIdle` | `expired_idle` | Token unknown/expired by inactivity (and no recent claim). | Nothing revoked. |
| `ErrExpiredAbsolute` | `expired_absolute` | Family passed `absoluteDeadline`. | Family revoked. |
| `ErrReuseDetected` | `reuse_detected` | Consumed token presented after the grace window (possible theft). | Family revoked. |
| `ErrUserInvalid` | `user_invalid` | Owner missing, inactive or blocked. | Nothing revoked; claimed key restored best-effort. |

## Flows (token issuance, refresh, revoke)

### Token issuance (password grant, opaque format)

1. `POST /auth/grant-password/authenticate` binds `{email, password, grant_type}`; bind failure → `404` empty, validation failure → error pipeline.
2. `ValidUsernamePassword` loads the password record via `FindPasswordByUsername` (matches `users.username` OR `users.email`, owned by [authentication](../authentication/guide.md)) and compares bcrypt hashes. `gorm.ErrRecordNotFound` → `400` with the "user not found / no password" message; other bcrypt/DB errors → error pipeline; mismatch → `400` "Email ou senha incorretos.".
3. `UserFindOneByUsername` loads the user; error → error pipeline. `!Active` → `403` (warning message, account not activated); `Blocked` → `403` (account blocked). Both states are checked even though the password was valid.
4. `Oauth2GenerateAndSaveToken` generates the opaque pair (`uuid v4` + 35 random chars each), builds `Oauth2TokenData` with `ExpireDate`/`ExpiresIn` from `AccessTokenTTL`, and writes: the access-token key with the access TTL and the refresh-token key (unprefixed, legacy format) with the idle TTL. Config errors fail loudly — no token is written with a wrong deadline.
5. Response `200` `{access_token, refresh_token, expires_in, user}`.

**JWT variant** (`Oauth2GenerateAndSaveTokenJWT`, used by the `oauth2_jwt` subplugin): the access token comes from the registered JWT generator (error if the subplugin is not installed) and is **not** stored in Redis; the refresh token is created already in the new format (`RT:` + `RTFAM:` index) so the first rotation simply continues the family. The returned `Oauth2TokenData` carries the JWT string as `AccessToken` and the generator's `expiresIn`.

**Access-token authentication on subsequent requests**: see the middleware summary in the API contract section. Two deliberate behaviors: in non-strict mode an expired-but-present token continues anonymous (403 is reserved for blocked users so frontends do not log out before trying the refresh), and only `Blocked` is rechecked against the DB (not `Active`).

### Refresh (rotating, single-use, family-aware)

Entry points: `RotateRefreshToken` (opaque format) and `RotateRefreshTokenWithFormat` (any format). The request context must be a `*bolo.RequestContext`.

1. **Replay inside the grace window** — `RTUSED:<token>` hit → return the *same* pair already issued (idempotent; the losing tab/device also gets 200). The owner is revalidated first: missing/inactive/blocked → `ErrUserInvalid`; DB failure → `ErrInternal`.
2. **Atomic claim of the new format** — `GETDEL RT:<token>`. Only one concurrent request wins. The winner validates the `RefreshTokenRecord`: past `absoluteDeadline` → revoke family, `ErrExpiredAbsolute`; owner missing/inactive/blocked → `ErrUserInvalid`; otherwise generate the new access token in the requested format (opaque stored in Redis with the access TTL; JWT stateless), generate a new refresh token (same family/owner/deadline), and write: `RT:<new>` with the idle TTL, add old+new to `RTFAM:<familyId>` (TTL = remaining absolute time), `RTUSED:<old>` = issued pair + owner (TTL = grace), `RTTOMB:<old>` = family ID (TTL = remaining absolute time).
3. **Legacy claim** — if step 2 missed, `GETDEL <token>` (unprefixed legacy key). The legacy `Oauth2TokenData` is upgraded in place to a new `RefreshTokenRecord` with a **fresh family** whose absolute deadline starts now; rotation proceeds as in step 2, so the legacy token migrates to the new format on first use.
4. **Miss** — the token is unknown/expired, or a concurrent winner claimed it milliseconds ago and has not published the pair yet. The caller polls `RTUSED:`/`RTTOMB:` every 25 ms for up to 1 s: a `RTUSED` appearance replays the winner's pair; a tombstone without grace means reuse outside the window → revoke family, `ErrReuseDetected`; after the deadline → `ErrExpiredIdle`.
5. **Crash safety** — when a claimed rotation fails with `ErrInternal` or `ErrUserInvalid`, the claimed key is restored best-effort so client retries of the same token reproduce the same outcome instead of a spurious "session expired". Failures that already revoked the family (absolute expiry) never restore anything.

Infra errors never revoke anything (fail-closed without destruction); the caller maps `RefreshError.Kind` to its HTTP contract. The `oauth2_jwt` refresh handler, for example, collapses `ErrExpiredIdle`/`ErrExpiredAbsolute`/`ErrReuseDetected` into a single "session expired" 400 and keeps the inactive/blocked 403 messages.

### Revoke (RFC 7009 style)

`POST /auth/grant-password/revoke` binds `{token, token_type_hint}`:

- `token_type_hint = "access_token"` → `DeleteAccessToken` removes the unprefixed access-token key.
- Any other hint (including absent — `refresh_token` is the RFC default) → `RevokeByRefreshToken`, which resolves the target in this order: active record (`RT:`) → revoke its whole family; tombstone (`RTTOMB:`) → revoke the family it points to; legacy unprefixed key → delete the key directly; leftover grace record → delete `RTUSED:`. Unknown tokens are not an error (best-effort), and an empty token is a no-op.
- Storage failures are only logged; the handler **always** answers `200` `{}` for a well-formed body, never revealing whether the token existed (per RFC 7009). Malformed JSON body → `404` empty; missing `token` → validation error.

The same library is used by logout glue: the authentication feature's `POST /auth/logout` accepts `X-Refresh-Token` (or body `refresh_token`) → `RevokeByRefreshToken`, and `Authorization: Bearer <token>` → `DeleteAccessToken`, both best-effort with the response staying 200.

## Configuration

All variables are read through the Bolo configuration (environment). TTL values accept `ParseTTL` syntax: `time.ParseDuration` units (`us`, `µs`/`μs`, `ms`, `s`, `m`, `h`) plus a `d` day suffix (`7d` → `168h`), combinable (`2d12h`, `1d1h30m`) and fractional (`1.5d` → `36h`); empty → default, invalid or non-positive → explicit error (config errors are never silenced).

| Variable | Default | Used by | Purpose |
| --- | --- | --- | --- |
| `SITE_OAUTH2_ADDR_WRITER` | — (none) | `InitStorage` | Redis address for token writes. |
| `SITE_OAUTH2_ADDR_READER` | — (none) | `InitStorage` | Redis address for token reads. |
| `SITE_OAUTH2_DB` | `1` | `InitStorage` | Redis DB index for tokens. |
| `SITE_OAUTH2_PASSWORD` | `""` | `InitStorage` | Redis password for both clients. |
| `OAUTH2_ACCESS_TOKEN_TTL` | `30m` | `AccessTokenTTL` | Access-token lifetime (string with unit). |
| `OAUTH2_ACCESS_TOKEN_EXPIRATION` | — | `AccessTokenTTL` | Legacy fallback, integer **minutes**; logs a deprecation warning; loses to the new variable. |
| `OAUTH2_REFRESH_IDLE_TTL` | `72h` | `RefreshIdleTTL` | Refresh-token idle lifetime, renewed on every rotation (also applied to the legacy refresh key at login). |
| `OAUTH2_REFRESH_TOKEN_EXPIRATION` | — | `RefreshIdleTTL` | Legacy fallback, integer **minutes** (no deprecation warning is logged, unlike the access-token equivalent). |
| `OAUTH2_REFRESH_ABSOLUTE_TTL` | `720h` (30 days) | `RefreshAbsoluteTTL` | Absolute cap of a refresh-token family since its first token. |
| `OAUTH2_REFRESH_REUSE_GRACE` | `30s` | `RefreshReuseGrace` | Window in which replaying a consumed refresh token returns the same issued pair (idempotent). |
| `OAUTH2_STRICT_401` | `false` | `Strict401Enabled` | When true, unknown/expired Bearer tokens get an explicit `401` with `WWW-Authenticate` instead of continuing anonymous. |

Code-driven behavior (not configurable): `expires_in` for opaque tokens equals the access TTL in seconds; access-token and refresh-token key prefixes are fixed empty strings; the claim-wait loop is fixed at 1 s timeout / 25 ms interval; the JWT access TTL is owned by the `oauth2_jwt` subplugin (`OAUTH2_JWT_TTL`), which also reuses `ParseTTL` for its own variables.

## Design decisions

- **Native password-grant implementation** over Echo + Redis (no `golang.org/x/oauth2` in this flow), reusing `ValidUsernamePassword`/`PasswordModel` from the authentication feature instead of duplicating credential logic.
- **Redis-only token state, zero migrations** — `GetMigrations` returns empty; tokens are ephemeral by nature and get their lifetimes from TTLs.
- **Opaque access tokens by default, JWT as a pluggable format** — the package defines `AccessTokenFormat` and consumes a `JWTAccessGenerator` callback registered by `oauth2_jwt`; it never touches signing keys or claims, and fails loudly when asked for a JWT without the generator installed.
- **Single-use rotating refresh tokens with atomic claim** — `GETDEL` guarantees exactly one concurrent winner per token; losers wait up to 1 s and receive the winner's pair via the grace record instead of an error.
- **Idempotent replay grace (30 s default)** absorbs lost races between tabs/devices; **tombstones** (`RTTOMB:`) survive the grace window so that later replay is classified as reuse, revoking the entire family (`RTFAM:` index) as theft containment.
- **Two-dimensional lifetime** — idle TTL renewed per rotation plus an absolute family cap checked against `absoluteDeadline`, so continuously refreshed sessions still die after 30 days by default.
- **Legacy compatibility** — unprefixed refresh keys from old deployments are claimed on rotation, migrated to the new family format, and remain revocable; family revocation also deletes unprefixed members.
- **Safe failure modes** — invalid TTL config aborts token writing (no token with a wrong deadline); infra failures during refresh return `ErrInternal` and revoke nothing; failed claims are restored best-effort so retries are consistent.
- **Anonymous-by-default token validation with opt-in strict 401** — expired/unknown tokens continue as anonymous so clients can attempt a refresh; 403 is reserved for definitively invalid sessions (blocked user), preventing premature frontend logouts; strict mode (`OAUTH2_STRICT_401`) emits RFC 6750 `WWW-Authenticate` headers for APIs that require explicit 401s.
- **JWT-aware middleware interplay** — the opaque middleware short-circuits on the `auth.jwt` context flag set by the `oauth2_jwt` middleware (which must register first), avoiding false 401s for stateless JWTs that have no Redis record.
- **RFC 7009 revocation semantics** — always 200 for well-formed bodies, no existence disclosure, best-effort storage cleanup with failures logged only.
- **Consumer-owned refresh route** — the plugin deliberately registers no `/grant-password/refresh-token` route, delegating that (and HTTP error mapping) to consumers so multiple integrations can coexist without Echo route conflicts.

## Assumptions & open items

Code-supported observations that need human review:

1. **No refresh route is registered by this plugin in this repository.** `BindRoutes` comments that consumers register `/grant-password/refresh-token` (e.g. `mm`). Here, only the `oauth2_jwt` subplugin exposes a refresh endpoint (`/auth/jwt/refresh-token`); a plain opaque-format client of this module has no in-repo HTTP path to refresh.
2. **Possible inverted error branch in the auth middleware.** In `oauth2TokenAuthentication`, a `gorm.ErrRecordNotFound` from `UserFindOne` yields `500 internal server error`, while *other* DB errors yield `403 invalid token` — the opposite of the usual mapping. Documented as coded; looks like a bug.
3. **The middleware rechecks only `Blocked`, not `Active`.** A user deactivated after login keeps authenticating with an existing valid token until it expires (login itself rejects inactive users with 403).
4. **`grant_type` is accepted but ignored** by `AuthenticationOauth2PasswordHandler` — the endpoint behaves as a password grant regardless of the value.
5. **`Oauth2FindUserWithToken` is a stub** returning `(nil, nil)`; it is exported but non-functional.
6. **Both token keys store the same JSON at login.** `Oauth2GenerateAndSaveToken` writes the full `Oauth2TokenData` (including the refresh-token string) under the access-token key and vice versa; redundant, and legacy consumers may depend on the shape.
7. **Empty key prefixes** — access and refresh tokens live at bare keys in the shared `SITE_OAUTH2_DB`; the commented-out `AT:`/`RT:` prefixes in `storage.go` suggest a planned (unexecuted) namespacing. Any other data in the same DB could collide.
8. **Opaque login pairs start with no family/absolute cap.** `Oauth2GenerateAndSaveToken` writes the legacy format; the family, tombstones and absolute deadline only exist after the first rotation (or immediately for JWT logins). Idle TTL still applies from login.
9. **`OAUTH2_REFRESH_TOKEN_EXPIRATION` has no deprecation warning**, unlike its access-token counterpart which logs one.
10. **Strict Bearer parsing quirks (tested as intended)** — scheme matching is case-sensitive via `strings.HasPrefix(authorization, "Bearer")`, and `"Bearer abc "` (trailing space → 3 split parts) parses as no token.
11. **Claim-wait latency** — on a refresh miss the handler blocks up to 1 s polling Redis before answering `expired_idle`; bursts of replays for the same consumed token can hold handlers for that duration each.
12. **Restored claimed keys use the idle TTL** — after a failed rotation the key is re-written with the current idle TTL rather than its original remaining TTL (best-effort heuristic).
13. **`Scopes` and `TokenType` are placeholders** — always `[]` and `""`; no scope enforcement exists anywhere in the flow.
14. **Revoke treats any unknown `token_type_hint` as a refresh token** (only `access_token` is special-cased); the hint value itself is never validated against RFC 7009's registry.
15. **Test fixture path oddity** — `oauth2_password/setup_test.go` sets `TEMPLATE_FOLDER=./testdata/themes`, but the directory does not exist inside `oauth2_password/` (and `oauth2_jwt` tests point at `../oauth2_password/testdata/themes`); tests pass because templates are only demanded when rendering. Test-hygiene issue only.
16. **Skipped scope** — the `oauth2_jwt/` internals (JWT signing, claims, its own config/middleware) are documented by the `oauth2-jwt` feature, not here; this spec covers only this package's exported surface consumed by that subplugin.
