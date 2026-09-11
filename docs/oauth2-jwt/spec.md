# OAuth2 JWT — Specification

## Overview & architecture

The feature lives entirely in `oauth2_jwt/` (Go package `user_oauth2_jwt`):

| File | Responsibility |
| ---- | -------------- |
| `Oauth2JWTPlugin.go` | `Oauth2JWTPlugin` (name `"AuthOauth2JWT"`), `NewPlugin(cfg *PluginCfgs)`, event wiring, route group `/auth/jwt`, empty migration list. |
| `config.go` | `Config` struct, `InitConfig(app)` (reads `OAUTH2_JWT_*` on the `configuration` event, fail-fast on missing secret/invalid TTLs, registers the JWT access generator in `oauth2_password`), `GetConfig()` (nil-safe read guarded by an `RWMutex`). |
| `jwt.go` | `AccessClaims`, `GenerateAccessToken`, `ValidateAccessToken`, `LooksLikeJWT`, `KeyID` (`"1"`), `ErrTokenExpired`. |
| `middleware.go` | `jwtAuthenticationMiddleware` (global Echo middleware) and `BuildUserStubFromClaims`. |
| `handlers.go` | `AuthenticationJWTHandler`, `RefreshTokenJWTHandler`, request/response structs, login-activity hook plumbing. |
| Tests | `setup_test.go` (miniredis + in-memory sqlite harness), `jwt_test.go`, `jwt_table_test.go`, `plugin_test.go` (HTTP-level behavior), `benchmark_test.go` (opaque vs JWT middleware cost). |

Architecture and integration points:

1. **Dependency on `oauth2_password`** (one-way): the subplugin never touches Redis itself. It registers `GenerateAccessToken` as the `JWTAccessGenerator` (`SetJWTAccessGenerator`) on the `configuration` event; `oauth2_password.Oauth2GenerateAndSaveTokenJWT` and `RotateRefreshTokenWithFormat(..., FormatJWT)` then call back into it for the access token while owning the refresh-token storage (Redis keys `RT:`, `RTUSED:`, `RTTOMB:`, `RTFAM:`). Without the subplugin installed, the generator is nil and JWT-format issuance fails with an explicit error instead of emitting unknown tokens.
2. **Plugin lifecycle** (`Init`): listens to `configuration` (calls the idempotent `user_oauth2_password.InitStorage(app)` first — covering consumers that register only this subplugin — then `InitConfig`), `bindMiddlewares` (`router.Use(jwtAuthenticationMiddleware())`, global) and `bindRoutes` (group `auth_jwt` at `/auth/jwt`).
3. **Two middlewares cooperate**. The JWT middleware runs **before** the opaque middleware (order = `RegisterPlugin` order):
   - Bearer token with JWT compact shape (`LooksLikeJWT`: exactly two dots, three non-empty segments) → validated here; on success the request context is marked authenticated and `c.Set("auth.jwt", true)` makes the opaque middleware skip its Redis lookup (the JWT does not exist there).
   - Bearer token that is opaque, or no `Authorization` header → passed through untouched for the opaque middleware (`oauth2TokenAuthentication`).
   - Public routes (`/health*`, `/public*`) are skipped by both middlewares.
4. **Stateless access, stateful refresh**: the access JWT is never persisted; only the refresh token has server-side state, owned by `oauth2_password` (single-use rotation, reuse grace, family absolute cap, chained revocation on reuse). Consequence: there is **no access-token denylist** — a JWT stays valid until `exp` (+ leeway) even after logout/revocation.
5. **Kill-switch**: installing/uninstalling the subplugin enables/disables the whole feature — routes disappear (404) and JWTs stop validating (opaque middleware → Redis miss → 401) without code changes.

## API contract

Routes registered by `Oauth2JWTPlugin.BindRoutes` on the router group `auth_jwt` (`/auth/jwt`):

| Method | Path | Auth / permission |
| ------ | ---- | ----------------- |
| POST | `/auth/jwt/authenticate` | Public (no permission required). Body credentials `email` + `password` (both required by validation). A valid `Authorization: Bearer` header is still enforced by the middleware — an invalid JWT on this route returns 401 before reaching the handler. |
| POST | `/auth/jwt/refresh-token` | Public (no permission required). Body `refresh_token` (required by validation). The presented refresh token is the credential. |

No other endpoint is registered by this package. Related endpoints owned by sibling features (referenced, not reimplemented): `POST /auth/grant-password/authenticate`, `POST /auth/grant-password/revoke` (RFC 7009 revocation; see `../oauth2-password/guide.md`), `POST /auth/logout` (see `../authentication/guide.md`).

### `POST /auth/jwt/authenticate`

Request body (JSON):

```json
{ "grant_type": "password", "email": "user@example.com", "password": "secret" }
```

`grant_type` is accepted but never checked by the handler. Bind failures (malformed JSON) return `404` with no content.

| Outcome | Status | Body (`messages` entries) |
| ------- | ------ | ------------------------- |
| User/password record not found | 400 | danger: `"Usuário não encontrado ou não possuí senha cadastrada."` |
| Wrong password | 400 | danger: `"Email ou senha incorretos."` |
| Account inactive (valid credentials) | 403 | warning: `"Conta não ativada. Por favor, verifique seu email para ativar sua conta."` |
| Account blocked | 403 | danger: `"Conta bloqueada. Entre em contato com o suporte."` |
| Internal error | 500 (error propagation) | — |
| Success | 200 | see below |

Success response (JSON):

```json
{
  "access_token": "<JWT>",
  "refresh_token": "<opaque rotating token>",
  "expires_in": 600,
  "user": { /* full user_models.UserModel */ }
}
```

`expires_in` is the JWT TTL in seconds and always reflects `OAUTH2_JWT_TTL` (e.g. `3m` → `180`). The `OnLoginActivity` hook fires with the user ID after success.

### `POST /auth/jwt/refresh-token`

Request body (JSON): `{ "refresh_token": "..." }` (required).

| Outcome | Status | Body |
| ------- | ------ | ---- |
| Unknown / idle-expired / absolute-expired token, or reuse detected outside the grace window | 400 | danger: `"Sessão expirada. Entre novamente."` |
| Owner no longer exists (nil / zero ID) | 400 | danger: `"Sessão expirada. Entre novamente."` |
| Owner inactive | 403 | warning: `"Conta não ativada. Por favor, verifique seu email para ativar sua conta."` |
| Owner blocked | 403 | danger: `"Conta bloqueada. Entre em contato com o suporte."` |
| Infrastructure failure (`ErrInternal` and future kinds) | 500 (error propagated) | — |
| Success (including replay inside the grace window, which returns the **same** pair) | 200 | same shape as authenticate |

Expired-idle, absolute-expired and reuse-detected are deliberately indistinguishable to the client. `OnLoginActivity` fires on every successful response, replays included.

### Middleware behavior on any other route

| Request | Result |
| ------- | ------ |
| No `Authorization` header, or Bearer token not JWT-shaped | Passed to the opaque middleware of `oauth2_password` (untouched here). |
| Bearer JWT valid | Request authenticated: user stub from claims, roles filled (token roles plus the `authenticated` role added by the request context), `auth.jwt` flag set. |
| Bearer JWT invalid/expired | `401` with `WWW-Authenticate: Bearer error="invalid_token", error_description="token expired"` (expired) or `...error_description="invalid token"` (any other failure) — **regardless of `OAUTH2_STRICT_401`**. |
| Bearer JWT while config not yet loaded | `401` `"invalid token"` (fail-closed) + error log. |

## Data models

### `AccessClaims` (`jwt.go`)

JWT payload (no PII):

| Field | JSON | Meaning |
| ----- | ---- | ------- |
| `Roles` | `roles` (omitempty) | User roles snapshot; omitted when the user has none. |
| `Active` | `active` | `u.IsActive()` snapshot at issuance. |
| `Blocked` | `blocked` | `u.IsBlocked()` snapshot at issuance. |
| StandardClaims | `iss`, `sub`, `aud`, `jti`, `iat`, `nbf`, `exp` | `sub` is the user ID (numeric string); `jti` is a fresh UUID v4 per token; `iat = nbf =` issuance time; `exp = iat + TTL`. |

Header: `alg: HS256` (pinned) and `kid: "1"` (`KeyID` constant; reserved for future key rotation, per RFC 8725 §3.5).

### `Config` (`config.go`)

`Secret`, `Issuer`, `Audience` (strings), `TTL`, `Leeway` (`time.Duration`). Held in a package-level `activeCfg` guarded by `sync.RWMutex`; `GetConfig()` returns `nil` before the `configuration` event.

### HTTP structs (`handlers.go`)

- Requests: `oauth2PasswordRequestBody{Email (required), Password (required), GrantType}` and `refreshTokenRequestBody{RefreshToken (required)}`.
- Success response: `authenticationJWTJSONResponse{AccessToken, RefreshToken, ExpiresIn, User}` (pointer fields, snake_case JSON keys).
- Error response: `authenticationJWTJSONResponseError` embedding `bolo.BaseErrorResponse` (a `messages` array of `{status, message}`).

### User stub (`middleware.go`)

`BuildUserStubFromClaims` returns a `user_models.UserModel` with only `ID` (parsed from `sub`), `Active`, `Blocked` and `RolesText` (JSON array of the `roles` claim) populated. The request context (`SetAuthenticatedUserAndFillRoles`) makes `GetRoles`/`ctx.Can` work from `RolesText` and adds the standard `authenticated` role. The stub never hits the database; staleness vs the database is bounded by the token TTL (accepted design contract — the authoritative check happens at the refresh gate).

### Refresh-token state (owned by `oauth2_password`)

`RefreshTokenRecord` (`RT:<token>`: `ownerId`, `familyId`, `createdAt`, `absoluteDeadline`), used-pair records (`RTUSED:`), tombstones (`RTTOMB:`) and family sets (`RTFAM:`) are documented in the sibling feature; this package only consumes them through `RotateRefreshTokenWithFormat`.

## Flows (JWT issuance/validation)

### 1. Issuance (`GenerateAccessToken`)

1. `expiresIn = cfg.TTL / time.Second`; `now = time.Now()`.
2. Claims built from the user: `roles`, `active`, `blocked`, `sub = u.GetID()`, `aud = cfg.Audience`, `iss = cfg.Issuer`, `iat = nbf = now`, `exp = now + TTL`, `jti =` new UUID v4.
3. Token signed HS256 with `cfg.Secret`; header gets `kid = "1"`.
4. Caller (`Oauth2GenerateAndSaveTokenJWT`) persists only the refresh token (new `RT:` record with a fresh family and absolute deadline); the JWT itself is returned to the client untouched.

### 2. Validation (`ValidateAccessToken`)

Cryptographic phase (golang-jwt parser pinned with `ValidMethods: [HS256]` and `SkipClaimsValidation: true` — v3 of the library has no leeway support):

1. Algorithm must be `*jwt.SigningMethodHMAC` (double-check on top of `ValidMethods`; mitigates algorithm-confusion/`alg:none`).
2. `kid`, when present, must equal `KeyID` (`"1"`); unknown `kid` rejects.
3. HS256 signature must verify with `cfg.Secret`.

Semantic phase (manual, with `cfg.Leeway`), fail-closed — any failure rejects:

1. `iss` exactly equals `cfg.Issuer`; `aud` exactly equals `cfg.Audience`.
2. `sub` non-empty **and** parseable as a numeric userID (`ParseUint` 64 bits).
3. `jti` non-empty.
4. `exp`: `now` must be before `exp + leeway`; a missing/zero `exp` falls back to epoch (1970) and rejects — surfaced as `ErrTokenExpired`.
5. `nbf` (when > 0): rejects if `nbf > now + leeway`.
6. `iat` (when > 0): rejects if `iat > now + leeway`.

### 3. Request authentication (middleware)

1. Skip public routes; extract the Bearer token (only the `Bearer` scheme is honored).
2. `token == ""` or `!LooksLikeJWT(token)` → pass through (opaque flow owns it).
3. `GetConfig() == nil` → log + `401` `"invalid token"` (fail-closed).
4. Validate; on failure → `401` with `WWW-Authenticate` (`token expired` vs `invalid token` descriptions).
5. On success → mount stub, `SetAuthenticatedUserAndFillRoles`, set `auth.jwt = true`, continue.

### 4. Refresh (delegated)

`RefreshTokenJWTHandler` calls `RotateRefreshTokenWithFormat(ctx, refresh_token, FormatJWT)`. Semantics owned by `oauth2_password`: atomic claim of the single-use token (GETDEL), idempotent replay inside `OAUTH2_REFRESH_REUSE_GRACE` returning the same pair, absolute deadline per family, chained family revocation when reuse is detected outside the grace, and transparent migration of legacy opaque refresh tokens to the JWT format on the first rotation. This handler maps `RefreshError` kinds to the HTTP statuses/messages listed in the API contract. Details: [../authentication/guide.md](../authentication/guide.md).

### 5. Revocation / logout (delegated)

`POST /auth/grant-password/revoke` (RFC 7009) always answers `200`: with `token_type_hint: "access_token"` a JWT hint is a no-op delete (stateless); with a refresh token the whole family dies immediately and further refresh attempts return `400` `"Sessão expirada. Entre novamente."`. The revoked JWT itself remains usable until `exp` (no denylist).

## Configuration

Read once on the `configuration` event by `InitConfig`. Missing secret or invalid TTL/leeway values abort startup (`log.Fatal`).

| Env var | Required | Default | Description |
| ------- | -------- | ------- | ----------- |
| `OAUTH2_JWT_SECRET` | **yes** | none (fails fast) | HS256 signing secret. No default by design; the startup message recommends a random secret of at least 32 bytes. |
| `OAUTH2_JWT_ISSUER` | no | `""` | `iss` claim value; exact-match enforced at validation. |
| `OAUTH2_JWT_AUDIENCE` | no | `mm` | `aud` claim value; exact-match enforced at validation. |
| `OAUTH2_JWT_TTL` | no | `10m` | Access-token lifetime; also returned as `expires_in` (seconds). Parsed with `oauth2_password.ParseTTL` (units `us/ms/s/m/h/d`, e.g. `30m`, `7d`; must be > 0). |
| `OAUTH2_JWT_LEEWAY` | no | `30s` | Clock-skew tolerance applied to `exp`/`nbf`/`iat` checks. Same parser. |

Related configuration owned by `oauth2_password` (used through the shared storage and refresh machinery, documented in the sibling feature): `SITE_OAUTH2_ADDR_WRITER`, `SITE_OAUTH2_ADDR_READER`, `SITE_OAUTH2_DB` (default 1), `SITE_OAUTH2_PASSWORD`, `OAUTH2_REFRESH_IDLE_TTL` (default 72h), `OAUTH2_REFRESH_ABSOLUTE_TTL` (default 720h/30d), `OAUTH2_REFRESH_REUSE_GRACE` (default 30s), `OAUTH2_STRICT_401` (default false; affects only the opaque middleware — the JWT middleware always answers 401 for JWT-format tokens).

## Design decisions

1. **HS256 with a single shared secret, no default.** A missing `OAUTH2_JWT_SECRET` aborts startup: an empty/implicit secret would accept forged tokens (the hardcoded-default-secret anti-pattern is explicitly avoided).
2. **No PII in claims.** The payload carries only the user ID, roles and the `active`/`blocked` snapshot so the middleware can authenticate requests without Redis or database access.
3. **Snapshot staleness is an accepted contract.** Role/block/active changes propagate only when the token is refreshed; the TTL is kept short (10m default) and the refresh gate re-checks the database (inactive/blocked owners are refused).
4. **Algorithm pinning twice.** `ValidMethods` rejects `alg:none` and algorithm swaps, plus a concrete `*jwt.SigningMethodHMAC` type assertion mitigates key-confusion; tests cover `none`, `HS384`, `HS512` and crafted `RS256` headers.
5. **`kid` today, rotation tomorrow.** Every issued token carries `kid: "1"` (RFC 8725 §3.5) so multiple keys can coexist when rotation is added; unknown kids are rejected.
6. **Manual claim validation with leeway.** golang-jwt v3 lacks leeway support, so `SkipClaimsValidation` is on and `exp`/`nbf`/`iat` are checked against `OAUTH2_JWT_LEEWAY`; validation fails closed (missing `exp`/`sub`/`jti` reject).
7. **JWT-format Bearer tokens always answer 401 from this middleware**, independent of `OAUTH2_STRICT_401`: the format is unambiguously ours, and deferring to the opaque flow would only turn a valid token into a false 401 (Redis miss). Opaque tokens and anonymous requests pass through untouched so both flows coexist.
8. **`auth.jwt` context flag.** Set after successful JWT authentication so the opaque middleware early-returns instead of failing on the Redis miss under `OAUTH2_STRICT_401=true`.
9. **Identical HTTP contract to grant-password.** Same body/response shape, status codes and (Portuguese) messages, so frontends switch endpoints with no other change; expired-idle, absolute-expired, unknown and reuse-outside-grace refresh failures are deliberately indistinguishable (`"Sessão expirada."`).
10. **Refresh security is not duplicated.** Rotation single-use, grace replay, absolute family cap and chained revocation live in `oauth2_password`; the subplugin only maps results to HTTP and selects the JWT format.
11. **No access-token denylist.** Revocation of stateless JWTs is accepted as impossible without extra state; RFC 7009 revoke answers 200 with a no-op for JWT hints, and real termination of a session is done by revoking the refresh family.
12. **Plugin install as kill-switch.** Uninstalling removes routes and stops JWT validation; the middleware ordering requirement (JWT before opaque, per `RegisterPlugin` order) is part of the contract.
13. **Login-activity hook parity.** `PluginCfgs.OnLoginActivity` mirrors the consumer handlers (e.g. mm login activity); failures are logged and never break login/refresh; replays inside the grace also count (the handler cannot distinguish them).

## Assumptions & open items

- **`grant_type` is never enforced.** `oauth2PasswordRequestBody.GrantType` is bound but no handler check exists; any value (or none) behaves as the password grant. Unclear whether this is intentional compatibility or a gap to fix.
- **Bind failures return `404` with no content** (`c.NoContent(http.StatusNotFound)`) for malformed JSON on both endpoints — an unusual mapping, apparently kept for parity with the legacy grant-password handlers; confirm it is contractual for frontends.
- **`kid` is optional at validation.** Only a present-but-different `kid` is rejected; a token without `kid` still validates. When key rotation lands, this will likely need to become mandatory.
- **Default audience `"mm"`** is baked into the package as `DefaultJWTAudience`. It looks consumer-specific (the "mm" app is referenced in comments); other consumers must remember to override `OAUTH2_JWT_AUDIENCE`.
- **User-facing messages are hardcoded pt-BR strings** in handlers; no i18n mechanism exists.
- **Single symmetric secret.** HS256 means every issuer and verifier shares `OAUTH2_JWT_SECRET`; there is no JWKS/asymmetric-key support and no key-rotation implementation yet (`KeyID` "1" is groundwork only). Multi-instance deployments must share the same secret and clock (leeway of 30s default mitigates skew).
- **`loginActivityHook` is a package-global** set by `NewPlugin`; constructing a second plugin overwrites the previous hook (last wins). Not a problem in the tested single-plugin setup, but worth noting for unusual compositions.
- **Middleware ordering is convention, not enforcement.** The JWT middleware must be registered before the opaque one (via `RegisterPlugin` order); nothing in code validates this. The harness always registers JWT first, matching the production consumer (mm).
- **The `"v1"` in the `KeyID` comment** ("since v1 every issued token carries the kid") refers informally to the current token format; no explicit format-version scheme exists in code.
- **`sub` must be a numeric userID**, matching `user_models.UserModel` IDs; other ID schemes are unsupported by design.
- **Scope of this document.** The internals of `oauth2_password` (refresh rotation algorithm, storage layout, opaque middleware, revoke handler internals — e.g. the ~600-line `refresh.go`) are documented by their own feature docs; only the contracts used by `oauth2_jwt` are repeated here. The `../oauth2-password/guide.md` page is the designated sibling doc and may not exist yet at the time of writing.
