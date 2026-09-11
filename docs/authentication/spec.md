---
id: authentication-spec
title: Authentication — technical specification
status: draft
created_at: 2026-09-11
updated_at: 2026-09-11
owner: TBD
affected_areas: [backend, http-api]
tags: [authentication, login, sessions, password-reset, throttling, recaptcha, redis, email, backend, http-api]
---

# Authentication — technical specification

## Overview & architecture

The feature lives in the `auth` plugin (`NewAuthPlugin`, `GetName() == "auth"`). `AuthPlugin.Init` wires the plugin to Bolo lifecycle events:

| Event | Handler | Effect |
| --- | --- | --- |
| `install` | `InstallAuth` | Seeds one default `AuthChangePasswordEmail` email-template record in the database (`CreateDefaultEmailTemplates`). |
| `configuration` | `Init` → `initRedisSession` | Creates the Redis session clients (`SessionDBWriter`, `SessionDBReader`) from `SITE_SESSION_ADDR_WRITER`, `SITE_SESSION_ADDR_READER`, `SITE_SESSION_PASSWORD`, DB index `SITE_CACHE_DB` (default `2`). Idempotent via `sessionInitialized`. |
| `bindMiddlewares` | `bindMiddlewares` | Creates a `redisstore/v9` store over `SessionDBWriter`, reads `SITE_SESSION_RESAVE` (default `true`) into `AuthPlugin.SessionResave`, and installs two global middlewares: `session.Middleware(store)` and `sessionAuthenticationMiddleware()`. |
| `bindRoutes` | `BindRoutes` | Registers all `/auth`, `/api/v2/auth`, `/login`, `/logout` and the Facebook app-login route (see API contract). |
| `setTemplateFunctions` | `setTemplateFunctions` | Registers the `renderFlashMessages` template function. |
| `http-error` | `OnHTTPError` | Converts `*bolo.HTTPError` and `validator.ValidationErrors` raised by handlers into session flash messages. |
| `bootstrap` | `Bootstrap` → `AddEmailTemplates` | Registers the three e-mail template definitions in the `emails` plugin. |
| `close` | `OnClose` | Closes the session store if it is a legacy `redistore.RediStore`. |

Components:

- **SessionController** — HTML/redirect login page and login/logout for cookie sessions.
- **AuthController** — logout API, current user, own-password change, admin set-password, forgot-password steps 1–3, signup (not routed, see open items).
- **Session middleware** (`middlewares.go` + `auth_session.go`) — resolves the authenticated user from the Redis session for every non-public route; public prefixes are `/health` and `/public`.
- **Session plumbing** (`session.go`) — `SetUserSession` (stores `uid` in the `session` cookie-backed Redis session and applies `user_helpers.GetSessionOptions`) and `DeleteUserSession` (`uid = 0`, `MaxAge = -1`).
- **Flash messages** (`flash.go`) — `FlashMessage{Type, Message, Field, Tag}` stored in session flashes under the `"messages"` key; used by the HTML flows.
- **Models** — `PasswordModel` (`passwords` table, bcrypt) and `AuthTokenModel` (`authtokens` table, one-time tokens).
- **Security package** — `LoginThrottle` (Redis counters) and `ReCAPTCHA` (Google siteverify client), not wired to routes inside this module.

Ownership note: `handlers.go` belongs to this feature area but contains only `UserSettingsHandler` (the JSON bootstrap payload served at `GET /user-settings`, registered by the **user** plugin, not the auth plugin — see [../user-management/guide.md](../user-management/guide.md)). It contains no route or middleware registration of its own. `handlers.go` does not reference any `FACEBOOK_*` configuration; all Facebook glue lives in `FacebookAuthController.go` and is documented in [../facebook-auth/guide.md](../facebook-auth/guide.md).

## API contract

Routes below are exactly those registered by `AuthPlugin.BindRoutes`. Authentication/permission reflects the handler checks; there is no route-level permission middleware in this module.

| Method | Path | Auth / permission |
| --- | --- | --- |
| GET | `/login` | Public. Redirects `307` to `/` when already authenticated. Renders `auth/login`. |
| POST | `/login` | Public. Body: `email` (username or e-mail, required), `password` (required), `remember_me` (bool, bound but unused). Errors re-render the login page with HTTP 400 + flash messages; success sets the session cookie and redirects `302` to `/`. |
| GET | `/logout` | Public. Deletes the cookie session (`uid = 0`, `MaxAge = -1`), redirects `307` to `/`. |
| POST | `/logout` | Same as GET `/logout`. |
| GET | `/auth/change-password` | Authenticated session required (redirects `307` to `/` when anonymous). Renders `auth/change-password`. |
| POST | `/auth/change-password` | Authenticated session required. Form/JSON body: `password` (current, optional), `newPassword` (required, min 3), `rNewPassword` (required, must equal `newPassword`). Re-renders the page with flash messages on error; sends `AuthChangePasswordEmail` on success. |
| GET | `/auth/logout` | Public. Revokes OAuth2 tokens when headers are present (see below); always returns `200` JSON `{}`. |
| POST | `/auth/logout` | Same as GET. Optional header `X-Refresh-Token` (or body `{"refresh_token": "..."}`) revokes the refresh-token family (best-effort); optional `Authorization: Bearer <token>` deletes that access token. |
| GET | `/auth/forgot-password` | Public. Renders `auth/forgot-password-request-with-identifier` (JSON response when `Accept: application/json`). |
| POST | `/auth/forgot-password` | Public. Body: `email` (required, e-mail format), `reset_prefix_name` (optional). Creates a `resetPassword` auth token and queues the `AuthResetPasswordEmail`. Always answers `200` for unknown e-mails in JSON mode (anti-enumeration). |
| GET | `/auth/:userID/forgot-password/reset` | Public. Query `t` = token. Validates user + token; renders `auth/forgot-password-reset-page`; `400` empty content if `userID`/`t` missing; `404` for blocked users or invalid tokens. |
| POST | `/auth/:userID/forgot-password/reset` | Public. Same validations; binds/validates the request body but does **not** change the password (the change happens in `/api/v2/auth/forgot-password/process`). |
| GET | `/auth/current` | Public. Returns `200` with the public view of the authenticated user (`UserModelPublic`) or `{}` when anonymous. |
| POST | `/auth/:userID/new-password` | Permission `manage_users` required (else `403`). Body: `newPassword` (required, min 3), `rNewPassword` (required, must equal). We.js compatibility alias. Returns `200` `{}`. |
| POST | `/auth/:userID/set-password` | Same as `/auth/:userID/new-password`. |
| POST | `/api/v2/auth/change-password` | Authenticated user required (else `403`). Same body/validation as `POST /auth/change-password`; wrong current password → `422`; success → `200` `{"messages":[...]}`. |
| POST | `/api/v2/auth/forgot-password/process` | Public + valid reset token. Body: `token` (required), `userID` (required, JSON number), `newPassword` (required, min 3), `rNewPassword` (required, must equal), `redirectOnSucess` (optional URL). Invalid token → `400`; success consumes the token, sends `AuthChangePasswordEmail` and returns `200` `{"messages":[...]}` or redirects `302` to `redirectOnSucess`. |
| POST | `/auth/facebook/app-login-code` | Public. Facebook app-code login; implemented by `FacebookAuthController` — documented in [../facebook-auth/guide.md](../facebook-auth/guide.md). |

Global middleware applied to all routes (including the table above): `session.Middleware` (Redis store) and `sessionAuthenticationMiddleware`, which skips paths prefixed with `/health` or `/public`.

## Data models

### `PasswordModel` — table `passwords`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | uint64 PK | |
| `userId` | `*int64`, `bigint` | FK to users by convention (no DB constraint). |
| `password` | `text` | bcrypt hash (`bcrypt.DefaultCost`). |
| `createdAt` / `updatedAt` | datetime, not null | |

Behavior:

- `SetPassword(password)` — rejects empty password, bcrypt-hashes into `Password`.
- `Compare(password)` — `bcrypt.CompareHashAndPassword`; returns error when the stored hash is empty or hashes mismatch.
- `FindPasswordByUsername(identifier, &record)` — joins `users` and matches `users.username = ? OR users.email = ?`.
- `FindPasswordByUserID(userID, &record)` — tolerates record-not-found (returns nil with `ID == 0`).
- `UpdateUserPasswordByUserID(userID, password)` — creates the record when missing, otherwise updates; used by `UserModel.SetPassword`.
- `UserModel.ValidPassword(password)` — same algorithm as `ValidUsernamePassword` but by user ID.

`ValidUsernamePassword(username, password)` loads the password record by username/e-mail and compares with bcrypt; returns `(false, nil)` on mismatch and surfaces `bcrypt.ErrMismatchedHashAndPassword` to callers for special-casing.

### `AuthTokenModel` — table `authtokens`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | uint64 PK | |
| `userId` | `*string`, indexed | |
| `providerUserId` | int64 | Used by social-auth token storage. |
| `tokenProviderId` | varchar(255) | Provider identifier. |
| `tokenType` | varchar(255) | e.g. `resetPassword`. |
| `token` | varchar(255) | Random 35-char string (`helpers.RandStringBytes`) generated on create when empty. |
| `isValid` | bool | Only valid tokens pass `ValidAuthToken`. |
| `redirectUrl` | text | |
| `createdAt` / `updatedAt` | datetime | |

Behavior:

- `CreateAuthToken(userID, tokenType)` — creates a record with `IsValid = true`.
- `ValidAuthToken(userID, token)` — looks up by `token` + `userId`; valid only if found and `IsValid`.
- `Delete()` — hard delete (`Unscoped`), giving single-use semantics to consumed reset tokens.
- `GetResetUrl(ctx, resetPrefixName, resetPrefixNames)` — returns `resetPrefixNames[prefix] + "t=<token>&u=<userID>"` when the configured prefix exists, otherwise `<AppOrigin>/auth/<userID>/forgot-password/reset?t=<token>&u=<userID>`.
- `FindInvalidOldUserTokens(uid)` — lists tokens with `isValid = false` (used by other features/social auth).

### Session state

- Cookie name: `session` (gorilla/echo-contrib session), stored in Redis via `redisstore/v9`.
- Value key: `uid` (string user ID). Helper `SessionData{UserID string}` marshals the same shape as JSON.
- Cookie options from `user_helpers.GetSessionOptions`: `Path` = `SITE_SESSION_PATH` (default `/`), `MaxAge` = `SITE_SESSION_MAX_AGE` (default `604800` = 7 days), `HttpOnly` = `SITE_SESSION_HTTP_ONLY` (default `false`); `Secure` forced `true` when `ENV == "production"`.

### Login throttle state — Redis (package `user/security`)

- `LoginThrottleStatus{Key, Count int, WaitTime int64}` serialized as JSON; `WaitTime` is a Unix timestamp.
- Key: `<RealIP>_<userID>`.
- Written with a TTL of `ResetTime` (10 minutes); thresholds: `MaxErrors = 3`, lockout `WaitTime = 10 minutes`.

### Flash message

`FlashMessage{Type, Message, Field, Tag}` JSON-encoded into the session flash bucket `"messages"`; surfaced in templates through `renderFlashMessages`.

### E-mail templates (registered at bootstrap in `email-templates.go`)

| Template name | Purpose | Key variables |
| --- | --- | --- |
| `AccontActivationEmail` | Account activation link after signup (name kept as coded, typo included). | `confirmUrl`, `username`, `displayName`, `fullName`, `email`, `siteName`, `siteUrl` |
| `AuthResetPasswordEmail` | Reset-password link. | `userId`, `username`, `displayName`, `siteName`, `siteUrl`, `resetPasswordUrl`, `token` |
| `AuthChangePasswordEmail` | Notification that the password changed. | `username`, `displayName`, `siteName`, `siteUrl` |

Each template has default subject/HTML/text bodies (pt-BR) registered via `emailPlugin.AddEmailTemplate`.

### Migrations

- `migrations/auth/` is an **empty directory** — it contains no migrations.
- The `users`, `passwords` and `authtokens` tables are created by `migrations/user/00001_init.go` (`GetInitMigration`), registered through `UserPlugin.GetMigrations()` (see [../user-management/guide.md](../user-management/guide.md)). The `passwords` migration also creates an `active` column that the Go model does not map.
- `updates/upgrades.go#GetMigrations` returns an empty list; `updates.AddNewPasswordEmailTemplateChange` exists but is a no-op and is not registered.

## Flows (login, logout, throttling, recaptcha)

### Login (password, cookie session)

1. `GET /login` — anonymous users get the `auth/login` page; authenticated users are redirected `307` to `/`.
2. `POST /login` — bind `LoginRequestBody{email, password, remember_me}`; redirect `307` to `/` if already authenticated; validation errors bubble up.
3. Credential check — `ValidUsernamePassword` finds the `passwords` record by `users.username` OR `users.email` and compares bcrypt hashes.
   - `bcrypt.ErrMismatchedHashAndPassword` → flash `Email ou senha incorretos.`, page re-rendered with HTTP 400.
   - Record not found → flash `Usuário não encontrado ou não possuí senha cadastrada.`, HTTP 400.
   - Other validation failures → flash `Erro ao validar a senha.`, HTTP 400.
   - Any other error → returned to the error pipeline.
4. Session creation — `UserFindOneByUsername` loads the user, `SetUserSession` writes `uid` into the Redis session with `GetSessionOptions`, response redirects `302` to `/`.
5. On every subsequent request the session middleware reads `uid`, loads the `UserModel` and calls `SetAuthenticatedUserAndFillRoles`, setting `ctx.IsAuthenticated` and `ctx.Session.UserID`. If another strategy (e.g. OAuth2 bearer, see [../oauth2-password/guide.md](../oauth2-password/guide.md)) already authenticated the request, the session middleware does nothing.

### Logout

Two independent endpoints:

- `GET/POST /logout` (`SessionController.Logout`) — `DeleteUserSession` sets `uid = 0` and `MaxAge = -1` (browser drops the cookie); failures add flash `Error on delete session.`; always redirects `307` to `/`.
- `GET/POST /auth/logout` (`AuthController.Logout`) — API logout:
  1. If header `X-Refresh-Token` (or body `refresh_token`) is present, `RevokeByRefreshToken` revokes the refresh-token family. Best-effort: failures are only logged.
  2. If no `Authorization` header, returns `200` `bolo.EmptyResponse{}`.
  3. With `Authorization: Bearer <token>`, `DeleteAccessToken` removes the access token (failures logged) and returns `200` `{}`.
  - Covered by `TestAuthController_Logout` and `TestAuthController_LogoutRevokesRefreshTokenFamily` (asserts response body `{}` and removal of refresh-token family keys in Redis).

### Session middleware details

- Skips `/health*` and `/public*` prefixes.
- `production` env forces `Secure` on the session cookie.
- When the session has no `uid` but the `session` cookie still exists, the cookie is expired (set to one year in the past) to clean up stale cookies.
- When `SITE_SESSION_RESAVE` is true (default) and the method is `GET`, the session is re-saved with fresh options, refreshing the sliding window (MaxAge) on activity.

### Forgot password (3 steps, one-time tokens)

1. **Request** — `POST /auth/forgot-password` with `email` (+ optional `reset_prefix_name`):
   - Unknown e-mail: JSON mode answers `200` with a generic "if the email is correct..." success message; HTML mode simply re-renders the request page (anti-enumeration).
   - Blocked user: `404` `auth.forgot-password.user.not-found`.
   - Existing user: `CreateAuthToken(userID, "resetPassword")` and, when the `emails` plugin is installed, `SendRequestResetPasswordEmail` builds `AuthResetPasswordEmail` (variables `userName`/`displayName`, `siteName`, `siteUrl`, `resetPasswordUrl`, `token`) and queues it.
   - If queuing fails, a warning response message is added and the reset URL is logged (`logrus.Warn`) so operators can recover the flow.
2. **Reset page** — `GET /auth/:userID/forgot-password/reset?t=<token>`:
   - `400` (empty body) when `userID` or `t` is missing; redirect `307` to `/auth/forgot-password` when the user does not exist; `404` for blocked users; `404` `auth.forgot-password.token.not-found` for invalid/expired tokens.
   - Valid token: renders `auth/forgot-password-reset-page`.
   - `POST` on this page only binds/validates the body; it does not alter the password.
3. **Process** — `POST /api/v2/auth/forgot-password/process` with `token`, `userID`, `newPassword`, `rNewPassword`, optional `redirectOnSucess`:
   - Invalid token → `400` `auth.forgot-password.token.invalid`.
   - Success: `UserModel.SetPassword` (bcrypt update), the token record is hard-deleted (single use), `AuthChangePasswordEmail` is sent asynchronously, success message `Senha alterada com sucesso` is returned (JSON `200`) or the client is redirected `302` to `redirectOnSucess`.

### Change own password

- HTML (`GET/POST /auth/change-password`) and JSON (`POST /api/v2/auth/change-password`) share the same rules:
  - Requires an authenticated user (HTML: flash + page render with 403 status; JSON: `403` `bolo.HTTPError`).
  - Body: `password` (current; optional), `newPassword` (required, min 3), `rNewPassword` (must match).
  - If `password` is empty, the change is allowed **only** when the user has no password record yet (`FindPasswordByUserID` returns `ID == 0`), i.e. setting an initial password; otherwise `422` `invalid password`.
  - If `password` is provided it is verified with `UserModel.ValidPassword`; wrong password → `422` (`Senha inválida, a senha atual está errada` / `Invalid password, current password is wrong`).
  - Success: bcrypt update, async `AuthChangePasswordEmail` notification; HTML re-renders the page with `passwordChanged = true`; JSON returns `200` `EmptySuccessResponse` with success message `Senha alterada com sucesso`.

### Admin set password

`POST /auth/:userID/new-password` (and `/auth/:userID/set-password`, We.js compatibility): validates `newPassword`/`rNewPassword`, requires `manage_users` (`403` otherwise), loads the user (`404` if missing) and calls `UpdateUserPasswordByUserID`. No current-password validation by design (code comment: "Current version dont need validation").

### Throttling (`security/loginThrottle.go`)

- `NewLoginThrottle(app)` builds writer/reader Redis clients from `SITE_OAUTH2_DB` (default `1`) and `AUTH_THROTTLE_REDIS_ADDR_WRITER` / `AUTH_THROTTLE_REDIS_ADDR_READER` (default `127.0.0.1:6379`).
- Registry key: `BuildKey(ip, userID) = ip + "_" + userID`, value = `LoginThrottleStatus` JSON with a 10-minute TTL (`ResetTime`) on every write.
- `CanLogin` — allowed when no registry exists or `now > WaitTime`; denied otherwise (and a denied check increments `Count` via `OnError`, re-arming lockout at `Count >= MaxErrors`).
- `OnLoginFail` — creates the registry on first failure with `Count = 0` (no increment on the very first record); subsequent failures increment and, at `Count >= 3`, set `WaitTime = now + 10 min` (lockout).
- `OnLoginSuccess` — resets `Count` and `WaitTime` when a registry exists.
- **Not wired into any handler in this module** — it is offered as a library (interface `LoginThrottleInterface`) and is exercised only by `security/loginThrottle_test.go` using `redismock` (tests confirm the "locked by count" denial and the fail/record flow).

### reCAPTCHA (`security/recaptcha.go`)

- Client for Google's siteverify endpoint (`https://www.google.com/recaptcha/api/siteverify`), supporting **v2** and **v3** (`VERSION` constants `V2`, `V3`).
- `NewReCAPTCHA(secret, version, timeout)` — rejects a blank secret; `Verify(response)` for simple checks; `VerifyWithOptions(response, VerifyOption{...})` for `Threshold` (v3 only; default minimum score `0.5` via `DefaultThreshold`), `Action` (v3 only), `Hostname`, `ApkPackageName`, `ResponseTime` and `RemoteIP`.
- Errors are `*security.Error` carrying `ErrorCodes` (from Google) and `RequestError` (transport/parse failures), so callers can distinguish "challenge failed" from "verification request failed".
- Custom `netClient` and `clock` interfaces exist for mocking in tests.
- **Not wired into any route in this module**; the test suite in `security/recaptcha_test.go` is fully commented out.

## Configuration

Environment/configuration variables read by this feature (via `bolo` configuration):

| Variable | Default | Used by | Purpose |
| --- | --- | --- | --- |
| `SITE_SESSION_ADDR_WRITER` | — (none; `cfgs.Get`) | `initRedisSession` | Redis address for the session store writer. |
| `SITE_SESSION_ADDR_READER` | — (none; `cfgs.Get`) | `initRedisSession` | Redis address for the session reader client (created, but the session store uses the writer client). |
| `SITE_SESSION_PASSWORD` | `""` | `initRedisSession` | Redis password for both session clients. |
| `SITE_CACHE_DB` | `2` | `initRedisSession` | Redis DB index for sessions. |
| `SITE_SESSION_RESAVE` | `true` | `AuthPlugin.bindMiddlewares` / `sessionAuthenticationHandler` | Re-save the session on GET requests (sliding expiration). |
| `SITE_SESSION_PATH` | `/` | `GetSessionOptions` | Session cookie path. |
| `SITE_SESSION_MAX_AGE` | `604800` (7 days) | `GetSessionOptions` | Session cookie MaxAge (seconds). |
| `SITE_SESSION_HTTP_ONLY` | `false` | `GetSessionOptions` | Session cookie HttpOnly flag. |
| `SITE_OAUTH2_DB` | `1` | `NewLoginThrottle` | Redis DB index for login-throttle counters. |
| `AUTH_THROTTLE_REDIS_ADDR_WRITER` | `127.0.0.1:6379` | `NewLoginThrottle` | Redis address for throttle writes. |
| `AUTH_THROTTLE_REDIS_ADDR_READER` | `127.0.0.1:6379` | `NewLoginThrottle` | Redis address for throttle reads. |

Additional code-driven behavior (not configurable by env): session cookie `Secure = true` when `ENV == "production"`; cookie name is fixed (`session`); session value key is fixed (`uid`).

`handlers.go` (`UserSettingsHandler`, served at `GET /user-settings` by the user plugin) also reads `SITE_NAME`, `DEFAULT_LOCALE`, `PAGER_LIMIT` and `PAGER_LIMIT_MAX`; those belong to the users feature (see [../user-management/guide.md](../user-management/guide.md)) and are listed here only for completeness of the owned file.

`FACEBOOK_*` variables are **not** referenced by this feature's files (`handlers.go` has no Facebook references); they are documented in [../facebook-auth/guide.md](../facebook-auth/guide.md).

## Design decisions

- **Redis-backed server-side sessions** (`redisstore/v9`) instead of cookie stores, with a dedicated DB index (`SITE_CACHE_DB`) and separate writer/reader addresses — sessions survive process restarts and scale horizontally.
- **Single global authentication middleware** that skips only `/health` and `/public`; authentication state is pushed into the Bolo `RequestContext` (`IsAuthenticated`, `AuthenticatedUser`, roles) so handlers and permission checks stay strategy-agnostic. The middleware yields to any strategy that already authenticated the request.
- **Sliding sessions**: sessions are re-saved with fresh options on GET requests when `SITE_SESSION_RESAVE` is enabled, extending `SITE_SESSION_MAX_AGE` on activity.
- **Bcrypt (default cost) with passwords in a dedicated `passwords` table**, joined to `users` by username **or** e-mail — the login identifier accepts both.
- **One-time reset tokens** in the `authtokens` table: 35-character random tokens, `isValid` flag, hard delete (`Unscoped`) on use, and configurable reset-page prefixes (`ResetPrefixNames`) so host apps can point the e-mail link to their own frontends.
- **Anti-enumeration on forgot-password**: unknown e-mails get the same generic success response in JSON mode; only the e-mail delivery reveals account existence.
- **Dual logout**: the cookie-session logout (`/logout`) and the API logout (`/auth/logout`) which also revokes OAuth2 access/refresh tokens (glue with [../oauth2-password/guide.md](../oauth2-password/guide.md)); token revocation failures never fail the logout response.
- **Flash messages for HTML flows, response messages for JSON flows**; the `http-error` event converts `bolo.HTTPError` and validation errors into flash messages so HTML pages can render them.
- **Reusable security primitives**: `LoginThrottle` (per IP+user Redis counters with TTL) and `ReCAPTCHA` (v2/v3 with score/action/hostname checks) exposed as a package, with interfaces (`netClient`, `clock`, `LoginThrottleInterface`, `DBRedisInterface`) designed for test doubles.
- **Backwards compatibility**: We.js-compatible route `POST /auth/:userID/new-password` and the legacy `redistore` close path are kept.
- **E-mail decoupling**: templates are registered at bootstrap and consumed through the `emails` plugin (`QueueToSend`/`SendEmailAsync`), keeping auth handlers free of transport concerns.

## Assumptions & open items

Code-supported observations that need human review:

1. **`migrations/auth/` is empty.** The feature's tables (`users`, `passwords`, `authtokens`) are created by `migrations/user/00001_init.go` via `UserPlugin.GetMigrations()`. The empty `migrations/auth/` directory looks like a leftover; its intended purpose is unclear. The `passwords` migration creates an `active` column that the Go model does not map.
2. **`LoginThrottle` is not integrated with login.** No handler in this module calls `CanLogin`/`OnLoginFail`/`OnLoginSuccess` — only tests do. The intended integration point (password login? OAuth2 password grant?) is undocumented.
3. **`ReCAPTCHA` is not integrated either**, and `security/recaptcha_test.go` is entirely commented out, so the client is untested as shipped.
4. **`SessionDBReader` is created but unused** in this module's request path; the session store is built exclusively on `SessionDBWriter`. Reads/writes go through one client despite the writer/reader configuration.
5. **Throttle quirks**: `SetAccessRegistry` writes through the *reader* client and swallows write errors (returns `nil`); the first `OnLoginFail` stores `Count = 0` (the counter effectively starts on the second failure); a denied `CanLogin` also increments the counter.
6. **`remember_me` is accepted but unused** by `SessionController.Login` — all sessions get the same `SITE_SESSION_MAX_AGE`.
7. **Signup has no route.** `AuthController.Signup` (creates users with `Active = false` and username validation `^[A-Za-z0-9_-]{2,30}$`) is not registered in `BindRoutes`; `AuthController_test.go` invokes the controller method directly against `POST /auth/signup`. `Activate` and the other stub handlers (`ForgotPasswordRequest`, `CheckIfResetPasswordTokenIsValid`, `ForgotPasswordUpdate`, `UpdatePassword`) return `501 not implemented` and are routed nowhere.
8. **`POST /auth/:userID/forgot-password/reset` does not reset the password.** It only validates user + token and binds a body whose shape (`ForgotPasswordChange_RequestBody` with required `email`) looks wrong for a reset page; the actual change happens in `/api/v2/auth/forgot-password/process`. This looks like an incomplete step-2 implementation.
9. **Misleading internal error text**: in change-own-password, the `422 invalid password` branch that triggers when the current password is empty but a password record *exists* logs internal message "password record not found". Observable behavior (422) is documented; the internal message is inconsistent.
10. **`/auth/current` for anonymous users returns `{}`** (empty map), not a user-shaped object — clients must handle both shapes (confirmed by tests asserting body `{}\n`).
11. **`OnClose` closes only legacy `redistore.RediStore`**; the active `redisstore/v9` store is not closed on shutdown.
12. **`AccontActivationEmail`** template name contains a typo and is kept as-is; any consumer must reference the misspelled name.
13. **Login error specialization**: `ValidUsernamePassword` surfaces `bcrypt.ErrMismatchedHashAndPassword`, which `Login` maps to a generic wrong-credentials flash; the distinction exists mainly to separate "user/password record not found" from mismatched hash.
14. **Forgot-password step 1 looks up users by username OR e-mail** (`UserFindOneByUsername`), but the field is validated as an e-mail format — users whose username is not an e-mail can only be found if their username string coincidentally matches; behavior for username-only login on this endpoint is untested.
15. **`SITE_SESSION_ADDR_WRITER`/`READER` have no defaults** — an unset value produces a Redis client with an empty address; failure mode at runtime is untested in this module.
