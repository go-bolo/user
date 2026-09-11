---
id: sessions-spec
title: Sessions — specification
status: draft
created_at: 2026-09-11
updated_at: 2026-09-11
owner: TBD
affected_areas: [backend, http-api]
tags: [sessions, redis, cookies, authentication, flash-messages, http]
---

# Sessions — specification

## Overview & architecture

The feature is composed of four parts, all in the root package `user` (plus one helper package):

1. **Redis clients and one-shot initialization** — `session.go`
   - `SessionDBWriter *redis.Client` and `SessionDBReader *redis.Client` are package-level clients created by `initRedisSession()`. The function is guarded by the `sessionInitialized` flag and only creates a client when the variable is still `nil` (which also allows tests to pre-inject mocks).
   - `Init(app)` (declared in `auth_session.go`) calls `initRedisSession()`; `AuthPlugin.Init` hooks it to the app `configuration` event.
2. **Session store and middleware wiring** — `AuthPlugin.bindMiddlewares`
   - A `redisstore` (`github.com/rbcervilla/redisstore/v9`) is created from `SessionDBWriter` and installed with `router.Use(session.Middleware(p.SessionStore))` (`github.com/labstack/echo-contrib/session`).
   - Right after it, `sessionAuthenticationMiddleware()` is installed; it skips public routes (`/health*`, `/public*`) and delegates to `HandleRequestSessionAuthentication`. That handler belongs to the `authentication` feature (see `../authentication/guide.md`) and reads the session to authenticate the request.
   - `p.SessionResave` is loaded from `SITE_SESSION_RESAVE` (default `true`); when enabled, the session is re-saved on authenticated `GET` requests.
3. **HTTP endpoints** — `SessionController` (`SessionController.go`), registered by `AuthPlugin.BindRoutes` on the main router.
4. **Flash messages** — `flash.go` plus the `renderFlashMessages` template function (`func-maps.go`, registered in `AuthPlugin.setTemplateFunctions` as `renderFlashMessages`).

Session values use gorilla's `sessions.Session` (`github.com/gorilla/sessions`) obtained through `session.Get("session", c)`. All call sites tolerate the `"session store not found"` error string where noted (login/logout helpers keep going with a zero-value session in that case; flash helpers return the error).

Dependencies (from `go.mod`): `github.com/redis/go-redis/v9` (Redis client), `github.com/rbcervilla/redisstore/v9` (gorilla-compatible Redis session store), `github.com/gorilla/sessions` (session types/flashes), `github.com/labstack/echo-contrib` (echo session middleware), `gopkg.in/boj/redistore.v1` (legacy import, only used for a type assertion in `OnClose`), and `github.com/alicebob/miniredis/v2` + `github.com/go-redis/redismock/v9` (tests).

## API contract

Routes registered by `AuthPlugin.BindRoutes` (main router, no route permission attached):

| Method | Path    | Handler                       | Auth / Permission                                                                                                                       |
| ------ | ------- | ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/login`  | `SessionController.LoginPage` | Public; redirects (307) to `/` when already authenticated. Renders `auth/login` template with the status previously set in the context (default 200). |
| POST   | `/login`  | `SessionController.Login`     | Public; redirects (307) to `/` when already authenticated. Body: `LoginRequestBody`. Success redirects (302) to `/`. Failures re-render the login page with HTTP 400 plus an error flash message. |
| GET    | `/logout` | `SessionController.Logout`    | Public. Deletes the session and redirects (307) to `/`.                                                                                  |
| POST   | `/logout` | `SessionController.Logout`    | Public. Same behavior as `GET /logout`.                                                                                                  |

Request body (`LoginRequestBody`, binds JSON or form):

| Field         | Type    | Validation            | Observed behavior                                                                                     |
| ------------- | ------- | --------------------- | ----------------------------------------------------------------------------------------------------- |
| `email`       | string  | `validate:"required"` | Used as username for `ValidUsernamePassword` and `UserFindOneByUsername`.                              |
| `password`    | string  | `validate:"required"` | Checked with `ValidUsernamePassword` (bcrypt).                                                         |
| `remember_me` | bool    | —                     | Bound (`json`/`form`) but not referenced by the login logic in the current code.                        |

Error flashes produced by `POST /login`:

| Condition                                             | Flash message (Type `error`)                                | Response                          |
| ----------------------------------------------------- | ----------------------------------------------------------- | --------------------------------- |
| bcrypt mismatch (`bcrypt.ErrMismatchedHashAndPassword`) | `Email ou senha incorretos.`                                  | Login page, status 400             |
| user/password record not found (`gorm.ErrRecordNotFound`) | `Usuário não encontrado ou não possuí senha cadastrada.`      | Login page, status 400             |
| `ValidUsernamePassword` returns `valid == false`        | `Erro ao validar a senha.`                                    | Login page, status 400             |
| Any other validation error                              | Returned by `c.Validate` (converted to flashes by `OnHTTPError` for `validator.ValidationErrors`) | per validator |

`Logout` adds the flash `Error on delete session.` (Type `error`) when `DeleteUserSession` fails.

Global error-to-flash mapping (`AuthPlugin.OnHTTPError`, `http-error` event): every `*bolo.HTTPError` becomes one `error` flash with the error message; every `validator.ValidationErrors` becomes one `error` flash per validation error with `Field` and `Tag` filled.

## Data models

- `LoginRequestBody` (`SessionController.go`)
  - `Email string` (`json:"email"`, `form:"email"`, required)
  - `Password string` (`json:"password"`, `form:"password"`, required)
  - `RememberMe bool` (`json:"remember_me"`, `form:"remember_me"`)
- `FlashMessage` (`flash.go`)
  - `Type string` (`json:"type"`) — e.g. `"error"`
  - `Message string` (`json:"message"`)
  - `Field string` (`json:"field"`) — filled by validation-error flashes
  - `Tag string` (`json:"tag"`) — filled by validation-error flashes
  - `ToJSON() []byte` marshals the struct (marshal errors ignored).
- `FlashMessages []*FlashMessage` — slice type returned by `GetFlashMessages`.
- `SessionData` (`auth_session.go`) — `UserID string` (`json:"userId"`); declared alongside the session code but not referenced elsewhere in this module.
- Session contents
  - Cookie/session name: `"session"` (used in every `session.Get("session", c)` call; `sessionAuthenticationHandler` also manipulates the `session` cookie directly).
  - `sess.Values["uid"]` — set to `user.GetID()` by `SetUserSession`; read back as `string` by `sessionAuthenticationHandler`. `DeleteUserSession` sets it to the integer `0` while expiring the cookie.
  - Flash bucket: `"messages"` — `AddFlashMessage` appends the `FlashMessage` JSON bytes; `GetFlashMessages` drains them (gorilla flashes are one-shot; `GetFlashMessages` saves the session after draining).
- Plugin state (`AuthPlugin`)
  - `SessionStore sessions.Store` — the `redisstore` instance.
  - `SessionResave bool` — from `SITE_SESSION_RESAVE`.
- Package state (`session.go`)
  - `SessionDBWriter` / `SessionDBReader` `*redis.Client` — both configured with the same DB index and password, different addresses.
  - `sessionInitialized bool` — makes `initRedisSession` idempotent.

## Flows

**Login (POST /login)**

1. `SessionController.Login` casts the context to `*bolo.RequestContext`; if `ctx.IsAuthenticated` it redirects (307) to `/`.
2. Binds `LoginRequestBody` (bind error → 404 No Content) and validates (validation errors are returned; `OnHTTPError` converts them into flashes).
3. `user_models.ValidUsernamePassword(email, password)` checks the password record (bcrypt). Failures map to specific error flash messages and re-render the login page with status 400 (see API contract).
4. On success, `UserFindOneByUsername(email, &userRecord)` loads the user and `SetUserSession(ctx.App, c, &userRecord)`:
   - `session.Get("session", c)`; a `"session store not found"` error is tolerated (session proceeds with the returned value).
   - `sess.Options` is replaced with `user_helpers.GetSessionOptions(app)`.
   - `sess.Values["uid"] = user.GetID()`; `sess.Save` persists the session through the Redis store (a `Set-Cookie` for `session` is emitted).
5. Redirect (302) to `/`.

**Logout (GET/POST /logout)**

1. `SessionController.Logout` calls `DeleteUserSession(c)`: `session.Get("session", c)` (store-not-found tolerated), `sess.Values["uid"] = 0`, `sess.Options.MaxAge = -1`, `sess.Save` (expires the session cookie).
2. On error, an `error` flash `Error on delete session.` is added.
3. Redirect (307) to `/`.

**Request authentication via session** (owned by the `authentication` feature — summary here for context, details in `../authentication/guide.md`)

1. `sessionAuthenticationMiddleware` skips `/health*` and `/public*` paths and calls `HandleRequestSessionAuthentication`.
2. `sessionAuthenticationHandler` gets the `session`, forces `sess.Options.Secure = true` when `ctx.ENV == "production"`, reads `uid` as string, loads the user with `UserFindOne`, and sets `ctx.AuthenticatedUser`, `ctx.Session.UserID` and `ctx.IsAuthenticated`.
3. If `uid` is absent but a `session` cookie is still present, the cookie is expired client-side (`Expires` set in the past).
4. If `AuthPlugin.SessionResave` is enabled and the request is `GET`, session options are refreshed via `GetSessionOptions` and the session is re-saved (sliding expiry).

**Flash messages**

1. Write: `AddFlashMessage` gets the session, appends `m.ToJSON()` to the `"messages"` flash bucket and saves.
2. Consume: `GetFlashMessages` drains the `"messages"` bucket, saves the session when messages were found (which is what makes them one-shot) and unmarshals each entry into a `FlashMessage` (unmarshal errors ignored).
3. Render: the `renderFlashMessages` template function (registered by `AuthPlugin.setTemplateFunctions`) calls `GetFlashMessages` and renders each message with the `blocks/notifications/flash-message` template; per-message render errors are logged, not returned.
4. Automatic errors: `AuthPlugin.OnHTTPError` turns `*bolo.HTTPError` and `validator.ValidationErrors` into error flashes during the `http-error` event.

**Initialization & shutdown**

1. `configuration` event → `Init(app)` → `initRedisSession()` creates both Redis clients (idempotent).
2. `bindMiddlewares` event → creates the `redisstore` from `SessionDBWriter`, loads `SITE_SESSION_RESAVE`, installs `session.Middleware` and `sessionAuthenticationMiddleware` (`log.Fatal` if the store cannot be created).
3. `close` event → `AuthPlugin.OnClose` closes the store only when it is a `*redistore.RediStore` (see Assumptions & open items — the created store is of a different type).

## Configuration

All values are read from the app configuration (environment). Redis connection settings come from `initRedisSession` (`session.go`); cookie options come from `GetSessionOptions` (`helpers/session_helpers.go`) and `bindMiddlewares` (`AuthPlugin.go`). The module `README.md` does not document session variables (it only lists Facebook OAuth settings).

| Key                       | Type   | Default            | Description                                                                                  |
| ------------------------- | ------ | ------------------ | -------------------------------------------------------------------------------------------- |
| `SITE_SESSION_ADDR_WRITER` | string | none (`cfgs.Get`)  | Redis address used by `SessionDBWriter` (the client backing the session store). Example: `localhost:6379`. |
| `SITE_SESSION_ADDR_READER` | string | none (`cfgs.Get`)  | Redis address used by `SessionDBReader`.                                                     |
| `SITE_SESSION_PASSWORD`    | string | `""`               | Password for both Redis clients.                                                              |
| `SITE_CACHE_DB`            | int    | `2`                | Redis DB index used by both clients.                                                          |
| `SITE_SESSION_RESAVE`      | bool   | `true`             | When true, re-save the session on authenticated `GET` requests (sliding expiry).               |
| `SITE_SESSION_PATH`        | string | `/`                | Session cookie `Path`.                                                                        |
| `SITE_SESSION_MAX_AGE`     | int    | `604800` (7 days)  | Session cookie `MaxAge` (seconds).                                                            |
| `SITE_SESSION_HTTP_ONLY`   | bool   | `false`            | Session cookie `HttpOnly` flag.                                                               |

Additional cookie behavior from code: `Secure` is forced to `true` in production by `sessionAuthenticationHandler` (see `../authentication/guide.md`); the cookie name is `session`.

Testing configuration: `setup_test.go` starts a `miniredis` server for the TestMain process (used by the OAuth2 storage via `SITE_OAUTH2_ADDR_WRITER`/`SITE_OAUTH2_ADDR_READER`) and the session-specific tests replace `user.SessionDBWriter`/`user.SessionDBReader` with miniredis-backed clients before app bootstrap; `redismock` is referenced but currently commented out.

## Design decisions

- **Redis as the session backend with gorilla compatibility**: the store is `rbcervilla/redisstore` (a gorilla `sessions.Store`), accessed through the standard `echo-contrib/session` middleware, keeping handlers store-agnostic (they only use `session.Get("session", c)`).
- **Separate writer/reader Redis clients**: `SessionDBWriter` and `SessionDBReader` allow pointing reads and writes at different Redis addresses (e.g. replicas). The store itself is built from the writer client.
- **Idempotent, overridable initialization**: `initRedisSession` is guarded by `sessionInitialized` and skips clients that are already non-`nil`, enabling tests to inject miniredis-backed clients.
- **Tolerating a missing store**: login/logout/flash helpers only fail on a `session.Get` error when the message does not contain `"session store not found"`; in that specific case they continue with the returned (zero-value) session instead of erroring out.
- **Flash payloads as JSON bytes in a named bucket**: messages are serialized with `ToJSON` and stored in the `"messages"` bucket, decoupling consumers from the in-session representation and allowing structured fields (`Field`, `Tag`).
- **One-shot semantics via save-after-drain**: `GetFlashMessages` saves the session when it finds flashes, which removes them from the store (gorilla flash behavior) — each message is rendered at most once.
- **Single template function for rendering**: `renderFlashMessages` is registered globally, so any template can render pending flashes through `blocks/notifications/flash-message`.
- **Errors become flashes centrally**: `AuthPlugin.OnHTTPError` maps framework HTTP errors and validation errors to error flashes, so HTML flows can display them after the next render without extra handler code.
- **Sliding session expiry (opt-out)**: with `SITE_SESSION_RESAVE=true` (default), authenticated `GET` requests re-save the session, refreshing its lifetime.

## Assumptions & open items

- **Reader client currently unused in this module**: `SessionDBReader` is created (and overridden in tests) but no code path in this module uses it — the `redisstore` is created exclusively from `SessionDBWriter`. Intent (per comments) is a read/write split; how reads should use the reader is not implemented here.
- **`SITE_SESSION_ADDR_WRITER` / `SITE_SESSION_ADDR_READER` have no default**: both are read with `cfgs.Get` (not `GetF`), so an unset variable produces a client with an empty address. Runtime behavior in that case is not covered by code or tests in this module.
- **`OnClose` type mismatch**: `AuthPlugin.OnClose` only closes `*redistore.RediStore` (`gopkg.in/boj/redistore.v1`), but `bindMiddlewares` creates a `*redisstore.RedisStore` (`rbcervilla/redisstore/v9`). As written, the close branch never matches and the active store is never closed.
- **`RememberMe` is dead input**: `LoginRequestBody.RememberMe` is bound but never read by `Login`; there is no "remember me" specific MaxAge handling in this module.
- **`uid` type asymmetry**: `SetUserSession` stores `user.GetID()` (read back as `string` by `sessionAuthenticationHandler`), while `DeleteUserSession` assigns the integer `0`. The delete path is protected by `MaxAge = -1`, but the literal type differs from what the reader expects.
- **Errors ignored in flash helpers**: `ToJSON` ignores marshal errors and `GetFlashMessages` ignores `json.Unmarshal` errors (a failed entry would yield a zero-value `FlashMessage`). `GetFlashMessages` also ignores the `sess.Save` error after draining.
- **`SessionData` struct is unreferenced**: `SessionData`/`ToJSON` in `auth_session.go` are declared but not used anywhere in this module.
- **`errors/session.go` is empty**: the file declares an empty var block; no session-specific error types exist.
- **Store-not-found tolerance is string-based**: helpers decide by matching the substring `"session store not found"` in the error message, which is fragile if the upstream middleware wording changes.
- **Tests cover session clients only indirectly**: tests inject miniredis-backed clients and exercise flows through HTTP endpoints (`AuthController_test.go`); there are no dedicated unit tests for `flash.go` or `SessionController` in this module.
- **Login/logout responses are redirects/HTML pages** (not JSON): consistent with the browser flow, but unverified against frontend expectations in this module.
