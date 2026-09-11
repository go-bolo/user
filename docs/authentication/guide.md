---
id: authentication
title: Authentication — password login, sessions, password recovery and account security
status: draft
created_at: 2026-09-11
updated_at: 2026-09-11
owner: TBD
affected_areas: [backend, http-api]
tags: [authentication, login, sessions, password-reset, throttling, recaptcha, redis, email, backend, http-api]
---

# Authentication — password login, sessions, password recovery and account security

## Description

The `authentication` feature is provided by the `auth` plugin (`user.NewAuthPlugin`, plugin name `"auth"`) of the `github.com/go-bolo/user` module. It bundles the classic account-security building blocks of a Bolo application:

- **Password login/logout** with HTML pages and redirects (`/login`, `/logout`, `SessionController`) and a JSON-friendly logout API (`/auth/logout`, `AuthController`) that also revokes OAuth2 tokens (see [oauth2-password](../oauth2-password/guide.md)).
- **Redis-backed session authentication**: a global Echo middleware loads the `uid` stored in the `session` cookie, resolves the `UserModel`, and fills `RequestContext.IsAuthenticated`, `RequestContext.AuthenticatedUser` and the user roles used by permission checks.
- **Password management**: change own password (HTML + `/api/v2` JSON), admin "set password" for a user (guarded by the `manage_users` permission), and a three-step forgot-password flow based on one-time `authtokens` records.
- **Security helpers** (package `user/security`): a Redis-backed login throttle (`LoginThrottle`) and a Google reCAPTCHA v2/v3 verification client (`ReCAPTCHA`).
- **Auth email templates** (`email-templates.go`): account activation, reset password and change password notifications registered in the `emails` plugin at bootstrap.

The plugin also registers the route for Facebook app-code login (`POST /auth/facebook/app-login-code`), whose internals belong to the [facebook-auth](../facebook-auth/guide.md) feature.

## How to use

- Register the plugin in the Bolo app (as done in `setup_test.go`):

  ```go
  app.RegisterPlugin(user.NewAuthPlugin(&user.AuthPluginCfgs{
      ResetPrefixNames: map[string]string{ /* optional custom reset page prefixes */ },
  }))
  ```

- Point the session Redis at `SITE_SESSION_ADDR_WRITER` / `SITE_SESSION_ADDR_READER` (and optionally `SITE_SESSION_PASSWORD`, `SITE_CACHE_DB`). The plugin creates the session store on the `bindMiddlewares` event and installs `session.Middleware` plus the session authentication middleware globally.
- Log a user in by posting `email` (username or e-mail), `password` and optional `remember_me` to `/login`; on success a Redis-backed `session` cookie holding `uid` is set and the user is redirected to `/`.
- Log out with `GET/POST /logout` (cookie-session only) or `POST /auth/logout` (optionally sending `Authorization: Bearer <access token>` and/or `X-Refresh-Token: <refresh token>` to also revoke OAuth2 tokens).
- Recover a password: `GET/POST /auth/forgot-password` (step 1, sends the `AuthResetPasswordEmail` with a reset URL), open `/auth/:userID/forgot-password/reset?t=<token>` (step 2, validates the token), then `POST /api/v2/auth/forgot-password/process` (step 3, sets the new password and consumes the token).
- Change the own password via `/auth/change-password` (HTML) or `POST /api/v2/auth/change-password` (JSON, requires an authenticated user).
- Use `user/security` building blocks from host applications:

  ```go
  throttle := security.NewLoginThrottle(app)
  if ok, _ := throttle.CanLogin(userID, c); ok { /* allow attempt */ }

  captcha, _ := security.NewReCAPTCHA(secret, security.V3, 10*time.Second)
  err := captcha.VerifyWithOptions(response, security.VerifyOption{Action: "login", RemoteIP: c.RealIP()})
  ```

  Note: inside this module these helpers are not yet wired into any HTTP handler; they are exercised only by their unit tests.

## Goals

- Authenticate requests coming from browser cookie sessions and expose the authenticated user/roles to the whole request pipeline.
- Provide password login/logout endpoints compatible with both HTML form flows and JSON clients.
- Provide safe, single-use password recovery using one-time tokens stored in the `authtokens` table.
- Notify users by e-mail on password changes and reset requests, using templates registered in the `emails` plugin.
- Offer reusable primitives (login throttling, reCAPTCHA verification) to harden login flows.
- Keep compatibility with legacy We.js clients (e.g. `POST /auth/:userID/new-password`).

## Affected areas

- **backend**: `AuthPlugin`, `AuthController`, `SessionController`, `auth_session.go`/`session.go`, `middlewares.go`, `handlers.go` (user settings JSON glue), `models/PasswordModel.go`, `models/AuthTokenModel.go`, `security/loginThrottle.go`, `security/recaptcha.go`, `email-templates.go`, `install.go`, `flash.go`.
- **http-api**: routes under `/login`, `/logout`, `/auth/*` and `/api/v2/auth/*` (see the API contract in [spec.md](./spec.md)); global session middleware applied to every route.
- **data**: `passwords`, `authtokens` tables (created by the module init migration); Redis keys for sessions and login-throttle counters.

## Tags

[authentication, login, sessions, password-reset, throttling, recaptcha, redis, email, backend, http-api]

## Links

- Feature spec: [spec.md](./spec.md)
- Changelog: [changelog.md](./changelog.md)
- OAuth2 password grant (token login used by SPAs/tests): [../oauth2-password/guide.md](../oauth2-password/guide.md)
- OAuth2 JWT: [../oauth2-jwt/guide.md](../oauth2-jwt/guide.md)
- Facebook authentication (route registered here, details there): [../facebook-auth/guide.md](../facebook-auth/guide.md)
- Sessions deep-dive: [../sessions/guide.md](../sessions/guide.md)
- Users feature (user model, CRUD, `/user-settings`): [../user-management/guide.md](../user-management/guide.md)
- Module README: [../../README.md](../../README.md)
