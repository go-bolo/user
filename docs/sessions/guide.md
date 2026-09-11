---
id: sessions
title: Sessions (Redis-backed store, login/logout endpoints and flash messages)
status: draft
created_at: 2026-09-11
updated_at: 2026-09-11
owner: TBD
affected_areas: [backend, http-api]
tags: [sessions, redis, cookies, authentication, flash-messages, http]
---

# Sessions

## Description

The `sessions` feature of the `github.com/go-bolo/user` plugin implements:

- **Redis-backed session storage**: two package-level Redis clients (`SessionDBWriter` and `SessionDBReader`) are created once (`initRedisSession`) and a `redisstore` (gorilla-compatible, from `github.com/rbcervilla/redisstore/v9`) is built on top of the writer client. The store is installed on the main Echo router through `echo-contrib/session` middleware, so every request has a `session` named session available.
- **Session lifecycle helpers**: `SetUserSession` writes the authenticated user id (`uid`) into the session with the options produced by `user_helpers.GetSessionOptions`, and `DeleteUserSession` zeroes `uid` and expires the session cookie (`MaxAge = -1`).
- **HTTP endpoints for browser login/logout**: `SessionController` registers `GET/POST /login` and `GET/POST /logout` on the main router (no permission attached).
- **Flash messages**: `FlashMessage` records (`type`, `message`, `field`, `tag`) are stored as JSON inside the session's `messages` flash bucket via `AddFlashMessage` and consumed with `GetFlashMessages`. The `renderFlashMessages` template function renders them with the `blocks/notifications/flash-message` template.

Session-based request authentication (reading `uid` back from the session on every request) is implemented by `auth_session.go` / `middlewares.go` and is documented in the authentication feature: see `../authentication/guide.md`.

## How to use

- **Log in (browser flow)**: `POST /login` with form or JSON body `{"email": "...", "password": "...", "remember_me": false}`. On success the user id is stored in the Redis session and the browser is redirected to `/`. On failure an error flash message is added and the login page is re-rendered with HTTP 400.
- **Log out**: `GET /logout` or `POST /logout` deletes the session (`uid = 0`, cookie expired) and redirects to `/`.
- **Login page**: `GET /login` renders the `auth/login` template; authenticated users are redirected to `/`.
- **Add a flash message (Go code)**: call `AddFlashMessage(c, &user.FlashMessage{Type: "error", Message: "..."})` inside any handler. The message is saved in the session and consumed on the next render.
- **Read flash messages (Go code)**: call `GetFlashMessages(c)`; it drains and returns the `messages` flash bucket as `[]*FlashMessage`.
- **Render flash messages (templates)**: templates can call the registered `renderFlashMessages` function, which renders each pending flash with the `blocks/notifications/flash-message` template.
- **Testing**: tests inject a `miniredis`-backed `*redis.Client` into `user.SessionDBWriter` / `user.SessionDBReader` before app bootstrap (see `setup_test.go` and `AuthController_test.go`).

## Goals

- Provide durable, Redis-backed server-side sessions for browser authentication.
- Keep cookie/session options centralized and configurable via `SITE_SESSION_*` environment variables.
- Offer simple login/logout endpoints for the classic (cookie/session) authentication flow.
- Provide a session-persisted one-shot messaging mechanism (flash messages) for form feedback and error rendering.

## Affected areas

- `backend`: session store initialization (`session.go`), plugin wiring (`AuthPlugin.go`: `bindMiddlewares`, `OnHTTPError`, `OnClose`, `setTemplateFunctions`), session helpers (`helpers/session_helpers.go`).
- `http-api`: `GET/POST /login`, `GET/POST /logout` endpoints (`SessionController.go`).

## Tags

`sessions`, `redis`, `cookies`, `authentication`, `flash-messages`, `http`

## Links

- Spec: [spec.md](./spec.md)
- Changelog: [changelog.md](./changelog.md)
- Related feature (session authentication handler, middleware, `/auth/logout`): [../authentication/guide.md](../authentication/guide.md)
