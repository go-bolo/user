# go-bolo/user

Users, authentication, OAuth2 and sessions for [Go Bolo](https://github.com/go-bolo/bolo) applications.

[![Go version](https://img.shields.io/badge/go-1.23%2B-00ADD8)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## Overview

`user` is the official Go Bolo plugin for identity: it ships the default user
model, the user REST API, password authentication with Redis-backed sessions,
password recovery, Facebook login and an OAuth2 password grant with rotating
refresh tokens — plus an optional JWT subplugin for stateless access tokens.

## Features

- **User management** — default user model, REST API (`/api/user`), role-based
  permissions (`owner`, `manage_users`, …), install/migration routines and
  template helpers.
- **Authentication** — password login/logout, bcrypt credentials, auth
  sessions and tokens, forgot/reset/change-password flows with anti-enumeration
  responses, login throttling and reCAPTCHA helpers, auth email templates.
- **Sessions** — Redis-backed cookie sessions with sliding expiration and
  one-shot flash messages.
- **Facebook login** — OAuth code exchange for app clients
  (`POST /auth/facebook/app-login-code`).
- **OAuth2 password grant** — token issuance, single-use rotating refresh
  tokens with theft containment, and RFC 7009 revocation.
- **OAuth2 JWT** — optional stateless HS256 access tokens with the same
  refresh-token infrastructure.

## Requirements

- Go 1.23+
- [Go Bolo](https://github.com/go-bolo/bolo) v1.1.5+
- Redis (session store and OAuth2 token storage)

## Installation

```sh
go get github.com/go-bolo/user
```

## Quick start

Register the plugins with your Go Bolo app:

```go
import (
    "github.com/go-bolo/bolo"
    user "github.com/go-bolo/user"
    auth_oauth2_password "github.com/go-bolo/user/oauth2_password"
    // optional JWT subplugin:
    // auth_oauth2_jwt "github.com/go-bolo/user/oauth2_jwt"
)

app := bolo.Init(opts)

app.RegisterPlugin(user.NewUserPlugin(&user.UserPluginCfg{}))
app.RegisterPlugin(auth_oauth2_password.NewPlugin(&auth_oauth2_password.PluginCfgs{}))
app.RegisterPlugin(user.NewAuthPlugin(&user.AuthPluginCfgs{}))
// optional, requires OAUTH2_JWT_SECRET:
// app.RegisterPlugin(auth_oauth2_jwt.NewPlugin(&auth_oauth2_jwt.PluginCfgs{}))
```

The auth plugin also registers the `/login` and `/logout` HTML pages and
applies session + token authentication middleware to every request.

## Configuration

All settings come from environment variables.

### Facebook login

| Key | Type | Default | Description |
| --- | ---- | ------- | ----------- |
| `SITE_FACEBOOK_APP_ID` | string | `""` | Facebook app id |
| `FACEBOOK_CLIENT_SECRET` | string | `""` | Facebook app secret |
| `FACEBOOK_REDIRECT_URI` | string | `""` | Facebook redirect url |

The endpoint returns `404` when the app id or secret is unset.

### Sessions

| Key | Type | Default | Description |
| --- | ---- | ------- | ----------- |
| `SITE_SESSION_ADDR_WRITER` | string | `""` | Redis address for session writes |
| `SITE_SESSION_ADDR_READER` | string | `""` | Redis address for session reads |
| `SITE_SESSION_PASSWORD` | string | `""` | Redis password |
| `SITE_SESSION_RESAVE` | bool | `true` | Resave the session (sliding expiration) on authenticated GETs |

### OAuth2 tokens

| Key | Type | Default | Description |
| --- | ---- | ------- | ----------- |
| `OAUTH2_ACCESS_TOKEN_TTL` | duration | `30m` | Access token lifetime |
| `OAUTH2_REFRESH_IDLE_TTL` | duration | `72h` | Refresh token idle timeout |
| `OAUTH2_REFRESH_ABSOLUTE_TTL` | duration | `720h` | Refresh token family absolute cap |
| `OAUTH2_REFRESH_REUSE_GRACE` | duration | `30s` | Replay grace window for rotated refresh tokens |
| `OAUTH2_STRICT_401` | bool | `false` | Reject anonymous requests with `401` + `WWW-Authenticate` |

`OAUTH2_ACCESS_TOKEN_EXPIRATION` and `OAUTH2_REFRESH_TOKEN_EXPIRATION`
(seconds) are accepted as legacy fallbacks.

### JWT subplugin

| Key | Type | Default | Description |
| --- | ---- | ------- | ----------- |
| `OAUTH2_JWT_SECRET` | string | required | HS256 signing secret — the plugin fails to start without it |
| `OAUTH2_JWT_ISSUER` | string | `""` | `iss` claim |
| `OAUTH2_JWT_AUDIENCE` | string | `mm` | `aud` claim |
| `OAUTH2_JWT_TTL` | duration | `10m` | JWT lifetime |
| `OAUTH2_JWT_LEEWAY` | duration | `30s` | Clock-skew tolerance for `exp`/`nbf` |

## HTTP API

Key endpoints (see each feature's spec for the full contract):

| Endpoint | Description | Docs |
| -------- | ----------- | ---- |
| `GET/POST /login`, `GET/POST /logout` | HTML session login/logout | [sessions](docs/sessions/spec.md) |
| `GET /auth/current` | Current user (public shape or `{}`) | [authentication](docs/authentication/spec.md) |
| `POST /auth/logout` | Logout + best-effort token revocation | [authentication](docs/authentication/spec.md) |
| `GET/POST /auth/forgot-password`, `GET/POST /auth/:userID/forgot-password/reset`, `POST /api/v2/auth/forgot-password/process` | Password recovery (3 steps) | [authentication](docs/authentication/spec.md) |
| `POST /api/v2/auth/change-password` | Change own password (API) | [authentication](docs/authentication/spec.md) |
| `GET/POST /api/user`, `GET/POST/PATCH/PUT/DELETE /api/user/:id`, `GET /api/user/count` | User CRUD with permissions | [user-management](docs/user-management/spec.md) |
| `GET /acl/permission`, `POST /acl/user/:userID/roles` | Roles and permissions | [user-management](docs/user-management/spec.md) |
| `POST /auth/facebook/app-login-code` | Facebook app-code login | [facebook-auth](docs/facebook-auth/spec.md) |
| `POST /auth/grant-password/authenticate`, `POST /auth/grant-password/revoke` | OAuth2 password grant + revocation | [oauth2-password](docs/oauth2-password/spec.md) |
| `POST /auth/jwt/authenticate`, `POST /auth/jwt/refresh-token` | JWT login + refresh | [oauth2-jwt](docs/oauth2-jwt/spec.md) |

## Documentation

Feature documentation lives in [`docs/`](docs) — each feature has a guide,
spec and changelog:

- [User management](docs/user-management/guide.md)
- [Authentication](docs/authentication/guide.md)
- [Sessions](docs/sessions/guide.md)
- [Facebook auth](docs/facebook-auth/guide.md)
- [OAuth2 password grant](docs/oauth2-password/guide.md)
- [OAuth2 JWT](docs/oauth2-jwt/guide.md)

Note: `docs/` is excluded from the published Go module zip (via an empty
`docs/go.mod`), so read it in the repository.

## Development

```sh
go test ./...
```

Tests run against SQLite and an in-memory Redis (miniredis) — no external
services required.

## Contributing

Bug reports and pull requests are welcome on
[GitHub](https://github.com/go-bolo/user). For behavior changes, please open
an issue first and reference the relevant feature spec under `docs/`.

## License

[MIT](LICENSE)
