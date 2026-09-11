---
id: user-management
title: User Management
status: draft
created_at: 2026-09-11
updated_at: 2026-09-11
owner: TBD
affected_areas: [backend, http-api]
tags: [users, acl, rest-api, permissions, gorm]
---

# User Management

## Description

The user-management feature is the core `user` plugin (`UserPlugin`, registered with the name `"user"`) of the `github.com/go-bolo/user` module. It owns:

- The default user model (`user_models.UserModel`, table `users`) with roles stored as a JSON text column, plus a public projection type (`user_models.UserModelPublic`).
- A REST resource for users under `/api/user` (list, count, create, find one, update, delete), registered through the Bolo framework's `SetResource`.
- Two ACL administration endpoints under `/acl`: read the application roles/permissions list and replace a user's roles.
- The registration of the `GET /user-settings` endpoint, which returns client bootstrap configuration for the SPA (handler implementation lives in `handlers.go`, documented by the authentication feature).
- The `renderClientAppConfigs` template function, which injects a `window.CATUPIRI_BOOTSTRAP_CONFIG` JSON script with app metadata, pager limits, locales, plugin names, the authenticated user and the authenticated roles.
- The `renderFlashMessages` template helper implementation (registered as a template function by the auth plugin) that renders session flash messages as the `blocks/notifications/flash-message` template.
- Small helpers: username validation regex (`user_helpers.ValidateUsername`) and session cookie options (`user_helpers.GetSessionOptions`).
- The `"init"` database migration that creates the `users`, `passwords` and `authtokens` tables.
- The install hook (`InstallAuth`) that creates a default `AuthChangePasswordEmail` email template record.
- Password validation primitives used by login flows (`user_models.ValidUsernamePassword`) and bcrypt-based password verification/update on `UserModel`.

Authentication itself (login, signup, logout, password reset flows, OAuth2, sessions and the request authentication middleware in `handlers.go`/`middlewares.go`) is documented separately by the authentication feature.

## How to use

### Register the plugin

```go
app.RegisterPlugin(user.NewUserPlugin(&user.UserPluginCfg{}))
```

During `Init` the plugin creates its `Controller` and subscribes to the framework events `bindRoutes` and `setTemplateFunctions`. `GetMigrations()` returns the `"init"` migration, which is executed by the framework's migration runner.

Routes registered by `BindRoutes`:

- `GET /user-settings` (`UserSettingsHandler`, see ../authentication/guide.md for handler details).
- Group `/acl`: `GET /acl/permission` and `POST /acl/user/:userID/roles`.
- Resource group `/api/user` via `app.SetResource("user", ctl, routerUser)`.

### Roles and permissions

Permission enforcement is done inside the handlers via `ctx.Can(permission)`, which resolves against the application role list (`App.RolesList`) configured by the host app. The permissions used by this feature are:

| Permission | Enforced in |
| ---------- | ----------- |
| `create_user` | `POST /api/user` |
| `find_user` | `GET /api/user`, `GET /api/user/count`, `GET /api/user/:id` (and page variants) |
| `update_user` | `POST|PATCH|PUT /api/user/:id` |
| `delete_user` | `DELETE /api/user/:id` |
| `manage_users` | `POST /acl/user/:userID/roles` |

The Bolo framework grants every permission to the `"administrator"` role. Additionally, on find/update/delete, if the authenticated user is the record itself, the `"owner"` role is appended to the request roles before the permission check.

### Example API calls

```bash
# List users (paginated, searchable)
curl "http://localhost:8080/api/user?limit=20&page=1&q=alberto"

# Get one user
curl "http://localhost:8080/api/user/42"

# Create a user (username is forced to a new UUID)
curl -X POST http://localhost:8080/api/user \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"a@b.com","displayName":"Alberto"}}'

# Update (body is merged onto the stored record)
curl -X PATCH http://localhost:8080/api/user/42 \
  -H "Content-Type: application/json" \
  -d '{"user":{"biography":"new bio"}}'

# Replace a user's roles (admin operation)
curl -X POST http://localhost:8080/acl/user/42/roles \
  -H "Content-Type: application/json" \
  -d '{"userRoles":["authenticated","moderator"]}'

# Read the app roles/permissions map used by admin UIs
curl http://localhost:8080/acl/permission
```

### Template functions

- `renderClientAppConfigs` (registered by this plugin): render inside an HTML layout to emit `<script>window.CATUPIRI_BOOTSTRAP_CONFIG={...}</script>`.
- `renderFlashMessages` (implemented in this module, registered by the auth plugin): renders pending session flash messages; see ../authentication/guide.md.

### Tests

The test suite boots an in-memory Bolo app (SQLite via `DB_URI=file::memory:?cache=shared` and miniredis for OAuth2 storage) and registers the user, auth and OAuth2 password plugins. Run with:

```bash
go test ./...
```

## Goals

- Provide the default user record format and storage for every Bolo application.
- Expose a standard CRUD REST resource for user administration.
- Provide ACL administration endpoints (read roles/permissions map, set user roles).
- Enforce permissions per handler, granting self-access through the implicit `owner` role.
- Ship schema migrations (`users`, `passwords`, `authtokens`) and the default email template seed.
- Provide client bootstrap configuration (app metadata, locales, pager limits, authenticated user) to server-rendered pages and SPAs.

## Affected areas

- `backend`: `UserPlugin.go`, `Controller.go`, `install.go`, `models/`, `helpers/`, `errors/`, `migrations/user/`, `updates/`, `func-maps.go`, `template-func-maps.go`.
- `http-api`: `/api/user` resource, `/acl/permission`, `/acl/user/:userID/roles`, `GET /user-settings`.

## Tags

`users`, `acl`, `rest-api`, `permissions`, `gorm`

## Links

- ../authentication/guide.md — login/signup/logout, sessions, `handlers.go` (`UserSettingsHandler`), `middlewares.go` (session authentication middleware), password reset flows and email templates.
- OAuth2 password grant lives in this module too (`oauth2_password/`, `oauth2_jwt/`) and reuses `ValidUsernamePassword` and `UserFindOneByUsername`; see the authentication doc for the token endpoints.
- Framework primitives used here: `bolo.App.SetResource`, `bolo.RequestContext.Can`, query filter parsing (`github.com/go-bolo/query_parser_to_db`).
