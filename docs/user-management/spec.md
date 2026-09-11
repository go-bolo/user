# User Management — Specification

## Overview & architecture

The feature is implemented inside the `user` package of `github.com/go-bolo/user` as a Bolo plugin.

```
UserPlugin (name "user")
├── Init(app)
│   ├── creates Controller (Controller.go)
│   ├── subscribes "bindRoutes"          → BindRoutes
│   └── subscribes "setTemplateFunctions"→ registers renderClientAppConfigs
├── BindRoutes(app)
│   ├── GET /user-settings               → UserSettingsHandler (handlers.go, see authentication doc)
│   ├── group /acl
│   │   ├── GET  /permission             → Controller.GetUserRolesAndPermissions
│   │   └── POST /user/:userID/roles     → Controller.UpdateUserRoles
│   └── SetResource("user", Controller, group /api/user)
│       ├── GET    ""                    → Query
│       ├── GET    /count                → Count
│       ├── POST   ""                    → Create
│       ├── GET    /:id                  → FindOne
│       ├── POST|PATCH|PUT /:id          → Update
│       └── DELETE /:id                  → Delete
├── GetMigrations() → migrations/user.GetInitMigration() ("init")
└── GetMigrations of updates/ package returns an empty list (see Assumptions)
```

Supporting pieces:

- `models/UserModel.go` — entity, persistence (`Save`, `Delete`), queries (`UserFindOne`, `UserFindOneByUsername`, `UsersQuery`, `LoadAllUsers`, `QueryAndCountFromRequest`, `CountQueryFromRequest`) and password primitives (`ValidPassword`, `SetPassword`).
- `models/UserModelPublic.go` — safe projection used by `/auth/current` (authentication feature).
- `models/ValidUsernamePassword.go` — username/email + bcrypt password check used by session login and the OAuth2 password grant.
- `install.go` — `InstallAuth` (triggered on the `"install"` event by the auth plugin) seeds a default `AuthChangePasswordEmail` email template record.
- `template-func-maps.go` — `renderClientAppConfigs`; `func-maps.go` — `renderFlashMessages` (registration happens in the auth plugin).
- `helpers/` — `ValidateUsername` regex and `GetSessionOptions` cookie options.
- `errors/session.go` — empty placeholder package (`var ()`).
- `updates/` — `GetMigrations()` returns an empty slice; `AddNewPasswordEmailTemplateChange` is a no-op migration variable that is not registered anywhere in this module.

All permission checks are executed inside the handlers (`ctx.Can(...)`) — the framework does not enforce route-level permissions (explicitly noted in the `UpdateUserRoles` comment as a privilege-escalation risk if left unchecked).

## API contract

Routes below are the actual registrations from `UserPlugin.BindRoutes` plus the generic resource routes created by `bolo.App.SetResource`. The framework content negotiation also exposes HTML page variants for find operations through `Controller.FindAllPageHandler` / `Controller.FindOnePageHandler`, but those handlers are not bound to any route inside this module (see Assumptions).

| Method | Path | Auth / permission |
| ------ | ---- | ----------------- |
| GET | `/user-settings` | No permission check in code; returns public app config plus authenticated user data/permissions when a session is authenticated. Handler defined in `handlers.go` (owned by the authentication doc). |
| GET | `/acl/permission` | No authentication or permission check in code. Returns the app `RolesList` map. |
| POST | `/acl/user/:userID/roles` | Requires authenticated request (401 otherwise) and `manage_users` permission (403 otherwise). 404 when the user does not exist. |
| GET | `/api/user` | No check in the controller; `QueryAndCountFromRequest` silently returns an empty list and count 0 when the caller lacks `find_user`. |
| GET | `/api/user/count` | Same silent `find_user` gate as the list endpoint. |
| POST | `/api/user` | Requires `create_user` (403 Forbidden otherwise). |
| GET | `/api/user/:id` | Appends the implicit `owner` role when the record is the authenticated user, then requires `find_user` (403). 404 when not found. Non-numeric `:id` returns the parse error. |
| POST | `/api/user/:id` | Same as PATCH/PUT (alias route). |
| PATCH | `/api/user/:id` | Appends implicit `owner` role for self, requires `update_user` (403). |
| PUT | `/api/user/:id` | Same as PATCH (alias route). |
| DELETE | `/api/user/:id` | Appends implicit `owner` role for self, requires `delete_user` (403). 404 JSON body when the record does not exist. |

Response envelopes (actual JSON shapes):

- List: `{"meta":{"count":N},"user":[UserModel...]}` (`ListJSONResponse`).
- Count: `{"count":N}` (`CountJSONResponse`).
- Find one / create (201) / update (200): `{"user":UserModel}` (`FindOneJSONResponse`).
- Delete: `204 No Content` with empty body.
- Update roles: `200` with `{}`.
- `GetUserRoles` exists on the controller but returns `501 Not implemented` and is not bound to any route.

Query parameters accepted by list/count:

- `q` — substring search on `displayName` OR `fullName` (`LIKE %q%`).
- `limit` — page size, clamped by the framework to `< PAGER_LIMIT_MAX`; default `PAGER_LIMIT` (20).
- `page` — page number; offset is computed as `limit * (page - 1)`.
- `order` / `sort` / `sortDirection` — parsed by `helpers.ParseUrlQueryOrder`; when no valid order is given the default is `createdAt DESC, id DESC`.
- Any query param mapped by the `filter:"param:...;type:..."` struct tags (e.g. `id`, `username`, `email`, `displayName`, `blocked`, `birthdate`, `phone`, `createdAt`, `updatedAt`) is converted into a SQL condition by the shared query parser.

## Data models

### `user_models.UserModel` (table `users`)

| Field | Column | Type / notes |
| ----- | ------ | ------------ |
| ID | `id` | uint64 primary key; JSON `id` |
| Username | `username` | unique; JSON `username` |
| Email | `email` | unique; JSON `email` (no format validation; `SetEmail` has a TODO) |
| DisplayName | `displayName` | longtext |
| FullName | `fullName` | longtext |
| Biography | `biography` | TEXT |
| Gender | `gender` | longtext |
| Active | `active` | bool; JSON `active` |
| Blocked | `blocked` | bool; JSON `blocked` |
| Language | `language` | longtext |
| ConfirmEmail | `confirmEmail` | longtext; JSON `confirmEmail` (serialized in API responses) |
| AcceptTerms | `acceptTerms` | bool |
| Birthdate | `birthdate` | longtext (string) |
| Phone | `phone` | longtext (string) |
| Roles | — | `gorm:"-"`; JSON `roles`; in-memory `[]string` |
| RolesText | `roles` | longtext; JSON-serialized role names; hidden from JSON |
| CreatedAt | `createdAt` | datetime(3); set on create |
| UpdatedAt | `updatedAt` | datetime(3); set from the app clock on every `Save` |

Behavior notes:

- `Save(ctx)` — sets `UpdatedAt` from `app.GetClock().Now()`; serializes `Roles` into `RolesText` when `len(Roles) > 0`; `INSERT` when `ID == 0` (with `CreatedAt` from a new global clock), full-row `Save` (update) otherwise.
- `Delete()` — hard delete (`Unscoped().Delete`); no-op when `ID == 0`.
- `GetRoles()` — lazily unmarshals `RolesText` into `Roles`.
- `SetRoles(v)` / `SetRole(role)` / `AddRole` / `RemoveRole` — mutate the role list; `SetRole`/`AddRole` only update the in-memory slice (`RolesText` is resynced on `Save`).
- `ValidPassword(password)` — loads the `PasswordModel` for the user id and compares bcrypt hashes; treats `bcrypt.ErrMismatchedHashAndPassword` as an invalid password instead of an error.
- `SetPassword(password)` — delegates to `UpdateUserPasswordByUserID`, which creates or updates the `passwords` row with a bcrypt hash (`bcrypt.DefaultCost`); empty passwords are rejected.
- String getters (`GetActiveString`, `GetBlockedString`, `GetCreatedAtString`, etc.) exist mainly for templates.

The raw `users` DDL in the `"init"` migration also defines `locationState varchar(10)`, `country varchar(5) DEFAULT 'BR'` and `city varchar(255)`, which are not present in the Go struct. The `users` DDL declares duplicated unique keys on `email` and `username`.

### `user_models.UserModelPublic` (table `users`, read-only projection)

Fields: `id`, `username`, `displayName`, `language`, `createdAt`, `updatedAt`. Built with `NewUserModelPublicFromUserModel`. Used by `GET /auth/current` (authentication feature) so public responses never expose email or roles.

### `user_models.PasswordModel` (table `passwords`)

`id`, `userId` (bigint), `password` (bcrypt hash text), timestamps. `FindPasswordByUsername` joins `users` and matches `username = ? OR email = ?`. `FindPasswordByUserID` ignores `gorm.ErrRecordNotFound` (caller checks `ID == 0`). Owned here because the `"init"` migration creates the table and `UserModel.ValidPassword/SetPassword` depend on it; the forgot/reset-password flows that consume it are documented in the authentication doc.

### `user_models.AuthTokenModel` (table `authtokens`)

`id`, `userId`, `providerUserId`, `tokenProviderId`, `tokenType`, `token` (random 35-char string generated on create when empty), `isValid`, `redirectUrl`, timestamps. Helpers: `ValidAuthToken`, `CreateAuthToken`, `FindOneAuthToken`, `FindInvalidOldUserTokens`, `GetResetUrl` (builds `/auth/:userID/forgot-password/reset?t=<token>&u=<userID>` by default). Table created by the `"init"` migration; the flows that issue/consume tokens belong to the authentication doc.

### `ValidUsernamePassword(username, password)`

Loads the password record via `FindPasswordByUsername` (username OR email match) and bcrypt-compares; returns `(false, nil)` on hash mismatch. Consumed by `SessionController.Login`, the OAuth2 password handlers, and duplicated as a wrapper in `oauth2_password`.

## Flows

### List / count users

1. `GET /api/user` → `Controller.Query` builds a `QueryAndCountFromRequestCfg` with the framework pager (`limit`, `offset`).
2. `QueryAndCountFromRequest` first checks `find_user`; without it, it returns `nil` (empty list, no error).
3. Applies model filter params, the `q` LIKE filter, ordering, `LIMIT`/`OFFSET`, then runs the count query (`CountQueryFromRequest`) and stores it in `ctx.Pager.Count`.
4. Each record's roles JSON is hydrated via `LoadData()` and the list is returned with `meta.count`.

`GET /api/user/count` → `Controller.Count` runs only the count path.

### Create user via resource

1. `POST /api/user` requires `create_user` (403 otherwise).
2. Body bound as `{"user":{...}}`; `record.ID` forced to `0` and `Username` forced to a new `uuid.New().String()` (client-chosen usernames are ignored on this endpoint).
3. Echo validator runs on the model; on success the record is saved, reloaded (`LoadData`) and returned with HTTP 201.

### Find / update / delete

1. The record is loaded with `UserFindOne(id)` (numeric id parse; `ID == 0` means not found → 404).
2. If the authenticated user is the record, the `"owner"` role is appended to `ctx.Roles`.
3. Permission check (`find_user` / `update_user` / `delete_user`) returns 403 when not satisfied.
4. Update binds `{"user":{...}}` onto the loaded record (in-place merge — omitted fields keep stored values) and saves; delete performs a hard delete and answers 204.

### Replace user roles (admin)

1. `POST /acl/user/:userID/roles` rejects unauthenticated callers with 401 and callers without `manage_users` with 403 (the comment in code explains this avoids an anonymous privilege-escalation path because the framework does not enforce route permissions and roles may come from JWT claims).
2. Loads the target user (404 when missing), binds `{"userRoles":["..."]}`, calls `SetRoles` (JSON-serializes into `RolesText`) and saves. Returns `{}`.

### Plugin install / migration

1. On the framework `"install"` event (wired by the auth plugin), `InstallAuth` saves one `emails.EmailTemplateModel` of type `AuthChangePasswordEmail` with placeholder content; there is no deduplication in this code.
2. `GetMigrations()` exposes the `"init"` migration: a single transaction that runs `CREATE TABLE IF NOT EXISTS` for `users`, `passwords` and `authtokens` (MySQL-flavored DDL). `Down` is a no-op. Tests do not execute this migration; they use GORM `AutoMigrate` on the same models.

### Client bootstrap config (`renderClientAppConfigs`)

1. Registered by `UserPlugin.setTemplateFunctions` under the name `renderClientAppConfigs`.
2. Builds `HTMLBootstrapConfig`: `appName` (`SITE_NAME`, default `App`), `env` (`GO_ENV`), `hostname` (`ctx.AppOrigin`), `defaultLocale`/`activeLocale` (`DEFAULT_LOCALE`, overridden by the authenticated user's language when set), `locales` (hard-coded `["pt-br"]`), `queryDefaultLimit`/`queryMaxLimit` (`PAGER_LIMIT`/`PAGER_LIMIT_MAX`), `date.defaultFormat` (`"L HH:mm"`), `plugins` (registered plugin names), `authenticatedUser` (`id`, `displayName` when authenticated), `userRoles` (authenticated role names).
3. Appends a `ur-<role>` body class per authenticated role and emits `<script>window.CATUPIRI_BOOTSTRAP_CONFIG=<json>;</script>`.

### Flash messages rendering (`renderFlashMessages`)

1. Reads pending flashes from the `"messages"` flash key of the gorilla session (`GetFlashMessages` in `flash.go`).
2. Renders each message with the `blocks/notifications/flash-message` template, concatenating the HTML; template registration is performed by the auth plugin (../authentication/guide.md).

## Configuration (env vars)

Variables read by this feature's code (defaults shown as implemented):

| Variable | Default | Used by | Purpose |
| -------- | ------- | ------- | ------- |
| `PAGER_LIMIT` | `20` | `renderClientAppConfigs`, framework pager | Default page size for list endpoints and `queryDefaultLimit` in client config. |
| `PAGER_LIMIT_MAX` | `50` | `renderClientAppConfigs`, framework pager | Upper bound for client-supplied `limit`; exported as `queryMaxLimit`. |
| `DEFAULT_LOCALE` | `en-us` | `renderClientAppConfigs` | Default and fallback active locale in client config. |
| `SITE_NAME` | `App` | `renderClientAppConfigs` | `appName` in client config. |
| `SITE_SESSION_PATH` | `/` | `GetSessionOptions` | Session cookie path. |
| `SITE_SESSION_MAX_AGE` | `604800` (`86400*7`) | `GetSessionOptions` | Session cookie max age in seconds. |
| `SITE_SESSION_HTTP_ONLY` | `false` | `GetSessionOptions` | Session cookie HttpOnly flag. |
| `SITE_SESSION_RESAVE` | `true` | Auth plugin middleware wiring | Session resave flag (read in `AuthPlugin.bindMiddlewares`). |

Framework-level variables consumed indirectly: `GO_ENV` (env in client config), `APP_ORIGIN`/`PROTOCOL`/`DOMAIN`/`PORT` (`ctx.AppOrigin`), `DB_URI` + `DB_ENGINE` (database connection used by all model queries; tests use `DB_ENGINE=sqlite`). Redis addresses (`SITE_OAUTH2_ADDR_WRITER`/`SITE_OAUTH2_ADDR_READER`) belong to the OAuth2/session storage and are covered by the authentication doc.

## Design decisions

- **Permission checks live in handlers, not routes.** Every mutation validates `ctx.Can(...)` explicitly; the code comment in `UpdateUserRoles` states the framework does not enforce `Route.Permission`, so handler-level checks are mandatory to avoid anonymous privilege escalation.
- **Implicit `owner` role for self-access.** Find/update/delete append `"owner"` to the request roles when the target record is the authenticated user, letting host apps grant users access to their own record purely through role configuration.
- **Resource creates get a random username.** `POST /api/user` forces `Username = uuid.New().String()`; choosing a username is only possible through the signup flow (authentication feature), which validates it with `ValidateUsername`.
- **Roles are stored as a JSON text column** (`users.roles`) rather than a join table; `RolesText` is hidden from JSON and hydrated into the `Roles` slice on `LoadData`/`GetRoles`.
- **Hard delete.** `Delete` uses `GORM Unscoped()`, so user removal is permanent; there is no soft-delete column.
- **Deny-by-silence on list.** `QueryAndCountFromRequest`/`CountQueryFromRequest` return an empty result (count 0, no error) instead of 403 when the caller lacks `find_user`; single-record `FindOne` returns an explicit 403.
- **Full model serialization.** The `/api/user` endpoints serialize the complete `UserModel` (including `email`, `confirmEmail`, `roles`, `blocked`); the redacted `UserModelPublic` projection is only used by `/auth/current`.
- **Count query divergence.** The count query applies the `q` filter with `.Or(...)` directly on a fresh `db` handle (without the model filter params), while the list query applies both; the two endpoints can therefore disagree when filters are combined.
- **Migration strategy.** Schema creation is shipped as one transactional `"init"` migration with `CREATE TABLE IF NOT EXISTS` and a no-op `Down`; the MySQL-flavored DDL is not exercised by the SQLite-based test suite, which relies on `AutoMigrate`.
- **Bootstrap config injection over templating.** Client-side configuration is centralized in one JSON blob (`window.CATUPIRI_BOOTSTRAP_CONFIG`) that also encodes roles as `ur-*` body classes for CSS-driven role styling.
- **Locales hard-coded.** The `locales` list in both `renderClientAppConfigs` and `UserSettingsHandler` is fixed to `["pt-br"]`, with only the default locale configurable via `DEFAULT_LOCALE`.

## Assumptions & open items

- `Controller.FindAllPageHandler` (HTML list with `user/teaser` render) and `Controller.FindOnePageHandler` (HTML profile page) are implemented but not bound to any route inside this module. They appear to be intended for host apps/themes to register; JSON content negotiation in both handlers delegates to `Query`/`FindOne`. Needs human confirmation on the intended registration point.
- `updates.GetMigrations()` returns an empty slice; `updates.AddNewPasswordEmailTemplateChange` is a no-op migration variable that is not referenced anywhere. It is unclear whether host apps are expected to register `updates.GetMigrations()` or whether this is dead code.
- `errors/session.go` is an empty placeholder package (`var ()`); no error values are exported by this feature yet.
- `Controller.GetUserRolesAndPermissions` performs no authentication/permission check and returns the whole `RolesList`; the `permissions` field of the response is declared as `string` and never populated (always empty). Whether this endpoint should require a permission is an open security question.
- `opts.IsHTML` exists in `QueryAndCountFromRequestCfg` but is never read by `QueryAndCountFromRequest`; its intended behavior is unimplemented.
- The `users` DDL in the `"init"` migration declares `locationState`, `country` (default `'BR'`) and `city` columns that have no counterpart in `UserModel`, and declares duplicate unique keys on `email` and `username`. Keeping them is intentional per the DDL, but they are unmaintained by the Go model.
- `UserModel.Save` sets `CreatedAt` from a new global clock (`clock.New().Now()`) instead of the app clock used for `UpdatedAt`; in tests the global clock is mocked, but in an app with a custom clock the two timestamps may diverge.
- `UserFindOne` returns the raw `strconv.ParseUint` error for non-numeric ids (surfaced as a server error rather than 404/400) in `FindOne`, `Update` and `UpdateUserRoles`.
- `CreateDefaultEmailTemplates` inserts a new `AuthChangePasswordEmail` template row on every `install` event with placeholder "Hello! This is a test." content and no deduplication; it predates the richer templates in `email-templates.go` (owned by the authentication doc).
- `SetEmail` and `SetLanguage` contain TODOs (no email-format or locale validation); `ConfirmEmail` is serialized in resource responses.
- `PasswordModel.UserID` is `*int64` while `AuthTokenModel.UserID` is `*string`; the inconsistency is inherited from the original schema and has not been unified.
- `q` search only matches `displayName`/`fullName` (not `username`/`email`); `CountQueryFromRequest` applies only the `q` filter and skips model filter params, so counts may differ from filtered lists.
- `GetUserRoles` (`501 Not implemented`) and the commented-out `buildUserRolesVar`/ACL route sketch in `UserPlugin.go` indicate unfinished role-management UI support.
- `handlers.go` (`UserSettingsHandler`) and `middlewares.go` are owned by the authentication feature documentation; only the `GET /user-settings` route registration performed by `UserPlugin.BindRoutes` is described here.
