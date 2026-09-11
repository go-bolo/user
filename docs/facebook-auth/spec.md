---
id: facebook-auth-spec
title: Facebook Authentication — specification
status: draft
created_at: 2026-09-11
updated_at: 2026-09-11
owner: TBD
affected_areas: [backend, http-api]
tags: [facebook, oauth2, social-login, authentication, users, backend, http-api]
---

# Facebook Authentication — specification

## Overview & architecture

The feature is a single controller, `FacebookAuthController` (package `user`, file `FacebookAuthController.go`), plus its wiring in the `auth` plugin:

1. **Controller** — `FacebookAuthController` is an empty struct created by `NewFacebookAuthController` (the `NewFacebookAuthControllerCFG.App` field is accepted but unused). It exposes one handler, `LoginWithFacebookAppCode`.
2. **OAuth config builder** — `GetFacebookOAuthConfig(ctx *bolo.RequestContext) *oauth2.Config` builds a `golang.org/x/oauth2` config with `Endpoint: facebook.Endpoint` (package `golang.org/x/oauth2/facebook`) and credentials from the app configuration (see Configuration).
3. **Facebook Graph API client** — `GetUserInfoFromFacebook(token string, ctx *bolo.RequestContext) (FacebookUserDetails, error)` performs `GET https://graph.facebook.com/me?fields=id,name,email&access_token=<token>` with `http.DefaultClient` and decodes the JSON body into `FacebookUserDetails`. The HTTP response status code is not checked; only decode errors are reported.
4. **Local account resolution** — `FindOrCreateUserFromFacebook(facebookUserDetails FacebookUserDetails, ctx *bolo.RequestContext) (*user_models.UserModel, error)` looks the account up by email (`UserFindOneByUsername` matches `username` OR `email`) and creates a new active user when none is found.
5. **Token issuance** — the handler calls `user_oauth2_password.Oauth2GenerateAndSaveToken(ctx, u)` from the OAuth2 password feature: an opaque access/refresh token pair (`uuid + 35 random chars` each), TTL from the OAuth2 access-token TTL configuration, persisted in Redis by `SetAccessToken`/`SetRefreshToken`. This is the non-JWT variant; `Oauth2GenerateAndSaveTokenJWT` is not used here.
6. **Wiring** — `AuthPlugin.Init` instantiates the controller; `AuthPlugin.BindRoutes` registers the route on the main router (not on the `/auth` group): `mainRouter.POST("/auth/facebook/app-login-code", fbAuthCtl.LoginWithFacebookAppCode)`.

Because the route is registered on the main router, requests traverse the global middlewares installed by the `auth` plugin (echo session middleware and the session authentication middleware — see [../sessions/guide.md](../sessions/guide.md)); the handler itself is public, checks no permission, and does not read or write the session. Authentication for subsequent requests is done with the returned token pair through the OAuth2 password feature's middleware (see [../authentication/guide.md](../authentication/guide.md)).

The file also declares `ErrorResponse`, `SuccessResponse`, `Claims` and `UserDetails`; none of them is referenced anywhere in this module (see Assumptions & open items).

## API contract

Routes registered for this feature (by `AuthPlugin.BindRoutes`, main router):

| Method | Path | Auth / Permission |
| ------ | ---- | ----------------- |
| POST | `/auth/facebook/app-login-code` | Public. No permission check and no route-specific guard; requests still pass through the global session middlewares. Answers `404` when the Facebook app id/secret is not configured. Content type of responses is `application/json` (set explicitly via `ctx.SetResponseContentType`). |

Request body (`LoginWithFacebookAppCodeBodyRequest`, JSON binding via `c.Bind`):

| Field | Type | Observed behavior |
| ----- | ---- | ----------------- |
| `code` | string | Facebook authorization code; passed to `OAuth2Config.Exchange`. Required in practice — without a valid code the exchange fails. |
| `redirect_uri` | string | Bound but never used by the handler; the OAuth2 `RedirectURL` comes only from the `FACEBOOK_REDIRECT_URI` configuration. |

Success response — `200` with `oauth2PasswordJSONResponse` (shared with the OAuth2 password login):

| Field | Type | Description |
| ----- | ---- | ----------- |
| `access_token` | string | Opaque access token (UUID + 35 random chars), stored in Redis. |
| `refresh_token` | string | Opaque refresh token, stored in Redis. |
| `expires_in` | number | Access token lifetime in seconds (from `Oauth2TokenData.ExpiresIn`). |
| `user` | `UserModel` | The authenticated local user (JSON serialization of the model). |

Error responses (`*bolo.HTTPError`; the `Internal` cause is logged via logrus, not returned to the client):

| Condition | HTTP status | Message |
| --------- | ----------- | ------- |
| Facebook app id or secret empty (`GetFacebookOAuthConfig`) | 404 | `facebook auth configuration not set` |
| Request body cannot be bound (non-echo error) | 404 | No content (`c.NoContent(http.StatusNotFound)`); `*echo.HTTPError` bind errors are returned as-is |
| `OAuth2Config.Exchange` fails or returns nil token | 401 | `Invalid token` |
| Graph API request/decode fails (`GetUserInfoFromFacebook`) | 401 | `Invalid token` |
| `FindOrCreateUserFromFacebook` fails (empty email, empty name, DB error, save error) | 401 | `Invalid token` |
| `Oauth2GenerateAndSaveToken` fails | 400 | `Invalid token` |

## Data models

- `FacebookUserDetails` (`FacebookAuthController.go`) — profile fetched from the Graph API:
  - `ID string` (`json:"id"`) — Facebook numeric id; becomes the `Username` of newly created users.
  - `Name string` (`json:"name"`) — becomes `DisplayName` and `FullName`; required.
  - `Email string` (`json:"email"`) — account lookup key and `Email`; required.
  - `Picture *FacebookUserPicture` (`json:"picture"`) — decoded but never used by this feature (the Graph request does not even ask for the `picture` field).
- `FacebookUserPicture` — `Data` struct with `Height int`, `IsSilhouette bool`, `URL string`, `Width int` (JSON tags `height`, `is_silhouette`, `url`, `width`).
- `LoginWithFacebookAppCodeBodyRequest` — `Code string` (`json:"code"`), `RedirectUri string` (`json:"redirect_uri"`).
- `oauth2PasswordJSONResponse` — `AccessToken *string` (`json:"access_token"`), `RefreshToken *string` (`json:"refresh_token"`), `ExpiresIn *int64` (`json:"expires_in"`), `User *user_models.UserModel` (`json:"user"`); the same type is used by the OAuth2 password login response.
- Local user creation (when no account matches): a `UserModel` is created with `Username = FacebookUserDetails.ID`, `Email`, `DisplayName = FullName = Name`, `Active = true`, `AcceptTerms = false`, and saved with `u.Save(ctx)` (GORM save through the app DB). No password record is created.
- Unused declarations in the same file (no references in this module): `ErrorResponse`, `SuccessResponse`, `Claims` (JWT claims with `Email`), `UserDetails`.

## Flows

**Facebook app-code login (`POST /auth/facebook/app-login-code`)**

1. **Context and configuration** — the handler casts the Echo context to `*bolo.RequestContext` and builds the OAuth2 config with `GetFacebookOAuthConfig`. If `ClientID` (`SITE_FACEBOOK_APP_ID`) or `ClientSecret` (`FACEBOOK_CLIENT_SECRET`) is empty, it returns `404 facebook auth configuration not set` — the feature is disabled.
2. **Bind** — the response content type is set to `application/json` and the body is bound to `LoginWithFacebookAppCodeBodyRequest`. A generic bind error returns `404` with no content; an `*echo.HTTPError` from the binder is returned unchanged.
3. **Code exchange** — `OAuth2Config.Exchange(context.Background(), body.Code)` calls Facebook's token endpoint (`facebook.Endpoint`) to exchange the authorization code for a Facebook access token. Failure (or a nil token) is logged and returns `401 Invalid token`.
4. **Profile fetch** — `GetUserInfoFromFacebook` calls `GET https://graph.facebook.com/me?fields=id,name,email&access_token=<access token>` with `http.DefaultClient` and decodes the JSON body into `FacebookUserDetails`. Request, response or decode failures return `401 Invalid token`.
5. **Find or create the local user** — `FindOrCreateUserFromFacebook`:
   - Rejects an empty `Email` or empty `Name` (the error strings misleadingly mention "last name"/"password" — see Assumptions & open items).
   - Loads the account with `UserFindOneByUsername(email)`, which matches `username = ? OR email = ?`; an error other than `gorm.ErrRecordNotFound` aborts with `401 Invalid token`.
   - If no record was found (`u.ID == 0`), creates a new `UserModel` (Username = Facebook id, Email, DisplayName/FullName = name, Active = true, AcceptTerms = false) and saves it; a save error aborts with `401 Invalid token`. If a record was found, it is reused as-is (no profile fields are updated).
6. **Token issuance** — `user_oauth2_password.Oauth2GenerateAndSaveToken(ctx, u)` generates the opaque access/refresh pair, resolves the TTL through the OAuth2 access-token TTL configuration (a configuration error aborts with `400 Invalid token`), and stores both tokens (JSON payload with owner id and expiry) in Redis via `SetAccessToken`/`SetRefreshToken`.
7. **Response** — `200` JSON with `access_token`, `refresh_token`, `expires_in` and `user`. No session cookie is set; clients authenticate later calls with `Authorization: Bearer <access_token>` (handled by the OAuth2 password middleware — see [../authentication/guide.md](../authentication/guide.md)). The global session middleware that this request traversed is described in [../sessions/guide.md](../sessions/guide.md).

**Step 0 (client side, outside this module)** — the client performs the Facebook Login dialog with the app id and the redirect URI registered in the Facebook app, and obtains the `code` posted in step 2. The backend renders no Facebook pages and registers no OAuth callback route.

## Configuration

Values read from the app configuration (environment) by this feature:

| Key | Type | Default | Description |
| --- | ---- | ------- | ----------- |
| `SITE_FACEBOOK_APP_ID` | string | `""` (`cfgs.Get`) | Facebook app id; used as the OAuth2 `ClientID`. This is the key the code reads — the `README.md` documents the same setting as `FACEBOOK_CLIENT_ID` (see Assumptions & open items). |
| `FACEBOOK_CLIENT_SECRET` | string | `""` (`cfgs.Get`) | Facebook app secret; used as the OAuth2 `ClientSecret`. Empty (alone or with an empty app id) disables the endpoint with `404`. |
| `FACEBOOK_REDIRECT_URI` | string | `""` (`cfgs.Get`) | Redirect URL registered in the Facebook app; assigned to the OAuth2 config's `RedirectURL`. Not used by `Exchange` for the server-side code exchange, but part of the config handed to Facebook. |

Related configuration owned by the OAuth2 password feature (not this one): the access-token TTL (`OAUTH2_ACCESS_TOKEN_TTL`, resolved by `AccessTokenTTL`) determines `expires_in`, and the OAuth2 Redis storage settings determine where the issued tokens are stored — see [../authentication/guide.md](../authentication/guide.md).

The module `README.md` lists `FACEBOOK_CLIENT_ID`, `FACEBOOK_REDIRECT_URI` and `FACEBOOK_CLIENT_SECRET` as the Facebook settings.

## Design decisions

- **App-driven code exchange**: the client performs the Facebook OAuth dialog and posts only the authorization code; the backend stays stateless (no redirect handling, no callback route, no `state` handling). The `context.Background()` used in `Exchange` also keeps the exchange independent of the HTTP request lifecycle.
- **Standard `golang.org/x/oauth2` with the fixed Facebook endpoint**: `facebook.Endpoint` is hardcoded; there is no configuration for alternative Graph/API versions.
- **Email as the account identity**: the local account is looked up by `UserFindOneByUsername(email)` (matching `username` OR `email`), and the Facebook numeric `id` becomes the `Username` of new accounts, keeping the Facebook id out of the email column.
- **Implicit signup**: unknown Facebook users become active local users automatically (`Active = true`), with `AcceptTerms = false` and no password record — they can only authenticate through social/token flows until a password is set.
- **Token contract reuse**: instead of a Facebook-specific session, the handler reuses `Oauth2GenerateAndSaveToken` and `oauth2PasswordJSONResponse` from the OAuth2 password feature, so the JSON response and Redis token storage are identical to password login and clients need no special handling. The opaque (non-JWT) variant is used.
- **Opaque failures**: every handler failure returns the generic message `Invalid token` (or the configuration 404); causes are wrapped into `HTTPError.Internal` and logged with logrus, avoiding leaking Facebook/user details to clients.
- **Configuration-gated availability**: an unconfigured app id/secret yields `404` instead of a runtime crash or a 500, effectively turning the route off.
- **JSON-only API**: no HTML pages, templates or redirects; content type is forced to `application/json`.

## Assumptions & open items

- **App-id key mismatch (needs human decision)**: the code reads `SITE_FACEBOOK_APP_ID` for the OAuth2 `ClientID`, while `README.md` documents `FACEBOOK_CLIENT_ID`. An operator following the README gets a `404` on every login. Either the code or the README is wrong; this documentation describes the code.
- **`redirect_uri` is dead input**: `LoginWithFacebookAppCodeBodyRequest.RedirectUri` is bound but never read; the redirect URL comes solely from `FACEBOOK_REDIRECT_URI`. Whether per-request redirect URIs were intended is unclear.
- **Email is mandatory and unverified**: if Facebook does not return an `email` (e.g. the user denied the email permission), the login fails with `401`. The code never checks an `email_verified`-style field (it is not requested from the Graph API), so any email Facebook returns is trusted.
- **Existing-account takeover/merge by email**: because the lookup matches `username` OR `email`, a Facebook login with the email of an existing local account signs into that account and never updates its profile (no name/avatar sync, no explicit linking/confirmation step). Whether this merging is desired is a product decision.
- **Misleading internal error strings**: `FindOrCreateUserFromFacebook` returns "FindOrCreateUserFromFacebook last name can't be empty" for an empty email and "…password can't be empty" for an empty name (copy-paste artifacts); any DB error other than record-not-found is reported as "user not found". These messages are only logged/internal, but they hurt diagnostics.
- **No Facebook-specific tests**: `grep` finds no Facebook references in `*_test.go` or `setup_test.go`; the endpoint's behavior is inferred from code only and is untested in this module.
- **Graph API client robustness**: `GetUserInfoFromFacebook` does not check the HTTP status code (a non-JSON error body surfaces as a decode error), uses `http.DefaultClient` (no timeout), and its second error check (`facebookUserDetailsResponseError`) is redundant with the first, since both come from the same `http.DefaultClient.Do` call.
- **No abuse protection**: the route is public with no permission check, and the module's login throttle/reCAPTCHA helpers (`user/security`) are not wired into it; nothing in this module rate-limits code-exchange attempts.
- **Picture and extra fields unused**: only `id,name,email` are requested from the Graph API; `FacebookUserDetails.Picture` is decoded but never persisted, and no avatar is stored on the user.
- **Dead declarations**: `ErrorResponse`, `SuccessResponse`, `Claims` and `UserDetails` in `FacebookAuthController.go` are not referenced anywhere in this module; they look like leftovers from the example this controller was derived from.
- **Users created here cannot password-login until a password exists**: no password record is created; setting one later depends on the flows owned by the `authentication` feature (e.g. admin "set password"), not on this feature.
- **Expiry semantics inherited**: `expires_in` is seconds and comes from the OAuth2 password TTL configuration; if that configuration is invalid, login fails with `400` even though the Facebook step succeeded (by design of `AccessTokenTTL`).
