---
id: facebook-auth
title: Facebook Authentication — OAuth code login for app clients
status: draft
created_at: 2026-09-11
updated_at: 2026-09-11
owner: TBD
affected_areas: [backend, http-api]
tags: [facebook, oauth2, social-login, authentication, users, backend, http-api]
---

# Facebook Authentication — OAuth code login for app clients

## Description

The `facebook-auth` feature is the Facebook social login of the `github.com/go-bolo/user` module. It is implemented by `FacebookAuthController` (`FacebookAuthController.go`), a small controller instantiated and wired by the `auth` plugin (`AuthPlugin.go`), which registers a single public JSON endpoint: `POST /auth/facebook/app-login-code`.

The endpoint implements the server half of an app-driven Facebook OAuth flow: the client application performs the Facebook Login dialog, obtains an authorization code, and posts it to the backend. The backend exchanges the code with Facebook, fetches the user profile from the Facebook Graph API (`id`, `name`, `email`), finds or creates the matching local `UserModel`, and issues an OAuth2 access/refresh token pair using the same storage and response contract as the password-based OAuth2 login (see [../authentication/guide.md](../authentication/guide.md)).

The route registration itself lives in the `auth` plugin (`AuthPlugin.BindRoutes`), which belongs to the `authentication` feature; the Facebook handler and all Facebook-specific helpers live here. This feature is a pure token API: it does not render pages, does not redirect, and does not create a browser session cookie — although requests still traverse the global session middleware described in [../sessions/guide.md](../sessions/guide.md), the handler never reads or writes that session.

## How to use

1. **Register the plugin** — Facebook auth ships inside the `auth` plugin; no extra registration is needed:

   ```go
   app.RegisterPlugin(user.NewAuthPlugin(&user.AuthPluginCfgs{}))
   ```

2. **Configure the Facebook app credentials** in the environment (read by `GetFacebookOAuthConfig`):

   - `SITE_FACEBOOK_APP_ID` — the Facebook app id (used as the OAuth2 `ClientID`). Note: the module `README.md` calls this variable `FACEBOOK_CLIENT_ID`; the code actually reads `SITE_FACEBOOK_APP_ID` (see the spec's Assumptions & open items).
   - `FACEBOOK_CLIENT_SECRET` — the Facebook app secret (OAuth2 `ClientSecret`).
   - `FACEBOOK_REDIRECT_URI` — the redirect URL registered in the Facebook app (OAuth2 `RedirectURL`).

   If the app id or secret is empty, the endpoint answers `404 facebook auth configuration not set`, effectively disabling the feature.

3. **Perform the Facebook Login dialog in your client app** using the Facebook app id and the same redirect URI, so the client receives an authorization `code`.

4. **Exchange the code for app tokens**:

   ```http
   POST /auth/facebook/app-login-code
   Content-Type: application/json

   { "code": "<facebook authorization code>" }
   ```

   Success returns `200` with the same JSON shape as the OAuth2 password login:

   ```json
   {
     "access_token": "...",
     "refresh_token": "...",
     "expires_in": 3600,
     "user": { "id": 1, "username": "<facebook id>", "email": "...", "displayName": "..." }
   }
   ```

5. **Call authenticated APIs** with `Authorization: Bearer <access_token>`; the pair is stored in Redis by the OAuth2 password storage and consumed by its authentication middleware (see [../authentication/guide.md](../authentication/guide.md)). Refresh/rotation behavior is owned by that feature, not by this one.

## Goals

- Let app clients (SPAs/mobile) sign in (or sign up implicitly) with Facebook without the backend handling browser redirects.
- Reuse the local user model: the Facebook `email` identifies the account; new accounts are created automatically from the Facebook profile.
- Reuse the OAuth2 password token infrastructure (opaque access/refresh tokens in Redis, identical JSON response) so clients treat Facebook login and password login identically.
- Keep the endpoint configuration-gated: without credentials the feature is simply not available (404).

## Affected areas

- **backend**: `FacebookAuthController.go` (controller, OAuth config builder, Graph API client, user find-or-create, response DTO); `AuthPlugin.go` (controller instantiation in `Init`, route registration in `BindRoutes`).
- **http-api**: `POST /auth/facebook/app-login-code` on the main router (see the API contract in [spec.md](./spec.md)).
- **data**: reads/writes the `users` table via `UserFindOneByUsername` and `UserModel.Save`; writes OAuth2 access/refresh token keys in Redis (owned by the OAuth2 password feature).

## Tags

[facebook, oauth2, social-login, authentication, users, backend, http-api]

## Links

- Feature spec: [spec.md](./spec.md)
- Changelog: [changelog.md](./changelog.md)
- Authentication (plugin, password login, route registration, token middleware): [../authentication/guide.md](../authentication/guide.md)
- Sessions (global session middleware traversed by this route): [../sessions/guide.md](../sessions/guide.md)
- Module README (Facebook env vars): [../../README.md](../../README.md)
