package user_oauth2_jwt

import (
	"encoding/json"
	"strconv"

	"github.com/go-bolo/bolo"
	user_models "github.com/go-bolo/user/models"
	user_oauth2_password "github.com/go-bolo/user/oauth2_password"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

// jwtAuthenticationMiddleware valida Bearer JWT. Contrato do subplugin:
//
//   - Bearer com formato JWT (2 pontos): válido => monta o stub autenticado
//     e marca c.Set("auth.jwt", true) para o middleware opaco do
//     oauth2_password pular a validação (o access JWT não existe no Redis);
//     inválido/expirado => 401 com WWW-Authenticate, INDEPENDENTE de
//     OAUTH2_STRICT_401 — o formato é inequivocamente nosso, cair no fluxo
//     opaco só transformaria o token válido em miss/401 falso;
//   - Bearer opaco ou sem header: segue intocado (middleware opaco cuida).
//
// Precisa ser registrado ANTES do middleware do oauth2_password: a ordem de
// execução segue a ordem de RegisterPlugin no consumidor.
func jwtAuthenticationMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if user_oauth2_password.IsPublicRoute(c.Path()) {
				return next(c)
			}

			token := user_oauth2_password.GetOauth2TokenFromAuthorization(c.Request().Header.Get("Authorization"))
			if token == "" || !LooksLikeJWT(token) {
				return next(c)
			}

			cfg := GetConfig()
			if cfg == nil {
				// sem configuração carregada não valida nada: fail-closed
				logrus.Error("oauth2_jwt: middleware ativo sem configuração (evento configuration não rodou?)")
				return user_oauth2_password.NewUnauthorizedTokenHTTPError(c, "invalid token")
			}

			claims, err := ValidateAccessToken(cfg, token)
			if err != nil {
				description := "invalid token"
				if err == ErrTokenExpired {
					description = "token expired"
				}

				logrus.WithFields(logrus.Fields{
					"error": err,
				}).Debug("oauth2_jwt: access token JWT rejeitado")

				return user_oauth2_password.NewUnauthorizedTokenHTTPError(c, description)
			}

			ctx := c.(*bolo.RequestContext)
			ctx.SetAuthenticatedUserAndFillRoles(BuildUserStubFromClaims(claims))
			c.Set("auth.jwt", true)

			return next(c)
		}
	}
}

// BuildUserStubFromClaims monta o stub de usuário a partir dos claims:
// RolesText alimentado com as roles do claim faz GetRoles/ctx.Can
// funcionarem, e o snapshot active/blocked sustenta o
// requireActiveUserMiddleware sem query no banco. A defasagem em relação ao
// banco é de no máximo o TTL do access token (contrato aceito).
func BuildUserStubFromClaims(claims *AccessClaims) *user_models.UserModel {
	rolesJSON, _ := json.Marshal(claims.Roles)

	userID, _ := strconv.ParseUint(claims.Subject, 10, 64)

	return &user_models.UserModel{
		ID:        userID,
		Active:    claims.Active,
		Blocked:   claims.Blocked,
		RolesText: string(rolesJSON),
	}
}
