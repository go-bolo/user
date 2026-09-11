package user_oauth2_password

import (
	"net/http"

	"github.com/go-bolo/bolo"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

// RevokeTokenRequestBody corpo do endpoint de revogação (RFC 7009).
type RevokeTokenRequestBody struct {
	Token         string `json:"token" validate:"required"`
	TokenTypeHint string `json:"token_type_hint"`
}

// RevokeOauth2TokenHandler revoga um refresh token (hint "refresh_token" ou
// ausente) ou um access token (hint "access_token"). Seguindo a RFC 7009,
// responde 200 SEMPRE para token de formato válido, sem revelar se o token
// existia; falha de revogação é apenas logada (best-effort).
func RevokeOauth2TokenHandler(c echo.Context) error {
	ctx := c.(*bolo.RequestContext)

	var body RevokeTokenRequestBody
	if err := c.Bind(&body); err != nil {
		return c.NoContent(http.StatusNotFound)
	}

	if err := c.Validate(&body); err != nil {
		return err
	}

	switch body.TokenTypeHint {
	case "access_token":
		if err := DeleteAccessToken(ctx, body.Token); err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Error("RevokeOauth2TokenHandler error on delete access token")
		}
	default:
		// refresh_token (hint padrão da RFC) ou hint não suportado
		if err := RevokeByRefreshToken(body.Token); err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Error("RevokeOauth2TokenHandler error on revoke refresh token")
		}
	}

	return c.JSON(http.StatusOK, make(map[string]string))
}
