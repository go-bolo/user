package user_oauth2_jwt

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-bolo/bolo"
	user_models "github.com/go-bolo/user/models"
	user_oauth2_password "github.com/go-bolo/user/oauth2_password"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type oauth2PasswordRequestBody struct {
	Email     string `json:"email" validate:"required"`
	Password  string `json:"password" validate:"required"`
	GrantType string `json:"grant_type"`
}

type authenticationJWTJSONResponse struct {
	AccessToken  *string                `json:"access_token"`
	RefreshToken *string                `json:"refresh_token"`
	ExpiresIn    *int64                 `json:"expires_in"`
	User         *user_models.UserModel `json:"user"`
}

type authenticationJWTJSONResponseError struct {
	bolo.BaseErrorResponse
}

// loginActivityHook é o callback de PluginCfgs.OnLoginActivity (paridade
// com os handlers do consumidor; o mm registra atividade de login).
var loginActivityHook func(userID uint64) error

// registerLoginActivity dispara o hook de atividade de login; falha só
// loga, nunca derruba o login/refresh.
func registerLoginActivity(userID uint64) {
	if loginActivityHook == nil {
		return
	}

	if err := loginActivityHook(userID); err != nil {
		logrus.WithFields(logrus.Fields{
			"error":  err,
			"userID": userID,
		}).Error("Falha ao registrar a atividade de login do usuário")
	}
}

// AuthenticationJWTHandler emite o par no formato JWT: access
// stateless + refresh opaco rotativo. Mesmo contrato de corpo/resposta do
// grant-password (incluindo as mensagens de inativo/bloqueado) — o
// frontend troca de endpoint sem nenhuma outra mudança.
func AuthenticationJWTHandler(c echo.Context) error {
	var body oauth2PasswordRequestBody
	ctx := c.(*bolo.RequestContext)

	if err := c.Bind(&body); err != nil {
		return c.NoContent(http.StatusNotFound)
	}

	if err := c.Validate(&body); err != nil {
		return err
	}

	valid, err := user_oauth2_password.ValidUsernamePassword(body.Email, body.Password)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			result := authenticationJWTJSONResponseError{}
			result.Messages = append(result.Messages, bolo.BaseErrorResponseMessage{
				Status:  "danger",
				Message: "Usuário não encontrado ou não possuí senha cadastrada.",
			})
			return c.JSON(400, &result)
		}

		logrus.WithFields(logrus.Fields{
			"error": fmt.Sprintf("%+v\n", err),
		}).Error("Unknow error", err)
		return err
	}

	if !valid {
		result := authenticationJWTJSONResponseError{}
		result.Messages = append(result.Messages, bolo.BaseErrorResponseMessage{
			Status:  "danger",
			Message: "Email ou senha incorretos.",
		})
		return c.JSON(400, &result)
	}

	var userRecord user_models.UserModel

	err = user_models.UserFindOneByUsername(body.Email, &userRecord)
	if err != nil {
		return err
	}

	// Mesma semântica do grant-password: inativo/bloqueado não recebe par de
	// tokens, mesmo com senha válida.
	if !userRecord.Active {
		result := authenticationJWTJSONResponseError{}
		result.Messages = append(result.Messages, bolo.BaseErrorResponseMessage{
			Status:  "warning",
			Message: "Conta não ativada. Por favor, verifique seu email para ativar sua conta.",
		})
		return c.JSON(http.StatusForbidden, &result)
	}

	if userRecord.Blocked {
		result := authenticationJWTJSONResponseError{}
		result.Messages = append(result.Messages, bolo.BaseErrorResponseMessage{
			Status:  "danger",
			Message: "Conta bloqueada. Entre em contato com o suporte.",
		})
		return c.JSON(http.StatusForbidden, &result)
	}

	data, err := user_oauth2_password.Oauth2GenerateAndSaveTokenJWT(ctx, &userRecord)
	if err != nil {
		return err
	}

	registerLoginActivity(userRecord.ID)

	resp := authenticationJWTJSONResponse{
		AccessToken:  &data.AccessToken,
		RefreshToken: &data.RefreshToken,
		ExpiresIn:    &data.ExpiresIn,
		User:         &userRecord,
	}

	return c.JSON(200, &resp)
}

type refreshTokenRequestBody struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

func refreshGrantErrorResponse(message string) *authenticationJWTJSONResponseError {
	result := authenticationJWTJSONResponseError{}
	result.Messages = append(result.Messages, bolo.BaseErrorResponseMessage{
		Status:  "danger",
		Message: message,
	})
	return &result
}

// RefreshTokenJWTHandler troca um refresh token válido por um par novo no
// formato JWT (access stateless). Toda a semântica de segurança (rotação
// single-use, graça de reuso idempotente, teto absoluto por família e
// revogação em cadeia quando detecta reuso) vive na lib
// (RotateRefreshTokenWithFormat); aqui apenas mapeamos o resultado para o
// contrato HTTP de sempre (status e mensagens preservados — os frontends
// dependem deles).
func RefreshTokenJWTHandler(c echo.Context) error {
	var body refreshTokenRequestBody
	ctx := c.(*bolo.RequestContext)

	if err := c.Bind(&body); err != nil {
		return c.NoContent(http.StatusNotFound)
	}

	if err := c.Validate(&body); err != nil {
		return err
	}

	pair, refreshedUser, rerr := user_oauth2_password.RotateRefreshTokenWithFormat(ctx, body.RefreshToken, user_oauth2_password.FormatJWT)
	if rerr != nil {
		switch rerr.Kind {
		case user_oauth2_password.ErrExpiredIdle, user_oauth2_password.ErrExpiredAbsolute, user_oauth2_password.ErrReuseDetected:
			// sessão vencida (idle/teto absoluto) e reuso fora da graça são
			// indistinguíveis para o usuário final
			return c.JSON(http.StatusBadRequest, refreshGrantErrorResponse(
				"Sessão expirada. Entre novamente.",
			))

		case user_oauth2_password.ErrUserInvalid:
			// usuário que não existe mais (ID zerado) trata como sessão
			// expirada; inativo/bloqueado mantêm as mensagens de sempre
			if refreshedUser == nil || refreshedUser.ID == 0 {
				return c.JSON(http.StatusBadRequest, refreshGrantErrorResponse(
					"Sessão expirada. Entre novamente.",
				))
			}

			if !refreshedUser.Active {
				result := authenticationJWTJSONResponseError{}
				result.Messages = append(result.Messages, bolo.BaseErrorResponseMessage{
					Status:  "warning",
					Message: "Conta não ativada. Por favor, verifique seu email para ativar sua conta.",
				})
				return c.JSON(http.StatusForbidden, &result)
			}

			if refreshedUser.Blocked {
				result := authenticationJWTJSONResponseError{}
				result.Messages = append(result.Messages, bolo.BaseErrorResponseMessage{
					Status:  "danger",
					Message: "Conta bloqueada. Entre em contato com o suporte.",
				})
				return c.JSON(http.StatusForbidden, &result)
			}

			// usuário teoricamente válido caiu aqui: trata como sessão expirada
			return c.JSON(http.StatusBadRequest, refreshGrantErrorResponse(
				"Sessão expirada. Entre novamente.",
			))

		default:
			// ErrInternal e kinds futuros: falha de infra (nada foi revogado)
			logrus.WithFields(logrus.Fields{
				"error": rerr,
			}).Error("RefreshTokenJWTHandler error on rotate refresh token")
			return rerr
		}
	}

	if refreshedUser == nil {
		// só ocorre no replay dentro da graça com falha ao carregar o dono
		logrus.Error("RefreshTokenJWTHandler missing user after successful refresh token rotation")
		return errors.New("RefreshTokenJWTHandler: usuário não carregado na rotação do refresh token")
	}

	registerLoginActivity(refreshedUser.ID)

	resp := authenticationJWTJSONResponse{
		AccessToken:  &pair.AccessToken,
		RefreshToken: &pair.RefreshToken,
		ExpiresIn:    &pair.ExpiresIn,
		User:         refreshedUser,
	}

	return c.JSON(200, &resp)
}
