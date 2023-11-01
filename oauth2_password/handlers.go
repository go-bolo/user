package user_oauth2_password

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-bolo/bolo"
	user_models "github.com/go-bolo/user/models"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type oauth2PasswordRequestBody struct {
	Email     string `json:"email" validate:"required"`
	Password  string `json:"password" validate:"required"`
	GrantType string `json:"grant_type"`
}

type oauth2PasswordJSONResponse struct {
	AccessToken  *string                `json:"access_token"`
	RefreshToken *string                `json:"refresh_token"`
	ExpiresIn    *int64                 `json:"expires_in"`
	User         *user_models.UserModel `json:"user"`
}

type oauth2PasswordJSONResponseError struct {
	bolo.BaseErrorResponse
}

func AuthenticationOauth2PasswordHandler(c echo.Context) error {
	var body oauth2PasswordRequestBody
	ctx := c.(*bolo.RequestContext)

	if err := c.Bind(&body); err != nil {
		return c.NoContent(http.StatusNotFound)
	}

	if err := c.Validate(&body); err != nil {
		return err
	}

	valid, err := ValidUsernamePassword(body.Email, body.Password)
	if err != nil {
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			result := oauth2PasswordJSONResponseError{}
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
		result := oauth2PasswordJSONResponseError{}
		result.Messages = append(result.Messages, bolo.BaseErrorResponseMessage{
			Status:  "danger",
			Message: "Email ou senha incorretos.",
		})
		return c.JSON(400, &result)
	}

	// create oauth2Tokens

	var userRecord user_models.UserModel

	err = user_models.UserFindOneByUsername(body.Email, &userRecord)
	if err != nil {
		return err
	}

	data, err := Oauth2GenerateAndSaveToken(ctx, &userRecord)
	if err != nil {
		return err
	}

	resp := oauth2PasswordJSONResponse{
		AccessToken:  &data.AccessToken,
		RefreshToken: &data.RefreshToken,
		ExpiresIn:    &data.ExpiresIn,
		User:         &userRecord,
	}

	return c.JSON(200, &resp)
}
