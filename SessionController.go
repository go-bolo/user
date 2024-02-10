package user

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-bolo/bolo"
	"github.com/go-bolo/metatags"
	user_models "github.com/go-bolo/user/models"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type loginJSONResponseError struct {
	bolo.BaseErrorResponse
}

type NewSessionControllerCFG struct {
	App bolo.App
}

type LoginRequestBody struct {
	Email      string `json:"email" form:"email" validate:"required"`
	Password   string `json:"password" form:"password" validate:"required"`
	RememberMe bool   `json:"remember_me" form:"remember_me"`
}

func NewSessionController(cfg *NewSessionControllerCFG) *SessionController {
	return &SessionController{App: cfg.App}
}

type SessionController struct {
	App bolo.App
}

func (ctl *SessionController) LoginPage(c echo.Context) error {
	ctx := c.(*bolo.RequestContext)
	if ctx.IsAuthenticated {
		return c.Redirect(http.StatusTemporaryRedirect, "/")
	}

	mt := c.Get("metatags").(*metatags.HTMLMetaTags)

	ctx.Title = "Login"
	mt.Title = "Login"

	status := http.StatusOK
	switch c.Get("status").(type) {
	case string:
		status, _ = strconv.Atoi(c.Get("status").(string))
	}

	return bolo.MinifiAndRender(status, "auth/login", &bolo.TemplateCTX{
		Ctx: ctx,
	}, ctx)
}

func (ctl *SessionController) Login(c echo.Context) error {
	var body LoginRequestBody

	ctx := c.(*bolo.RequestContext)

	if ctx.IsAuthenticated {
		return c.Redirect(http.StatusTemporaryRedirect, "/")
	}

	if err := c.Bind(&body); err != nil {
		return c.NoContent(http.StatusNotFound)
	}

	if err := c.Validate(&body); err != nil {
		return err
	}

	valid, err := user_models.ValidUsernamePassword(body.Email, body.Password)
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			AddFlashMessage(c, &FlashMessage{
				Type:    "error",
				Message: "Email ou senha incorretos.",
			})
			c.Set("status", http.StatusBadRequest)
			return ctl.LoginPage(c)
		}

		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = AddFlashMessage(c, &FlashMessage{
				Type:    "error",
				Message: "Usuário não encontrado ou não possuí senha cadastrada.",
			})
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"error": fmt.Sprintf("%+v\n", err),
				}).Error("AddFlashMessage Error", err)
			}
			c.Set("status", http.StatusBadRequest)
			return ctl.LoginPage(c)
		}

		logrus.WithFields(logrus.Fields{
			"error": fmt.Sprintf("%+v\n", err),
		}).Error("Unknow error", err)
		return err
	}

	if !valid {
		AddFlashMessage(c, &FlashMessage{
			Type:    "error",
			Message: "Erro ao validar a senha.",
		})
		c.Set("status", http.StatusBadRequest)
		return ctl.LoginPage(c)
	}

	var userRecord user_models.UserModel

	err = user_models.UserFindOneByUsername(body.Email, &userRecord)
	if err != nil {
		return err
	}

	_, err = SetUserSession(ctx.App, c, &userRecord)
	if err != nil {
		return err
	}

	return c.Redirect(http.StatusFound, "/")
}

func (ctl *SessionController) Logout(c echo.Context) error {
	err := DeleteUserSession(c)
	if err != nil {
		AddFlashMessage(c, &FlashMessage{
			Type:    "error",
			Message: "Error on delete session.",
		})
	}

	return c.Redirect(http.StatusTemporaryRedirect, "/")
}
