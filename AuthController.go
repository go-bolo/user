package user

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-bolo/bolo"
	"github.com/go-bolo/emails"
	"github.com/go-bolo/metatags"
	"github.com/go-bolo/system_settings"
	auth_helpers "github.com/go-bolo/user/helpers"
	user_models "github.com/go-bolo/user/models"
	auth_oauth2_password "github.com/go-bolo/user/oauth2_password"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type AuthController struct {
	App bolo.App
}

type SignupBody struct {
	Username     string `json:"username,omitempty" validate:"required"`
	Email        string `json:"email,omitempty" validate:"required,email"`
	ConfirmEmail string `json:"confirmEmail,omitempty" validate:"required,email,eqcsfield=Email"`
	DisplayName  string `json:"displayName,omitempty" validate:"required"`
	FullName     string `json:"fullName,omitempty"`
	Biography    string `json:"biography,omitempty"`
	Gender       string `json:"gender,omitempty"`
	Language     string `json:"language,omitempty"`
	AcceptTerms  bool   `json:"acceptTerms,omitempty" validate:"required"`
	Birthdate    string `json:"birthdate,omitempty"`
	Phone        string `json:"phone,omitempty"`
}

func (sb *SignupBody) ToJSON() string {
	jsonString, _ := json.Marshal(sb)
	return string(jsonString)
}

type SignupResponse struct {
	User   *user_models.UserModel       `json:"user"`
	Errors []*bolo.ValidationFieldError `json:"errors,omitempty"`
}

type SetPasswordBody struct {
	NewPassword  string `json:"newPassword,omitempty" validate:"required,min=3"`
	RNewPassword string `json:"rNewPassword,omitempty" validate:"required,eqfield=NewPassword"`
}

func (b *SetPasswordBody) ToJSON() string {
	jsonString, _ := json.Marshal(b)
	return string(jsonString)
}

type ChangeOwnPasswordBody struct {
	Password     string `json:"password,omitempty" form:"password"`
	NewPassword  string `json:"newPassword,omitempty" form:"newPassword" validate:"required,min=3"`
	RNewPassword string `json:"rNewPassword,omitempty" form:"rNewPassword" validate:"required,eqfield=NewPassword"`
}

func (b *ChangeOwnPasswordBody) ToJSON() string {
	jsonString, _ := json.Marshal(b)
	return string(jsonString)
}

func (ctl *AuthController) GetCurrentUser(c echo.Context) error {
	ctx := c.(*bolo.RequestContext)
	if ctx.IsAuthenticated {
		return c.JSON(http.StatusOK, user_models.NewUserModelPublicFromUserModel(ctx.AuthenticatedUser.(*user_models.UserModel)))
	} else {
		return c.JSON(http.StatusOK, map[string]string{})
	}
}

func (ctl *AuthController) Signup(c echo.Context) error {
	body := SignupBody{}

	if err := c.Bind(&body); err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Debug("AuthController.Signup error on bind")

		if _, ok := err.(*echo.HTTPError); ok {
			return err
		}
		return c.NoContent(http.StatusNotFound)
	}

	if err := c.Validate(&body); err != nil {
		return err
	}

	if !auth_helpers.ValidateUsername(body.Username) {
		resp := bolo.ValidationResponse{
			Errors: []*bolo.ValidationFieldError{
				{
					Field:   "username",
					Message: "invalid username",
				},
			},
		}
		return c.JSON(http.StatusBadRequest, resp)
	}

	if !body.AcceptTerms {
		// TODO! return a bad request
		return errors.New("auth.register.acceptTerms.required")
	}

	userRecord := user_models.UserModel{
		Username:    body.Username,
		Email:       body.Email,
		DisplayName: body.DisplayName,
		FullName:    body.FullName,
		Biography:   body.Biography,
		Gender:      body.Gender,
		Active:      false,
		Blocked:     false,
		Language:    body.Language,
		AcceptTerms: body.AcceptTerms,
		Birthdate:   body.Birthdate,
		Phone:       body.Phone,
	}

	err := userRecord.Save()
	if err != nil {
		return err // TODO! improve this error handler
	}

	return c.JSON(http.StatusOK, SignupResponse{User: &userRecord})
}

// Logout handler with supports to unAuthenticate from all strategies
// TODO! add support for unauthenticate from all session strategies with events
func (ctl *AuthController) Logout(c echo.Context) error {
	ctx := c.(*bolo.RequestContext)

	authorizationToken := c.Request().Header.Get("Authorization")

	if authorizationToken == "" {
		return c.JSON(http.StatusOK, bolo.EmptyResponse{})
	}

	if authorizationToken != "" {
		// remove the token
		token := auth_oauth2_password.GetOauth2TokenFromAuthorization(authorizationToken)
		if token != "" {
			err := auth_oauth2_password.DeleteAccessToken(ctx, token)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"error": err,
				}).Error("AuthController.Logout error on delete access token")
			}
		}
	}

	return c.JSON(http.StatusOK, make(map[string]string))
}

// Activate a user account with activation code
func (ctl *AuthController) Activate(c echo.Context) error {
	return c.String(501, "not implemented")
}

// Generate one time reset password token and send it to user
// change password with token
func (ctl *AuthController) ForgotPasswordRequest(c echo.Context) error {
	return c.String(501, "not implemented")
}

// Check if a reset token is valid
func (ctl *AuthController) CheckIfResetPasswordTokenIsValid(c echo.Context) error {
	return c.String(501, "not implemented")
}

func (ctl *AuthController) ForgotPasswordUpdate(c echo.Context) error {
	return c.String(501, "not implemented")
}

func (ctl *AuthController) UpdatePassword(c echo.Context) error {
	return c.String(501, "not implemented")
}

func (ctl *AuthController) ChangeOwnPassword_Page(c echo.Context) error {
	if c.Get("template") == nil {
		c.Set("template", "auth/change-password")
	}

	ctx := c.(*bolo.RequestContext)
	if !ctx.IsAuthenticated {
		return c.Redirect(http.StatusTemporaryRedirect, "/")
	}

	mt := c.Get("metatags").(*metatags.HTMLMetaTags)
	mt.Title = "Change password | Monitor do Mercado"

	ctx.Title = "Change password"

	status := http.StatusOK
	switch c.Get("status").(type) {
	case string:
		status, _ = strconv.Atoi(c.Get("status").(string))
	}

	return bolo.MinifiAndRender(status, c.Get("template").(string), &bolo.TemplateCTX{
		Ctx: ctx,
	}, ctx)
}

// ChangeOwnPassword - POST endpoint
func (ctl *AuthController) ChangeOwnPassword(c echo.Context) error {
	ctx := c.(*bolo.RequestContext)
	c.Set("template", "auth/change-password")

	if !ctx.IsAuthenticated {
		AddFlashMessage(c, &FlashMessage{
			Type:    "error",
			Message: "user should be authenticated",
		})
		c.Set("status", http.StatusForbidden)
		return ctl.ChangeOwnPassword_Page(c)
	}

	body := ChangeOwnPasswordBody{}

	if err := c.Bind(&body); err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Debug("AuthController.ChangeOwnPassword error on bind")

		if e, ok := err.(*echo.HTTPError); ok {
			AddFlashMessage(c, &FlashMessage{
				Type:    "error",
				Message: e.Error(),
			})
			c.Set("status", e.Code)
		} else {
			AddFlashMessage(c, &FlashMessage{
				Type:    "error",
				Message: "Invalid data sent",
			})
			c.Set("status", http.StatusBadRequest)
		}

		return ctl.ChangeOwnPassword_Page(c)
	}

	if err := c.Validate(&body); err != nil {
		return err
	}

	record := ctx.AuthenticatedUser.(*user_models.UserModel)

	if body.Password == "" {
		var passwordRecord user_models.PasswordModel
		err := user_models.FindPasswordByUserID(record.GetID(), &passwordRecord)
		if err != nil {
			return err
		}

		if passwordRecord.ID != 0 {
			return &bolo.HTTPError{
				Code:     http.StatusUnprocessableEntity,
				Message:  "invalid password",
				Internal: errors.New("ChangeOwnPassword forbidden: password record not found"),
			}
		}
	} else {
		valid, err := record.ValidPassword(body.Password)
		if err != nil {
			return err
		}

		if !valid {
			return &bolo.HTTPError{
				Code:     http.StatusUnprocessableEntity,
				Message:  "Invalid password, current password is wrong",
				Internal: errors.New("ChangeOwnPassword forbidden"),
			}
		}
	}

	err := record.SetPassword(body.NewPassword)
	if err != nil {
		return err
	}

	// Notify the password change:
	emails.SendEmailAsync(&emails.EmailOpts{
		To:           record.Email,
		TemplateName: "AuthChangePasswordEmail",
		Variables: emails.TemplateVariables{
			"displayName": record.DisplayName,
			"siteName":    system_settings.Get("siteName"),
			"siteUrl":     ctx.AppOrigin,
			"username":    record.Username,
		},
	})

	c.Set("passwordChanged", true)
	return ctl.ChangeOwnPassword_Page(c)
}

// Set user password, usualy used by admins
// Current version dont need validation
func (ctl *AuthController) SetPassword(c echo.Context) error {
	userID := c.Param("userID")
	ctx := c.(*bolo.RequestContext)

	body := SetPasswordBody{}

	if err := c.Bind(&body); err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Debug("AuthController.SetPassword error on bind")

		if _, ok := err.(*echo.HTTPError); ok {
			return err
		}
		return c.NoContent(http.StatusBadRequest)
	}

	if err := c.Validate(&body); err != nil {
		return err
	}

	if !ctx.Can("manage_users") {
		return &bolo.HTTPError{
			Code:     http.StatusForbidden,
			Message:  "Forbidden",
			Internal: errors.New("SetPassword forbidden"),
		}
	}

	var record user_models.UserModel
	err := user_models.UserFindOne(userID, &record)
	if err != nil {
		return err
	}

	if record.ID == 0 {
		logrus.WithFields(logrus.Fields{
			"id": userID,
		}).Debug("AuthController.ChangePassword user not found")
		return echo.NotFoundHandler(c)
	}

	err = user_models.UpdateUserPasswordByUserID(userID, body.NewPassword)
	if err != nil {
		return err
	}
	return c.JSON(200, struct{}{})
}

type ForgotPasswordChange_RequestBody struct {
	Email string `json:"email" form:"email" validate:"required,email"`
}

// ForgotPassword_Request - step 1 to change password
func (ctl *AuthController) ForgotPassword_Request(c echo.Context) error {
	ctx := c.(*bolo.RequestContext)

	body := ForgotPasswordChange_RequestBody{}
	if err := c.Bind(&body); err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Debug("AuthController.ForgotPasswordChange_Request error on bind")

		if _, ok := err.(*echo.HTTPError); ok {
			return err
		}
		return c.NoContent(http.StatusBadRequest)
	}

	if err := c.Validate(&body); err != nil {
		return err
	}

	u := user_models.UserModel{}
	err := user_models.UserFindOneByUsername(body.Email, &u)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return errors.Wrap(err, "AuthController.ForgotPasswordChange_Request error on find user")
	}

	if u.ID == 0 {
		return echo.NotFoundHandler(c)
	}

	if u.Blocked {
		return &bolo.HTTPError{
			Code:     http.StatusNotFound,
			Message:  "auth.forgot-password.user.not-found",
			Internal: errors.New("auth.forgot-password.user.not-found user id=" + u.GetID()),
		}
	}

	authToken, err := user_models.CreateAuthToken(u.GetID(), "resetPassword")
	if err != nil {
		return errors.Wrap(err, "AuthController.ForgotPasswordChange_Request error on create auth token")
	}

	if ctl.App.GetPlugin("emails") != nil {
		email, err := emails.NewEmailWithTemplate(&emails.EmailOpts{
			To:           u.Email,
			TemplateName: "AuthResetPasswordEmail",
			Variables: emails.TemplateVariables{
				"displayName":      u.DisplayName,
				"siteName":         system_settings.Get("siteName"),
				"siteUrl":          ctx.AppOrigin,
				"resetPasswordUrl": authToken.GetResetUrl(ctx),
				"token":            authToken.Token,
			},
		})
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": fmt.Errorf("%+v", err),
			}).Error("AuthController.ForgotPasswordChange_Request error on create email")
		} else {
			err = email.Send()
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"error": fmt.Errorf("%+v", err),
				}).Error("AuthController.ForgotPasswordChange_Request error on send email")
			}
		}
	}

	return c.JSON(200, struct{}{})
}

// ForgotPassword_RequestWithIdentifier - Step 1 to change password
func (ctl *AuthController) ForgotPassword_RequestWithIdentifier(c echo.Context) (err error) {
	ctx := c.(*bolo.RequestContext)

	ctx.Set("template", "auth/forgot-password-request-with-identifier")
	mt := c.Get("metatags").(*metatags.HTMLMetaTags)
	ctx.Title = "Senha perdida - resetar"
	mt.Title = "Senha perdida - resetar | Monitor do Mercado"

	if ctx.Request().Method == "POST" {
		body := ForgotPasswordChange_RequestBody{}
		if err := c.Bind(&body); err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Debug("AuthController.ForgotPassword_RequestWithIdentifier error on bind")

			if _, ok := err.(*echo.HTTPError); ok {
				return err
			}

			return &bolo.HTTPError{
				Code:     http.StatusBadRequest,
				Message:  "invalid param or data format",
				Internal: errors.Wrap(err, "invalid param or data format"),
			}
		}

		if err := c.Validate(body); err != nil {
			if _, ok := err.(*echo.HTTPError); ok {
				return err
			}
			return err
		}

		u := user_models.UserModel{}
		err = user_models.UserFindOneByUsername(body.Email, &u)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.Wrap(err, "AuthController.ForgotPassword_RequestWithIdentifier error on find user")
		}

		if u.ID == 0 {
			return bolo.MinifiAndRender(http.StatusOK, ctx.Get("template").(string), &bolo.TemplateCTX{
				Ctx: ctx,
			}, ctx)
		}

		if u.Blocked {
			return &bolo.HTTPError{
				Code:     http.StatusNotFound,
				Message:  "auth.forgot-password.user.not-found",
				Internal: errors.New("auth.forgot-password.user.not-found user id=" + u.GetID()),
			}
		}

		authToken, err := user_models.CreateAuthToken(u.GetID(), "resetPassword")
		if err != nil {
			return errors.Wrap(err, "AuthController.ForgotPassword_RequestWithIdentifier error on create auth token")
		}

		emailSent := false
		if ctl.App.GetPlugin("emails") != nil {
			emailSent, err = SendRequestResetPasswordEmail(ctx, authToken, &u)
			if err != nil {
				return errors.Wrap(err, "AuthController.ForgotPassword_RequestWithIdentifier error on send reset password email")
			}
		}

		if emailSent {
			ctx.AddResponseMessage(&bolo.ResponseMessage{
				Message: "E-mail enviado com sucesso. Verifique sua caixa de entrada e siga as instruções para resetar sua senha.",
				Type:    "success",
			})
		}

		switch ctx.GetResponseContentType() {
		case "application/json":
			return c.JSON(http.StatusOK, bolo.EmptyResponse{})
		}
	}

	return bolo.MinifiAndRender(http.StatusOK, ctx.Get("template").(string), &bolo.TemplateCTX{
		Ctx: ctx,
	}, ctx)
}

func SendRequestResetPasswordEmail(ctx *bolo.RequestContext, authToken *user_models.AuthTokenModel, u *user_models.UserModel) (bool, error) {
	var err error

	userName := u.DisplayName
	if userName == "" {
		userName = u.FullName
	}

	email, err := emails.NewEmailWithTemplate(&emails.EmailOpts{
		To:           u.Email,
		TemplateName: "AuthResetPasswordEmail",
		Variables: emails.TemplateVariables{
			"userName":         userName,
			"siteName":         system_settings.Get("siteName"),
			"siteUrl":          ctx.AppOrigin,
			"resetPasswordUrl": authToken.GetResetUrl(ctx),
			"token":            authToken.Token,
		},
	})
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": fmt.Errorf("%+v", err),
		}).Error("AuthController.ForgotPassword_RequestWithIdentifier error on create email")
		return false, err
	}
	err = email.QueueToSend()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": fmt.Errorf("%+v", err),
		}).Error("AuthController.ForgotPassword_RequestWithIdentifier error on QueueToSend email")
		return false, nil
	}

	return true, nil
}

// ForgotPassword_ResetPage - step 2 to change password
func (ctl *AuthController) ForgotPassword_ResetPage(c echo.Context) error {
	// var err error
	ctx := c.(*bolo.RequestContext)
	userID := c.Param("userID")
	token := c.QueryParam("t")

	ctx.Set("template", "auth/forgot-password-reset-page")

	if userID == "" || token == "" {
		// TODO!>
		return c.NoContent(http.StatusBadRequest)
	}

	u := user_models.UserModel{}
	err := user_models.UserFindOne(userID, &u)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return errors.Wrap(err, "AuthController.ForgotPasswordChange_Request error on find user")
	}

	if u.ID == 0 {
		return ctx.Redirect(http.StatusTemporaryRedirect, "/auth/forgot-password")
	}

	if u.Blocked {
		return &bolo.HTTPError{
			Code:     http.StatusNotFound,
			Message:  "auth.forgot-password.user.not-found",
			Internal: errors.New("auth.forgot-password.user.blocked user id=" + u.GetID()),
		}
	}

	valid, _, err := user_models.ValidAuthToken(userID, token)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return errors.Wrap(err, "AuthController.ForgotPasswordChange_Request error on find auth token")
	}

	if !valid {
		ctx.Set("messages", []struct {
			Type    string
			Message string
		}{
			{
				Type:    "error",
				Message: "auth.forgot-password.token.invalid",
			},
		})

		return &bolo.HTTPError{
			Code:     http.StatusNotFound,
			Message:  "auth.forgot-password.token.not-found",
			Internal: errors.New("auth.forgot-password.token.invelid token=" + token),
		}
	}

	mt := c.Get("metatags").(*metatags.HTMLMetaTags)
	ctx.Title = "Resetar senha"
	mt.Title = "Resetar senha | Monitor do Mercado"

	if ctx.Request().Method == "POST" {
		body := ForgotPasswordChange_RequestBody{}
		if err := c.Bind(&body); err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Debug("AuthController.ForgotPasswordChange_Request error on bind")

			if _, ok := err.(*echo.HTTPError); ok {
				return err
			}

			return &bolo.HTTPError{
				Code:     http.StatusBadRequest,
				Message:  "invalid param or data format",
				Internal: errors.Wrap(err, "invalid param or data format"),
			}
		}

		if err := c.Validate(body); err != nil {
			if _, ok := err.(*echo.HTTPError); ok {
				return err
			}
			return err
		}

	}

	return bolo.MinifiAndRender(http.StatusOK, "auth/forgot-password-reset-page", &bolo.TemplateCTX{
		Ctx: ctx,
	}, ctx)
}

// ForgotPassword_Process - step 3 to change password
func (ctl *AuthController) ForgotPassword_Process(c echo.Context) error {

	return nil
}

type NewAuthControllerCFG struct {
	App bolo.App
}

func NewAuthController(cfg *NewAuthControllerCFG) *AuthController {
	return &AuthController{App: cfg.App}
}
