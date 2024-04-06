package user

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-bolo/bolo"
	user_models "github.com/go-bolo/user/models"
	user_oauth2_password "github.com/go-bolo/user/oauth2_password"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

type FacebookAuthController struct {
}

func (ctl *FacebookAuthController) LoginWithFacebookAppCode(c echo.Context) error {
	ctx := c.(*bolo.RequestContext)

	var OAuth2Config = GetFacebookOAuthConfig(ctx)
	if OAuth2Config.ClientID == "" || OAuth2Config.ClientSecret == "" {
		return &bolo.HTTPError{
			Code:     http.StatusNotFound,
			Message:  "facebook auth configuration not set",
			Internal: errors.New("facebook auth configuration not set"),
		}
	}

	ctx.SetResponseContentType("application/json")

	var body LoginWithFacebookAppCodeBodyRequest
	if err := c.Bind(&body); err != nil {
		if _, ok := err.(*echo.HTTPError); ok {
			return err
		}
		return c.NoContent(http.StatusNotFound)
	}

	token, err := OAuth2Config.Exchange(context.Background(), body.Code)
	if err != nil || token == nil {
		logrus.WithFields(logrus.Fields{
			"err": err,
		}).Error("LoginWithFacebookAppCode: error on exchange token")

		return &bolo.HTTPError{
			Code:     http.StatusUnauthorized,
			Message:  "Invalid token",
			Internal: fmt.Errorf("error on exchange token: %w", err),
		}
	}

	fbUserDetails, fbUserDetailsError := GetUserInfoFromFacebook(token.AccessToken, ctx)
	if fbUserDetailsError != nil {
		logrus.WithFields(logrus.Fields{
			"err": err,
		}).Error("LoginWithFacebookAppCode: error on get user info from facebook")

		return &bolo.HTTPError{
			Code:     http.StatusUnauthorized,
			Message:  "Invalid token",
			Internal: fmt.Errorf("error on get user info from facebook: %w", fbUserDetailsError),
		}
	}

	u, authTokenError := FindOrCreateUserFromFacebook(fbUserDetails, ctx)
	if authTokenError != nil {
		d, _ := json.Marshal(fbUserDetails)

		logrus.WithFields(logrus.Fields{
			"err":  err,
			"data": d,
		}).Error("LoginWithFacebookAppCode: error on FindOrCreateUserFromFacebook")

		return &bolo.HTTPError{
			Code:     http.StatusUnauthorized,
			Message:  "Invalid token",
			Internal: fmt.Errorf("FindOrCreateUserFromFacebook: %w", authTokenError),
		}
	}

	// Authenticate user:
	data, err := user_oauth2_password.Oauth2GenerateAndSaveToken(ctx, u)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"err": err,
		}).Error("LoginWithFacebookAppCode: error on generate and save token")

		return &bolo.HTTPError{
			Code:     http.StatusBadRequest,
			Message:  "Invalid token",
			Internal: fmt.Errorf("error on generate and save token: %w", err),
		}
	}

	resp := oauth2PasswordJSONResponse{
		AccessToken:  &data.AccessToken,
		RefreshToken: &data.RefreshToken,
		ExpiresIn:    &data.ExpiresIn,
		User:         u,
	}

	return c.JSON(200, &resp)
}

type NewFacebookAuthControllerCFG struct {
	App bolo.App
}

func NewFacebookAuthController(cfg *NewFacebookAuthControllerCFG) *FacebookAuthController {
	return &FacebookAuthController{}
}

// ErrorResponse is struct for sending error message with code.
type ErrorResponse struct {
	Code    int
	Message string
}

// SuccessResponse is struct for sending error message with code.
type SuccessResponse struct {
	Code     int
	Message  string
	Response interface{}
}

// Claims is  a struct that will be encoded to a JWT.
// jwt.StandardClaims is an embedded type to provide expiry time
type Claims struct {
	Email string
	jwt.StandardClaims
}

// UserDetails is struct used for user details
type UserDetails struct {
	Name     string
	Email    string
	Password string
}

// FacebookUserDetails is struct used for user details
type FacebookUserDetails struct {
	ID      string               `json:"id"`
	Name    string               `json:"name"`
	Email   string               `json:"email"`
	Picture *FacebookUserPicture `json:"picture"`
}

type FacebookUserPicture struct {
	Data struct {
		Height       int    `json:"height"`
		IsSilhouette bool   `json:"is_silhouette"`
		URL          string `json:"url"`
		Width        int    `json:"width"`
	} `json:"data"`
}

type LoginWithFacebookAppCodeBodyRequest struct {
	Code        string `json:"code"`
	RedirectUri string `json:"redirect_uri"`
}

// GetFacebookOAuthConfig will return the config to call facebook Login
func GetFacebookOAuthConfig(ctx *bolo.RequestContext) *oauth2.Config {
	cfgs := ctx.App.GetConfiguration()
	return &oauth2.Config{
		ClientID:     cfgs.Get("SITE_FACEBOOK_APP_ID"),
		ClientSecret: cfgs.Get("FACEBOOK_CLIENT_SECRET"),
		Endpoint:     facebook.Endpoint,
		RedirectURL:  cfgs.Get("FACEBOOK_REDIRECT_URI"),
	}
}

// GetUserInfoFromFacebook will return information of user which is fetched from facebook
func GetUserInfoFromFacebook(token string, ctx *bolo.RequestContext) (FacebookUserDetails, error) {
	var fbUserDetails FacebookUserDetails
	facebookUserDetailsRequest, _ := http.NewRequest("GET", "https://graph.facebook.com/me?fields=id,name,email&access_token="+token, nil)
	facebookUserDetailsResponse, facebookUserDetailsResponseError := http.DefaultClient.Do(facebookUserDetailsRequest)

	if facebookUserDetailsResponseError != nil {
		return FacebookUserDetails{}, errors.New("error occurred while getting information from facebook")
	}

	decoder := json.NewDecoder(facebookUserDetailsResponse.Body)
	decoderErr := decoder.Decode(&fbUserDetails)
	defer facebookUserDetailsResponse.Body.Close()

	if decoderErr != nil {
		return FacebookUserDetails{}, errors.New("error occurred while getting information from facebook")
	}

	return fbUserDetails, nil
}

// SignInUser Used for Signing In the Users
func FindOrCreateUserFromFacebook(facebookUserDetails FacebookUserDetails, ctx *bolo.RequestContext) (*user_models.UserModel, error) {
	if facebookUserDetails == (FacebookUserDetails{}) {
		return nil, errors.New("FindOrCreateUserFromFacebook user details can't be empty")
	}

	if facebookUserDetails.Email == "" {
		return nil, errors.New("FindOrCreateUserFromFacebook last name can't be empty")
	}

	if facebookUserDetails.Name == "" {
		return nil, errors.New("FindOrCreateUserFromFacebook password can't be empty")
	}

	u := user_models.UserModel{}
	err := user_models.UserFindOneByUsername(facebookUserDetails.Email, &u)
	if err != nil {
		return nil, errors.New("FindOrCreateUserFromFacebook user not found")
	}

	if u.ID == 0 {
		// user not found, create new user
		u.Username = facebookUserDetails.ID
		u.Email = facebookUserDetails.Email
		u.DisplayName = facebookUserDetails.Name
		u.FullName = facebookUserDetails.Name
		u.Active = true
		u.AcceptTerms = false

		err = u.Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("FindOrCreateUserFromFacebook error on save user: %w", err)
		}
	}

	return &u, nil
}

type oauth2PasswordJSONResponse struct {
	AccessToken  *string                `json:"access_token"`
	RefreshToken *string                `json:"refresh_token"`
	ExpiresIn    *int64                 `json:"expires_in"`
	User         *user_models.UserModel `json:"user"`
}
