package user

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-bolo/bolo"
	user_models "github.com/go-bolo/user/models"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

// Init - Start the redis session connection
func Init(app bolo.App) {
	initRedisSession()
}

func isPublicRoute(url string) bool {
	return strings.HasPrefix(url, "/health") || strings.HasPrefix(url, "/public")
}

func HandleRequestSessionAuthentication(c echo.Context) error {
	var err error
	ctx := c.(*bolo.RequestContext)

	if !ctx.IsAuthenticated {
		err = sessionAuthenticationHandler(c)
		if err != nil {
			return err
		}
	}

	return nil
}

type SessionData struct {
	UserID string `json:"userId"`
}

func (sd *SessionData) ToJSON() string {
	jsonData, _ := json.Marshal(sd)
	return string(jsonData)
}

func sessionAuthenticationHandler(c echo.Context) error {
	ctx := c.(*bolo.RequestContext)
	authPlugin := ctx.App.GetPlugin("auth").(*AuthPlugin)

	sess, err := session.Get("session", c)
	if err != nil {
		if !strings.Contains(err.Error(), "session store not found") {
			return fmt.Errorf("error on get session: %w", err)
		}
	}

	if ctx.ENV == "production" {
		sess.Options.Secure = true
	}

	if sess.Values["uid"] == nil {
		seesC, _ := c.Cookie("session")
		if seesC != nil && seesC.Value != "" {
			// the session cookie still exists then delete it:
			seesC.Expires = time.Now().AddDate(0, -1, 0)
			c.SetCookie(seesC)
		}
		return nil // not authenticated with sessions
	}

	userId := sess.Values["uid"].(string)
	savedUser := user_models.UserModel{}

	err = user_models.UserFindOne(userId, &savedUser)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"err":    err,
			"value":  sess.Values,
			"userID": userId,
		}).Error("sessionAuthenticationHandler error on find user")
	}

	if savedUser.ID != 0 {
		logrus.WithFields(logrus.Fields{
			"userId": savedUser.ID,
		}).Debug("sessionAuthenticationHandler user authenticated")

		if ctx.AuthenticatedUser == nil {
			ctx.SetAuthenticatedUserAndFillRoles(&savedUser)
		}

		ctx.Session.UserID = ctx.AuthenticatedUser.GetID()
		ctx.IsAuthenticated = true
	}

	if authPlugin.SessionResave {
		sess.Options = authPlugin.SessionOptions
		err = sess.Save(c.Request(), c.Response())
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"err":    err,
				"value":  sess.Values,
				"userID": userId,
			}).Error("sessionAuthenticationHandler error on save session")
		}
	}
	return nil
}
