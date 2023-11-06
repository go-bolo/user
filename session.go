package user

import (
	"fmt"
	"strings"

	"github.com/go-bolo/bolo"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

var sessionInitialized bool

var (
	// SessionDB - Redis session connection for writes
	SessionDBWriter *redis.Client
	// SessionDB - Redis session connection for gets
	SessionDBReader *redis.Client
)

// initRedisSession - Start the redis session connection
func initRedisSession() {
	cfgs := bolo.GetConfiguration()

	if !sessionInitialized {
		db := cfgs.GetIntF("SITE_CACHE_DB", 2)
		password := cfgs.GetF("SITE_SESSION_PASSWORD", "")
		addrWriter := cfgs.Get("SITE_SESSION_ADDR_WRITER")
		addrReader := cfgs.Get("SITE_SESSION_ADDR_READER")

		if SessionDBWriter == nil {
			SessionDBWriter = redis.NewClient(&redis.Options{
				Addr:     addrWriter, // ex localhost:6379
				Password: password,
				DB:       db,
			})
		}

		if SessionDBReader == nil {
			SessionDBReader = redis.NewClient(&redis.Options{
				Addr:     addrReader, // ex localhost:6379
				Password: password,
				DB:       db,
			})
		}

		sessionInitialized = true
	}
}

func SetUserSession(c echo.Context, user bolo.UserInterface) (*sessions.Session, error) {
	sess, err := session.Get("session", c)
	if err != nil {
		if !strings.Contains(err.Error(), "session store not found") {
			return nil, fmt.Errorf("error on get session: %w", err)
		}
	}

	ctx := c.(*bolo.RequestContext)
	authPlugin := ctx.App.GetPlugin("auth").(*AuthPlugin)

	sess.Options = authPlugin.SessionOptions

	sess.Values["uid"] = user.GetID()
	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		return nil, err
	}

	return sess, nil
}

func DeleteUserSession(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		if !strings.Contains(err.Error(), "session store not found") {
			return fmt.Errorf("DeleteUserSession: error on get session: %w", err)
		}
	}

	sess.Values["uid"] = 0
	sess.Options.MaxAge = -1
	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		return fmt.Errorf("error on delete session: %w", err)
	}

	return nil
}
