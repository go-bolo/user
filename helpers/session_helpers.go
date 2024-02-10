package user_helpers

import (
	"github.com/go-bolo/bolo"
	"github.com/gorilla/sessions"
)

func GetSessionOptions(app bolo.App) *sessions.Options {
	cfgs := app.GetConfiguration()

	return &sessions.Options{
		Path:     cfgs.GetF("SITE_SESSION_PATH", "/"),
		MaxAge:   cfgs.GetIntF("SITE_SESSION_MAX_AGE", 86400*7),
		HttpOnly: cfgs.GetBoolF("SITE_SESSION_HTTP_ONLY", false),
	}
}
