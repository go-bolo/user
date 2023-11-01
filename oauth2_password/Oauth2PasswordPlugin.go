package user_oauth2_password

import (
	"github.com/go-bolo/bolo"
	"github.com/gookit/event"
	"github.com/sirupsen/logrus"
)

type Oauth2PasswordPlugin struct {
	bolo.Pluginer

	Name string
}

func (p *Oauth2PasswordPlugin) GetName() string {
	return p.Name
}

func (p *Oauth2PasswordPlugin) Init(app bolo.App) error {
	logrus.Debug(p.GetName() + ".Init Running")

	app.GetEvents().On("configuration", event.ListenerFunc(func(e event.Event) error {
		initStorage(app)
		return nil
	}), event.Normal)

	app.GetEvents().On("bindMiddlewares", event.ListenerFunc(func(e event.Event) error {
		return p.bindMiddlewares(app)
	}), event.Normal)

	app.GetEvents().On("bindRoutes", event.ListenerFunc(func(e event.Event) error {
		return p.BindRoutes(app)
	}), event.Normal)

	return nil
}

func (p *Oauth2PasswordPlugin) bindMiddlewares(app bolo.App) error {
	logrus.Debug(p.GetName() + " bindMiddlewares")

	router := app.GetRouter()
	router.Use(oauth2AuthenticationMiddleware())

	return nil
}

func (r *Oauth2PasswordPlugin) BindRoutes(app bolo.App) error {
	logrus.Debug(r.GetName() + " BindRoutes")

	router := app.SetRouterGroup("auth", "/auth")
	router.POST("/grant-password/authenticate", AuthenticationOauth2PasswordHandler)
	// router.POST("/auth/logout", HealthCheck)
	// router.POST("/auth/forgot-password", HealthCheck)
	// router.GET("/auth/forgot-password", HealthCheck)

	return nil
}

func (r *Oauth2PasswordPlugin) GetMigrations() []*bolo.Migration {
	return []*bolo.Migration{}
}

type PluginCfgs struct{}

func NewPlugin(cfg *PluginCfgs) *Oauth2PasswordPlugin {
	p := Oauth2PasswordPlugin{Name: "AuthOauth2Password"}
	return &p
}
