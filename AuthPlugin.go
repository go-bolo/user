package user

import (
	"context"
	"fmt"
	"log"

	"github.com/go-bolo/bolo"
	"github.com/go-playground/validator/v10"
	"github.com/gookit/event"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/rbcervilla/redisstore/v9"
	"github.com/sirupsen/logrus"
	"gopkg.in/boj/redistore.v1"
)

type AuthPlugin struct {
	bolo.Pluginer
	// a map with valid reset page prefix:
	ResetPrefixNames map[string]string

	AuthController         *AuthController
	SessionController      *SessionController
	FacebookAuthController *FacebookAuthController

	Name string

	SessionStore  sessions.Store // TODO! add more session store options as plugins
	SessionResave bool
}

func (p *AuthPlugin) GetName() string {
	return p.Name
}

func (p *AuthPlugin) Init(app bolo.App) error {
	logrus.Debug(p.GetName() + ".Init Running")

	p.AuthController = NewAuthController(&NewAuthControllerCFG{App: app})
	p.SessionController = NewSessionController(&NewSessionControllerCFG{App: app})
	p.FacebookAuthController = NewFacebookAuthController(&NewFacebookAuthControllerCFG{App: app})

	app.GetEvents().On("install", event.ListenerFunc(func(e event.Event) error {
		InstallAuth(app)
		return nil
	}), event.Normal)

	app.GetEvents().On("configuration", event.ListenerFunc(func(e event.Event) error {
		Init(app)
		return nil
	}), event.Normal)

	app.GetEvents().On("bindMiddlewares", event.ListenerFunc(func(e event.Event) error {
		return p.bindMiddlewares(app)
	}), event.Normal)

	app.GetEvents().On("bindRoutes", event.ListenerFunc(func(e event.Event) error {
		return p.BindRoutes(app)
	}), event.Normal)

	app.GetEvents().On("setTemplateFunctions", event.ListenerFunc(func(e event.Event) error {
		return p.setTemplateFunctions(app)
	}), event.Normal)

	app.GetEvents().On("http-error", event.ListenerFunc(func(e event.Event) error {
		return p.OnHTTPError(app, e)
	}), event.Normal)

	// on bootstrap
	app.GetEvents().On("bootstrap", event.ListenerFunc(func(e event.Event) error {
		return p.Bootstrap(app)
	}), event.High)

	app.GetEvents().On("close", event.ListenerFunc(func(e event.Event) error {
		return p.OnClose(app)
	}), event.Normal)

	return nil
}

func (p *AuthPlugin) bindMiddlewares(app bolo.App) error {
	logrus.Debug("AuthPlugin.bindMiddlewares " + p.GetName())

	var err error

	cfgs := app.GetConfiguration()

	store, err := redisstore.NewRedisStore(context.Background(), SessionDBWriter)
	if err != nil {
		log.Fatal("failed to create redis store: ", err)
	}

	p.SessionStore = store
	p.SessionResave = cfgs.GetBoolF("SITE_SESSION_RESAVE", true)

	router := app.GetRouter()
	router.Use(session.Middleware(p.SessionStore))
	router.Use(sessionAuthenticationMiddleware())

	return nil
}

func (r *AuthPlugin) BindRoutes(app bolo.App) error {
	logrus.Debug(r.GetName() + " BindRoutes")

	router := app.SetRouterGroup("auth", "/auth")
	router.GET("/change-password", r.AuthController.ChangeOwnPassword_Page) // ok
	router.POST("/change-password", r.AuthController.ChangeOwnPassword)     // ok
	router.POST("/logout", r.AuthController.Logout)
	router.GET("/logout", r.AuthController.Logout)
	// Step 1 to reset password
	router.GET("/forgot-password", r.AuthController.ForgotPassword_RequestWithIdentifier)
	router.POST("/forgot-password", r.AuthController.ForgotPassword_RequestWithIdentifier)
	// Step 2 to reset password
	router.GET("/:userID/forgot-password/reset", r.AuthController.ForgotPassword_ResetPage)
	router.POST("/:userID/forgot-password/reset", r.AuthController.ForgotPassword_ResetPage)

	routerV2 := app.SetRouterGroup("auth_v2", "/api/v2/auth")
	routerV2.POST("/forgot-password/process", r.AuthController.ForgotPassword_Process)
	routerV2.POST("/change-password", r.AuthController.ChangeOwnPasswordApi)

	mainRouter := app.GetRouter()
	mainRouter.GET("/login", r.SessionController.LoginPage) // ok
	mainRouter.POST("/login", r.SessionController.Login)    // ok
	mainRouter.GET("/logout", r.SessionController.Logout)
	mainRouter.POST("/logout", r.SessionController.Logout)

	router.GET("/current", r.AuthController.GetCurrentUser) // ok
	// Compatibility with we.js:
	router.POST("/:userID/new-password", r.AuthController.SetPassword)
	router.POST("/:userID/set-password", r.AuthController.SetPassword)

	// social auths:
	fbAuthCtl := r.FacebookAuthController
	mainRouter.POST("/auth/facebook/app-login-code", fbAuthCtl.LoginWithFacebookAppCode)
	return nil
}

func (p *AuthPlugin) setTemplateFunctions(app bolo.App) error {
	app.SetTemplateFunction("renderFlashMessages", renderFlashMessages)

	return nil
}

func (p *AuthPlugin) OnHTTPError(app bolo.App, e event.Event) error {
	d := e.Data()

	if d["error"] == nil || d["echoContext"] == nil {
		return nil
	}

	err := d["error"].(error)
	c := d["echoContext"].(echo.Context)

	switch e := err.(type) {
	case *bolo.HTTPError:
		msg := fmt.Sprintf("%s", e.GetMessage())
		AddFlashMessage(c, &FlashMessage{
			Type:    "error",
			Message: msg,
		})

		return nil
	case validator.ValidationErrors:
		for _, errV := range e {
			AddFlashMessage(c, &FlashMessage{
				Type:    "error",
				Message: errV.Error(),
				Field:   errV.Field(),
				Tag:     errV.Tag(),
			})
		}
	}

	return nil
}

func (p *AuthPlugin) Bootstrap(app bolo.App) error {
	logrus.Debug("AuthPlugin.Bootstrap " + p.GetName())

	AddEmailTemplates(app)

	return nil
}

func (p *AuthPlugin) OnClose(app bolo.App) error {
	switch p.SessionStore.(type) {
	case *redistore.RediStore:
		return p.SessionStore.(*redistore.RediStore).Close()
	}

	return nil
}

func (p *AuthPlugin) GetMigrations() []*bolo.Migration {
	return []*bolo.Migration{}
}

type AuthPluginCfgs struct {
	ResetPrefixNames map[string]string
}

func NewAuthPlugin(cfg *AuthPluginCfgs) *AuthPlugin {
	p := AuthPlugin{
		Name:             "auth",
		ResetPrefixNames: cfg.ResetPrefixNames,
	}
	return &p
}
