package user_oauth2_jwt

import (
	"github.com/go-bolo/bolo"
	user_oauth2_password "github.com/go-bolo/user/oauth2_password"
	"github.com/gookit/event"
	"github.com/sirupsen/logrus"
)

// Oauth2JWTPlugin é o subplugin de auth com access JWT stateless: emite e
// valida access tokens JWT (HS256) nos endpoints /auth/jwt/*, mantendo o
// refresh opaco rotativo do oauth2_password. Ativação/desativação =
// instalar/desinstalar o subplugin no consumidor (desinstalar é o
// kill-switch: rotas /auth/jwt somem e JWTs deixam de validar).
type Oauth2JWTPlugin struct {
	bolo.Pluginer

	Name string
}

func (p *Oauth2JWTPlugin) GetName() string {
	return p.Name
}

func (p *Oauth2JWTPlugin) Init(app bolo.App) error {
	logrus.Debug(p.GetName() + ".Init Running")

	app.GetEvents().On("configuration", event.ListenerFunc(func(e event.Event) error {
		// storage compartilhado com o oauth2_password (mesmo Redis/DB):
		// inicializar aqui cobre o consumidor que registre apenas o
		// subplugin; a chamada é idempotente
		user_oauth2_password.InitStorage(app)
		InitConfig(app)
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

func (p *Oauth2JWTPlugin) bindMiddlewares(app bolo.App) error {
	logrus.Debug(p.GetName() + " bindMiddlewares")

	router := app.GetRouter()
	router.Use(jwtAuthenticationMiddleware())

	return nil
}

func (r *Oauth2JWTPlugin) BindRoutes(app bolo.App) error {
	logrus.Debug(r.GetName() + " BindRoutes")

	router := app.SetRouterGroup("auth_jwt", "/auth/jwt")
	router.POST("/authenticate", AuthenticationJWTHandler)
	router.POST("/refresh-token", RefreshTokenJWTHandler)

	return nil
}

func (r *Oauth2JWTPlugin) GetMigrations() []*bolo.Migration {
	return []*bolo.Migration{}
}

// PluginCfgs configura o subplugin. Revogação (RFC 7009) e logout continuam
// nos endpoints existentes (/auth/grant-password/revoke e /auth/logout).
type PluginCfgs struct {
	// OnLoginActivity é chamado após authenticate e refresh bem-sucedidos
	// (paridade com os handlers do consumidor; o mm registra atividade de
	// login). Falhas do hook são apenas logadas.
	OnLoginActivity func(userID uint64) error
}

func NewPlugin(cfg *PluginCfgs) *Oauth2JWTPlugin {
	p := Oauth2JWTPlugin{Name: "AuthOauth2JWT"}

	loginActivityHook = nil
	if cfg != nil && cfg.OnLoginActivity != nil {
		loginActivityHook = cfg.OnLoginActivity
	}

	return &p
}
