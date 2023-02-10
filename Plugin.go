package user

import (
	"github.com/go-catupiry/catu"
	"github.com/gookit/event"
	"github.com/sirupsen/logrus"
)

type Plugin struct {
	catu.Pluginer
	Controller *Controller

	Name string
}

func (r *Plugin) GetName() string {
	return r.Name
}

func (r *Plugin) Init(app catu.App) error {
	logrus.Debug(r.GetName() + " Init")

	r.Controller = NewController(&ControllerCfg{})

	app.GetEvents().On("bindRoutes", event.ListenerFunc(func(e event.Event) error {
		return r.BindRoutes(app)
	}), event.Normal)

	app.GetEvents().On("setTemplateFunctions", event.ListenerFunc(func(e event.Event) error {
		return r.setTemplateFunctions(app)
	}), event.Normal)

	return nil
}

func (r *Plugin) BindRoutes(app catu.App) error {
	logrus.Debug(r.GetName() + " BindRoutes")

	ctl := r.Controller

	router := app.GetRouter()
	router.GET("/user-settings", UserSettingsHandler)

	aclRouter := app.SetRouterGroup("acl", "/acl")
	aclRouter.GET("/permission", ctl.GetUserRolesAndPermissions)
	aclRouter.POST("/user/:userID/roles", ctl.UpdateUserRoles)

	app.SetRouterGroup("user", "/api/user")
	routerUser := app.GetRouterGroup("user")
	app.SetResource("user", r.Controller, routerUser)

	return nil
}

func (p *Plugin) setTemplateFunctions(app catu.App) error {
	app.SetTemplateFunction("renderClientAppConfigs", renderClientAppConfigs)
	return nil
}

type PluginCfg struct{}

func NewPlugin(cfg *PluginCfg) *Plugin {
	p := Plugin{Name: "user"}
	return &p
}
