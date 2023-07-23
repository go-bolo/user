package user

import (
	"net/http"

	"github.com/go-bolo/bolo"
	"github.com/gookit/event"
)

type Plugin struct {
	bolo.Plugin
	Controller *Controller

	Name string
}

func (r *Plugin) GetName() string {
	return r.Name
}

func (r *Plugin) Init(app bolo.App) error {
	app.GetLogger().Debug(r.GetName() + " Init")

	r.Controller = NewController(&ControllerCfg{})

	app.GetEvents().On("bindRoutes", event.ListenerFunc(func(e event.Event) error {
		return r.BindRoutes(app)
	}), event.Normal)

	app.GetEvents().On("setTemplateFunctions", event.ListenerFunc(func(e event.Event) error {
		return r.setTemplateFunctions(app)
	}), event.Normal)

	return nil
}

func (r *Plugin) BindRoutes(app bolo.App) error {
	app.GetLogger().Debug(r.GetName() + " BindRoutes")

	ctl := r.Controller

	app.SetRoute("urls_query", &bolo.Route{
		Method:   http.MethodGet,
		Path:     "/user-settings",
		Action:   UserSettingsHandler,
		Template: "urls/find",
	})

	app.SetRoute("get_acl_permissions", &bolo.Route{
		Method: http.MethodGet,
		Path:   "/acl/permission",
		Action: ctl.GetUserRolesAndPermissions,
	})

	app.SetRoute("get_user_roles", &bolo.Route{
		Method: http.MethodPost,
		Path:   "/acl/user/:userID/roles",
		Action: ctl.UpdateUserRoles,
	})

	app.SetResource(&bolo.Resource{
		Name:       "user",
		Path:       "/api/user",
		Controller: r.Controller,
	})

	return nil
}

func (p *Plugin) setTemplateFunctions(app bolo.App) error {
	app.SetTemplateFunction("renderClientAppConfigs", renderClientAppConfigs)
	return nil
}

type PluginCfg struct{}

func NewPlugin(cfg *PluginCfg) *Plugin {
	p := Plugin{Name: "user"}
	return &p
}
