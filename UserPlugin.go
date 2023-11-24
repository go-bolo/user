package user

import (
	"github.com/go-bolo/bolo"
	migrations_user "github.com/go-bolo/user/migrations/user"
	"github.com/gookit/event"
	"github.com/sirupsen/logrus"
)

type UserPlugin struct {
	bolo.Pluginer
	Controller *Controller

	Name string
}

func (r *UserPlugin) GetName() string {
	return r.Name
}

func (r *UserPlugin) Init(app bolo.App) error {
	logrus.Debug(r.GetName() + " Init")

	r.Controller = NewController(&ControllerCfg{App: app})

	app.GetEvents().On("bindRoutes", event.ListenerFunc(func(e event.Event) error {
		return r.BindRoutes(app)
	}), event.Normal)

	app.GetEvents().On("setTemplateFunctions", event.ListenerFunc(func(e event.Event) error {
		return r.setTemplateFunctions(app)
	}), event.Normal)

	return nil
}

func (r *UserPlugin) BindRoutes(app bolo.App) error {
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

	// 'get /acl/user/:userId([0-9]+)/roles': {
	// 	'titleHandler'  : 'i18n',
	// 	'titleI18n'     : 'admin.user.roles',
	// 	'controller'    : 'role',
	// 	'action'        : 'updateUserRoles',
	// 	'model'         : 'user',
	// 	'permission'    : 'manage_role',
	// 	'responseType'  : 'json'
	// },
	// 'post /acl/role/:roleName/permissions/:permissionName': {
	// 	'controller'    : 'role',
	// 	'action'        : 'addPermissionToRole',
	// 	'permission'    : 'manage_permissions'
	// },
	// 'delete /acl/role/:roleName/permissions/:permissionName': {
	// 	'controller'    : 'role',
	// 	'action'        : 'removePermissionFromRole',
	// 	'permission'    : 'manage_permissions'
	// },
	// 'get /acl/role': {
	// 	'name'          : 'admin.role.find',
	// 	'controller'    : 'role',
	// 	'action'        : 'find',
	// 	'permission'    : 'manage_permissions',
	// 	'responseType'  : 'json'
	// },
	// 'post /acl/role': {
	// 	'controller'    : 'role',
	// 	'action'        : 'find',
	// 	'permission'    : 'manage_permissions',
	// 	'responseType'  : 'json'
	// }

	return nil
}

func (p *UserPlugin) GetMigrations() []*bolo.Migration {
	return []*bolo.Migration{
		migrations_user.GetInitMigration(),
	}
}

func (p *UserPlugin) setTemplateFunctions(app bolo.App) error {
	app.SetTemplateFunction("renderClientAppConfigs", renderClientAppConfigs)
	return nil
}

type UserPluginCfg struct{}

func NewUserPlugin(cfg *UserPluginCfg) *UserPlugin {
	p := UserPlugin{Name: "user"}
	return &p
}
