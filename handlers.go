package user

import (
	"strconv"

	"github.com/go-catupiry/catu"
	"github.com/go-catupiry/system_settings"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

type userSettingsJSONResponse struct {
	AppName           string               `json:"appName"`
	AppLogo           string               `json:"appLogo"`
	Site              string               `json:"site"`
	Hostname          string               `json:"hostname"`
	QueryDefaultLimit int                  `json:"queryDefaultLimit"`
	QueryMaxLimit     int                  `json:"queryMaxLimit"`
	Locales           []string             `json:"locales"`
	DefaultLocale     string               `json:"defaultLocale"`
	Date              clientSideDateFormat `json:"date"`
	Plugins           []string             `json:"plugins"`
	User              catu.UserInterface   `json:"authenticatedUser"`
	ActiveLocale      string               `json:"activeLocale"`
	UserPermissions   map[string]bool      `json:"userPermissions"`
	SystemSettings    map[string]string    `json:"systemSettings"`
}

type clientSideDateFormat struct {
	DefaultFormat string `json:"defaultFormat"`
}

func UserSettingsHandler(c echo.Context) error {
	logrus.Debug("user.UserSettingsHandler running")
	ctx := c.(*catu.RequestContext)

	cfgs := catu.GetConfiguration()

	queryDefaultLimit, _ := strconv.Atoi(cfgs.GetF("PAGER_LIMIT", "20"))
	queryMaxLimit, _ := strconv.Atoi(cfgs.GetF("PAGER_LIMIT_MAX", "50"))

	ss, err := system_settings.FindAllAsMap()
	if err != nil {
		return err
	}

	data := userSettingsJSONResponse{
		AppName:           cfgs.GetF("SITE_NAME", "App"),
		Hostname:          ctx.AppOrigin,
		ActiveLocale:      cfgs.GetF("DEFAULT_LOCALE", "en-us"),
		DefaultLocale:     cfgs.GetF("DEFAULT_LOCALE", "en-us"),
		Date:              clientSideDateFormat{DefaultFormat: "L HH:mm"},
		QueryDefaultLimit: queryDefaultLimit,
		QueryMaxLimit:     queryMaxLimit,
		Locales:           []string{"pt-br"},
		Plugins:           []string{},
		UserPermissions:   make(map[string]bool),
		SystemSettings:    ss,
	}

	if ctx.IsAuthenticated {
		data.User = ctx.AuthenticatedUser

		// TODO! add all user authenticated data
		AUserLang := ctx.AuthenticatedUser.GetLanguage()
		if AUserLang != "" {
			data.ActiveLocale = AUserLang
		}
	}

	roles := ctx.GetAuthenticatedRoles()

	for _, roleName := range *roles {
		role := ctx.App.GetRole(roleName)
		if role == nil {
			continue
		}

		for _, permissionName := range role.Permissions {
			data.UserPermissions[permissionName] = true
		}
	}

	return c.JSON(200, &data)
}
