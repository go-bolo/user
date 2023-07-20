package user

import (
	"strconv"

	"github.com/go-bolo/bolo"
	"github.com/go-catupiry/system_settings"
	"github.com/labstack/echo/v4"
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
	User              bolo.User            `json:"authenticatedUser"`
	ActiveLocale      string               `json:"activeLocale"`
	UserPermissions   map[string]bool      `json:"userPermissions"`
	SystemSettings    map[string]string    `json:"systemSettings"`
}

type clientSideDateFormat struct {
	DefaultFormat string `json:"defaultFormat"`
}

func UserSettingsHandler(c echo.Context) (bolo.Response, error) {
	l := bolo.GetLogger(c)
	l.Debug("user.UserSettingsHandler running")
	app := bolo.GetApp(c)
	cfgs := app.GetConfiguration()

	queryDefaultLimit, _ := strconv.Atoi(cfgs.GetF("PAGER_LIMIT", "20"))
	queryMaxLimit, _ := strconv.Atoi(cfgs.GetF("PAGER_LIMIT_MAX", "50"))

	ss, err := system_settings.FindAllAsMap()
	if err != nil {
		return nil, err
	}

	data := userSettingsJSONResponse{
		AppName:           cfgs.GetF("SITE_NAME", "App"),
		Hostname:          bolo.GetBaseURL(c),
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

	if bolo.IsAuthenticated(c) {
		data.User = bolo.GetAuthenticatedUser(c)

		// TODO! add all user authenticated data
		AUserLang := data.User.GetLanguage()
		if AUserLang != "" {
			data.ActiveLocale = AUserLang
		}
	}

	roles := bolo.GetRoles(c)

	for _, roleName := range roles {
		role := app.GetAcl().GetRole(roleName)
		if role == nil {
			continue
		}

		for _, permissionName := range role.Permissions {
			data.UserPermissions[permissionName] = true
		}
	}

	return &bolo.DefaultResponse{
		Data: data,
	}, nil
}
