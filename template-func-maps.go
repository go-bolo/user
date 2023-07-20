package user

import (
	"encoding/json"
	"fmt"
	"html/template"
	"strconv"

	"github.com/go-bolo/bolo"
	"github.com/labstack/echo/v4"
)

type HTMLBootstrapConfig struct {
	AppName           string               `json:"appName"`
	AppLogo           string               `json:"appLogo"`
	ENV               string               `json:"env"`
	Site              string               `json:"site"`
	Hostname          string               `json:"hostname"`
	QueryDefaultLimit int                  `json:"queryDefaultLimit"`
	QueryMaxLimit     int                  `json:"queryMaxLimit"`
	Locales           []string             `json:"locales"`
	DefaultLocale     string               `json:"defaultLocale"`
	Date              clientSideDateFormat `json:"date"`
	Plugins           []string             `json:"plugins"`
	User              map[string]string    `json:"authenticatedUser"`
	UserRoles         []string             `json:"userRoles"`
	ActiveLocale      string               `json:"activeLocale"`
}

func renderClientAppConfigs(tplCtx bolo.TemplateCTX) template.HTML {
	c := tplCtx.Ctx.(echo.Context)
	app := bolo.GetApp(c)
	cfgs := app.GetConfiguration()

	queryDefaultLimit, _ := strconv.Atoi(cfgs.GetF("PAGER_LIMIT", "20"))
	queryMaxLimit, _ := strconv.Atoi(cfgs.GetF("PAGER_LIMIT_MAX", "50"))

	keys := make([]string, 0, len(app.GetPlugins()))
	for k := range app.GetPlugins() {
		keys = append(keys, k)
	}

	data := HTMLBootstrapConfig{
		AppName:           cfgs.GetF("SITE_NAME", "App"),
		ENV:               app.GetEnv(),
		Hostname:          bolo.GetBaseURL(c),
		ActiveLocale:      cfgs.GetF("DEFAULT_LOCALE", "en-us"),
		DefaultLocale:     cfgs.GetF("DEFAULT_LOCALE", "en-us"),
		Date:              clientSideDateFormat{DefaultFormat: "L HH:mm"},
		QueryDefaultLimit: queryDefaultLimit,
		QueryMaxLimit:     queryMaxLimit,
		Locales:           []string{"pt-br"},
		Plugins:           keys,
		UserRoles:         bolo.GetRoles(c),
	}

	if bolo.IsAuthenticated(c) {
		user := bolo.GetAuthenticatedUser(c)
		data.User = make(map[string]string)
		data.User["id"] = user.GetID()
		data.User["displayName"] = user.GetDisplayName()
		// TODO! add all user authenticated data
		AUserLang := user.GetLanguage()
		if AUserLang != "" {
			data.ActiveLocale = AUserLang
		}
	}

	for _, role := range data.UserRoles {
		bolo.AddHTMLBodyClass(c, "ur-"+role)
	}

	jsonStringData, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("Error: %s", err)
	}

	return template.HTML("<script>window.CATUPIRI_BOOTSTRAP_CONFIG=" + string(jsonStringData) + ";</script>")
}
