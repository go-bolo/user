package user

import (
	"encoding/json"
	"fmt"
	"html/template"
	"strconv"

	"github.com/go-bolo/bolo"
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
	ctx := tplCtx.Ctx.(*bolo.RequestContext)
	app := bolo.GetApp()

	cfgs := bolo.GetConfiguration()

	queryDefaultLimit, _ := strconv.Atoi(cfgs.GetF("PAGER_LIMIT", "20"))
	queryMaxLimit, _ := strconv.Atoi(cfgs.GetF("PAGER_LIMIT_MAX", "50"))

	keys := make([]string, 0, len(app.GetPlugins()))
	for _, p := range app.GetPlugins() {
		keys = append(keys, p.GetName())
	}

	data := HTMLBootstrapConfig{
		AppName:           cfgs.GetF("SITE_NAME", "App"),
		ENV:               ctx.ENV,
		Hostname:          ctx.AppOrigin,
		ActiveLocale:      cfgs.GetF("DEFAULT_LOCALE", "en-us"),
		DefaultLocale:     cfgs.GetF("DEFAULT_LOCALE", "en-us"),
		Date:              clientSideDateFormat{DefaultFormat: "L HH:mm"},
		QueryDefaultLimit: queryDefaultLimit,
		QueryMaxLimit:     queryMaxLimit,
		Locales:           []string{"pt-br"},
		Plugins:           keys,
		UserRoles:         *ctx.GetAuthenticatedRoles(),
	}

	if ctx.IsAuthenticated {
		data.User = make(map[string]string)
		data.User["id"] = ctx.AuthenticatedUser.GetID()
		data.User["displayName"] = ctx.AuthenticatedUser.GetDisplayName()

		// TODO! add all user authenticated data
		AUserLang := ctx.AuthenticatedUser.GetLanguage()
		if AUserLang != "" {
			data.ActiveLocale = AUserLang
		}
	}

	for _, role := range data.UserRoles {
		ctx.BodyClass = append(ctx.BodyClass, "ur-"+role)
	}

	jsonStringData, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("Error: %s", err)
	}

	return template.HTML("<script>window.CATUPIRI_BOOTSTRAP_CONFIG=" + string(jsonStringData) + ";</script>")
}
