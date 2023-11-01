package user_test

import (
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	approvals "github.com/approvals/go-approval-tests"
	"github.com/approvals/go-approval-tests/reporters"
	"github.com/go-bolo/bolo"
	"github.com/go-bolo/clock"
	"github.com/go-bolo/emails"
	"github.com/go-bolo/metatags"
	"github.com/go-bolo/system_settings"
	"github.com/go-bolo/user"
	user_models "github.com/go-bolo/user/models"
	auth_oauth2_password "github.com/go-bolo/user/oauth2_password"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

func NewApp(t *testing.T) bolo.App {
	c := clock.NewMock()
	tp, _ := time.Parse("2006-01-02", "2023-07-16")
	c.Set(tp)

	var app bolo.App
	// TODO! remove that if when related old methods stop using the global app instance:
	opts := &bolo.AppOptions{
		GormOptions: &gorm.Config{},
	}
	if bolo.GetApp() == nil {
		app = bolo.Init(opts)
	} else {
		app = bolo.NewApp(opts)
	}

	app.SetClock(c)

	app.RegisterPlugin(metatags.NewPlugin(&metatags.PluginCfgs{}))
	app.RegisterPlugin(system_settings.NewPlugin(&system_settings.PluginCfgs{}))
	// Requires files and taxonomy plugins:
	app.RegisterPlugin(user.NewUserPlugin(&user.UserPluginCfg{}))
	app.RegisterPlugin(auth_oauth2_password.NewPlugin(&auth_oauth2_password.PluginCfgs{}))

	app.RegisterPlugin(user.NewAuthPlugin(&user.AuthPluginCfgs{}))

	err := app.Bootstrap()
	if err != nil {
		panic(err)
	}

	err = app.GetDB().AutoMigrate(
		&user_models.UserModel{},
		&user_models.PasswordModel{},
		&user_models.AuthTokenModel{},
		&system_settings.Settings{},
		&emails.EmailModel{},
		&emails.EmailTemplateModel{},
	)
	if err != nil {
		panic(errors.Wrap(err, "widget.GetAppInstance Error on run auto migration"))
	}

	return app
}

func TestMain(m *testing.M) {
	mr, err := miniredis.Run()
	if err != nil {
		panic(err)
	}

	defer mr.Close()

	err = os.Setenv("SITE_OAUTH2_ADDR_WRITER", mr.Addr())
	if err != nil {
		panic(err)
	}
	err = os.Setenv("SITE_OAUTH2_ADDR_READER", mr.Addr())
	if err != nil {
		panic(err)
	}

	os.Setenv("DB_URI", "file::memory:?cache=shared")
	os.Setenv("DB_ENGINE", "sqlite")
	os.Setenv("TEMPLATE_FOLDER", "./_stubs/themes")
	// os.Setenv("LOG_QUERY", "1")

	r := approvals.UseReporter(reporters.NewVSCodeReporter())
	defer r.Close()
	approvals.UseFolder("testdata/approvals")

	// db, mock := redismock.NewClientMock()
	// redisMock = mock
	// auth_oauth2_password.StorageDBWriter = db
	// auth_oauth2_password.StorageDBReader = db

	// user.SessionDBWriter = db
	// user.SessionDBReader = db

	// mock.ExpectPing().SetVal("PONG")

	os.Exit(m.Run())
}
