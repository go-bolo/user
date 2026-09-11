package user_oauth2_password_test

import (
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-bolo/bolo"
	user_models "github.com/go-bolo/user/models"
	auth_oauth2_password "github.com/go-bolo/user/oauth2_password"
	"gorm.io/gorm"
)

// testRedis é o miniredis compartilhado por todos os testes do pacote: o
// plugin aponta StorageDBWriter/StorageDBReader para ele via envs.
var testRedis *miniredis.Miniredis

func TestMain(m *testing.M) {
	mr, err := miniredis.Run()
	if err != nil {
		panic(err)
	}

	defer mr.Close()

	testRedis = mr

	err = os.Setenv("SITE_OAUTH2_ADDR_WRITER", mr.Addr())
	if err != nil {
		panic(err)
	}

	err = os.Setenv("SITE_OAUTH2_ADDR_READER", mr.Addr())
	if err != nil {
		panic(err)
	}

	// DB 0: os métodos diretos do miniredis (Exists/Get/SMembers) enxergam
	// apenas o DB selecionado, então os testes ancoram tudo nele
	err = os.Setenv("SITE_OAUTH2_DB", "0")
	if err != nil {
		panic(err)
	}

	os.Setenv("DB_URI", "file::memory:?cache=shared")
	os.Setenv("DB_ENGINE", "sqlite")
	os.Setenv("TEMPLATE_FOLDER", "./testdata/themes")

	os.Exit(m.Run())
}

// newOAuthTestApp cria um app bolo mínimo (sqlite in-memory + plugin
// oauth2_password) com middlewares e rotas já registrados via Bootstrap.
func newOAuthTestApp(t *testing.T) bolo.App {
	t.Helper()

	var app bolo.App
	opts := &bolo.AppOptions{GormOptions: &gorm.Config{}}
	if bolo.GetApp() == nil {
		app = bolo.Init(opts)
	} else {
		app = bolo.NewApp(opts)
	}

	app.RegisterPlugin(auth_oauth2_password.NewPlugin(&auth_oauth2_password.PluginCfgs{}))

	if err := app.Bootstrap(); err != nil {
		t.Fatalf("failed to bootstrap app: %v", err)
	}

	if err := app.GetDB().AutoMigrate(&user_models.UserModel{}); err != nil {
		t.Fatalf("failed to auto migrate: %v", err)
	}

	return app
}

// newTestContext cria um bolo.RequestContext para invocar as funções da lib
// fora do fluxo HTTP (ex.: RotateRefreshToken), mesmo padrão dos testes do mm.
func newTestContext(app bolo.App, method, target string, body io.Reader) *bolo.RequestContext {
	req := httptest.NewRequest(method, target, body)
	rec := httptest.NewRecorder()
	c := app.GetRouter().NewContext(req, rec)
	return bolo.NewRequestContext(&bolo.RequestContextOpts{EchoContext: c, App: app})
}

// createTestUser cria um usuário direto no banco com ID explícito: em sqlite a
// coluna bigint unsigned não é alias de rowid e o autoincrement não é
// retornado via gorm.
func createTestUser(t *testing.T, app bolo.App, id uint64, active, blocked bool) *user_models.UserModel {
	t.Helper()

	record := &user_models.UserModel{
		ID:          id,
		Username:    fmt.Sprintf("oauth2-refresh-test-user-%d", id),
		Email:       fmt.Sprintf("oauth2-refresh-test-%d@example.com", id),
		DisplayName: "Oauth2 Refresh Test User",
		Active:      active,
		Blocked:     blocked,
	}

	if err := app.GetDB().Create(record).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	return record
}

// flushRedis limpa o miniredis entre testes: as chaves usam uuids, mas o
// flush evita qualquer vazamento de estado.
func flushRedis() {
	testRedis.FlushAll()
}
