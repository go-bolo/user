package user_oauth2_jwt_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-bolo/bolo"
	user_models "github.com/go-bolo/user/models"
	auth_oauth2_jwt "github.com/go-bolo/user/oauth2_jwt"
	auth_oauth2_password "github.com/go-bolo/user/oauth2_password"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// testRedis é o miniredis compartilhado por todos os testes do pacote: o
// plugin aponta StorageDBWriter/StorageDBReader para ele via envs.
var testRedis *miniredis.Miniredis

// storageCtx contexto para acesso direto ao storage nos testes.
var storageCtx = context.Background()

// loginActivityCalls registra as chamadas do hook OnLoginActivity.
var loginActivityCalls []uint64

const testJWTSecret = "jwt-test-secret-0123456789abcdef0123456789abcdef"

func TestMain(m *testing.M) {
	// silencia logs de info do bootstrap (poluem a saída dos benchmarks)
	logrus.SetLevel(logrus.ErrorLevel)

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
	os.Setenv("TEMPLATE_FOLDER", "../oauth2_password/testdata/themes")

	// config mínima do subplugin JWT (o secret é fail-fast quando vazio).
	// STRICT_401 ligado em TODOS os testes: é a configuração de risco
	// (middleware JWT + opaco juntos).
	os.Setenv("OAUTH2_JWT_SECRET", testJWTSecret)
	os.Setenv("OAUTH2_JWT_ISSUER", "https://api.jwt-test.example")
	os.Setenv("OAUTH2_JWT_AUDIENCE", "mm")
	os.Setenv("OAUTH2_JWT_TTL", "10m")
	os.Setenv("OAUTH2_JWT_LEEWAY", "30s")
	os.Setenv("OAUTH2_STRICT_401", "true")

	os.Exit(m.Run())
}

// newJWTTestApp cria um app bolo mínimo (sqlite in-memory) com os plugins de
// auth na MESMA ordem de registro do consumidor (mm): subplugin JWT antes do
// oauth2_password — a ordem de RegisterPlugin define a ordem dos
// middlewares. withJWT=false monta o app SEM o subplugin (cenário
// kill-switch / não instalado).
func newJWTTestApp(tb testing.TB, withJWT bool) bolo.App {
	tb.Helper()

	var app bolo.App
	opts := &bolo.AppOptions{GormOptions: &gorm.Config{}}
	if bolo.GetApp() == nil {
		app = bolo.Init(opts)
	} else {
		app = bolo.NewApp(opts)
	}

	if withJWT {
		app.RegisterPlugin(auth_oauth2_jwt.NewPlugin(&auth_oauth2_jwt.PluginCfgs{
			OnLoginActivity: func(userID uint64) error {
				loginActivityCalls = append(loginActivityCalls, userID)
				return nil
			},
		}))
	}

	app.RegisterPlugin(auth_oauth2_password.NewPlugin(&auth_oauth2_password.PluginCfgs{}))

	// o logger.Init() do NewApp reseta o nível herdado do TestMain: cala os
	// logs de info do bootstrap (intercalam com a saída dos benchmarks)
	logrus.SetLevel(logrus.ErrorLevel)

	if err := app.Bootstrap(); err != nil {
		tb.Fatalf("failed to bootstrap app: %v", err)
	}

	if err := app.GetDB().AutoMigrate(&user_models.UserModel{}, &user_models.PasswordModel{}); err != nil {
		tb.Fatalf("failed to auto migrate: %v", err)
	}

	registerWhoamiRoute(app)

	return app
}

// registerWhoamiRoute expõe uma rota protegida que ecoa o estado de
// autenticação montado pelos middlewares.
func registerWhoamiRoute(app bolo.App) {
	app.GetRouter().GET("/test-jwt-whoami", func(c echo.Context) error {
		ctx := c.(*bolo.RequestContext)

		resp := map[string]interface{}{
			"authenticated": ctx.IsAuthenticated,
			"roles":         ctx.Roles,
		}

		if ctx.IsAuthenticated && ctx.AuthenticatedUser != nil {
			resp["userID"] = ctx.AuthenticatedUser.GetID()
			resp["active"] = ctx.AuthenticatedUser.IsActive()
			resp["blocked"] = ctx.AuthenticatedUser.IsBlocked()
		}

		return c.JSON(http.StatusOK, resp)
	})
}

// newTestContext cria um bolo.RequestContext para invocar as funções da lib
// fora do fluxo HTTP, mesmo padrão dos testes do oauth2_password.
func newTestContext(app bolo.App, method, target string, body io.Reader) *bolo.RequestContext {
	req := httptest.NewRequest(method, target, body)
	rec := httptest.NewRecorder()
	c := app.GetRouter().NewContext(req, rec)
	return bolo.NewRequestContext(&bolo.RequestContextOpts{EchoContext: c, App: app})
}

// createTestUser cria um usuário direto no banco com senha bcrypt (custo
// mínimo: o custo padrão deixaria a suíte lenta) e roles opcionais.
func createTestUser(tb testing.TB, app bolo.App, id uint64, password string, active, blocked bool, roles ...string) *user_models.UserModel {
	tb.Helper()

	record := &user_models.UserModel{
		ID:          id,
		Username:    fmt.Sprintf("jwt-test-user-%d", id),
		Email:       fmt.Sprintf("jwt-test-%d@example.com", id),
		DisplayName: "JWT Test User",
		Active:      active,
		Blocked:     blocked,
	}

	if len(roles) > 0 {
		if err := record.SetRoles(roles); err != nil {
			tb.Fatalf("failed to set roles: %v", err)
		}
	}

	if err := app.GetDB().Create(record).Error; err != nil {
		tb.Fatalf("failed to create user: %v", err)
	}

	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			tb.Fatalf("failed to hash password: %v", err)
		}

		userID := int64(id)
		pwd := &user_models.PasswordModel{UserID: &userID, Password: string(hash)}
		if err := app.GetDB().Create(pwd).Error; err != nil {
			tb.Fatalf("failed to create password: %v", err)
		}
	}

	return record
}

// doJSON executa uma requisição JSON no router do app, com Bearer opcional.
func doJSON(t *testing.T, app bolo.App, method, target, body, bearer string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAccept, echo.MIMEApplicationJSON)
	if bearer != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+bearer)
	}

	rec := httptest.NewRecorder()
	app.GetRouter().ServeHTTP(rec, req)

	return rec
}

// decodeTokenPair decodifica a resposta dos endpoints de auth.
func decodeTokenPair(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()

	var data map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil {
		t.Fatalf("resposta não é JSON válido: %v — corpo: %s", err, rec.Body.String())
	}

	return data
}

// flushRedis limpa o miniredis entre testes.
func flushRedis() {
	testRedis.FlushAll()
}

// redisGet lê uma chave direto do miniredis (helper de asserção); devolve ""
// para chave inexistente.
func redisGet(t *testing.T, key string) string {
	t.Helper()

	v, err := testRedis.Get(key)
	if err == miniredis.ErrKeyNotFound {
		return ""
	}
	if err != nil {
		t.Fatalf("redis get %s: %v", key, err)
	}

	return v
}

// unitConfig devolve uma Config para testes unitários de emissão/validação.
func unitConfig() *auth_oauth2_jwt.Config {
	return &auth_oauth2_jwt.Config{
		Secret:   testJWTSecret,
		Issuer:   "https://api.jwt-test.example",
		Audience: "mm",
		TTL:      10 * time.Minute,
		Leeway:   30 * time.Second,
	}
}
