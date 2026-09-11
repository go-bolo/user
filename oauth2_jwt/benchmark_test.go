package user_oauth2_jwt_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-bolo/bolo"
	user_models "github.com/go-bolo/user/models"
	auth_oauth2_password "github.com/go-bolo/user/oauth2_password"
	"github.com/labstack/echo/v4"
)

// newBenchmarkApp monta um app com os dois middlewares ativos (JWT antes do
// opaco) e um usuário alvo das iterações. O sqlite in-memory é compartilhado
// por toda a suíte: limpa o usuário alvo antes de recriar.
func newBenchmarkApp(b *testing.B) (bolo.App, *user_models.UserModel) {
	b.Helper()

	flushRedis()
	loginActivityCalls = nil
	app := newJWTTestApp(b, true)

	app.GetDB().Exec("DELETE FROM users WHERE id = ?", uint64(9300))
	app.GetDB().Exec("DELETE FROM passwords WHERE userId = ?", int64(9300))

	user := createTestUser(b, app, 9300, "", true, false, "premium")

	return app, user
}

// benchRequest executa b.N requests autenticadas na rota de teste.
func benchRequest(b *testing.B, app bolo.App, token string) {
	b.Helper()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test-jwt-whoami", nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
		req.Header.Set(echo.HeaderAccept, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		app.GetRouter().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			b.Fatalf("request não autenticou: %d — %s", rec.Code, rec.Body.String())
		}
	}
}

// BenchmarkOpaqueMiddleware mede o custo por request do fluxo legado: Redis
// GET + unmarshal do Oauth2TokenData + query do usuário no banco.
func BenchmarkOpaqueMiddleware(b *testing.B) {
	app, user := newBenchmarkApp(b)

	ctx := newTestContext(app, http.MethodGet, "/test-jwt-whoami", nil)
	data, err := auth_oauth2_password.Oauth2GenerateAndSaveToken(ctx, user)
	if err != nil {
		b.Fatalf("failed to generate opaque token: %v", err)
	}

	benchRequest(b, app, data.AccessToken)
}

// BenchmarkJWTMiddleware mede o custo por request do access JWT stateless:
// validação HS256 + claims com leeway + montagem do stub — sem Redis e sem
// query no banco.
func BenchmarkJWTMiddleware(b *testing.B) {
	app, user := newBenchmarkApp(b)

	ctx := newTestContext(app, http.MethodGet, "/test-jwt-whoami", nil)
	data, err := auth_oauth2_password.Oauth2GenerateAndSaveTokenJWT(ctx, user)
	if err != nil {
		b.Fatalf("failed to generate JWT: %v", err)
	}

	benchRequest(b, app, data.AccessToken)
}

// BenchmarkAnonymousRequest mede a sobrecesa do par de middlewares numa
// request SEM Authorization (caminho de saída rápida dos dois).
func BenchmarkAnonymousRequest(b *testing.B) {
	app, _ := newBenchmarkApp(b)

	benchRequest(b, app, "")
}
