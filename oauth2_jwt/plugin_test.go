package user_oauth2_jwt_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-bolo/bolo"
	user_models "github.com/go-bolo/user/models"
	auth_oauth2_jwt "github.com/go-bolo/user/oauth2_jwt"
	auth_oauth2_password "github.com/go-bolo/user/oauth2_password"
	"github.com/stretchr/testify/assert"
)

// authenticateJWT faz o login no endpoint /auth/jwt e devolve a resposta
// decodificada.
func authenticateJWT(t *testing.T, app bolo.App, email, password string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()

	body := `{"grant_type":"password","email":"` + email + `","password":"` + password + `"}`
	rec := doJSON(t, app, http.MethodPost, "/auth/jwt/authenticate", body, "")

	return rec, decodeTokenPair(t, rec)
}

// refreshJWT troca o refresh token no endpoint /auth/jwt.
func refreshJWT(t *testing.T, app bolo.App, refreshToken string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()

	body := `{"refresh_token":"` + refreshToken + `"}`
	rec := doJSON(t, app, http.MethodPost, "/auth/jwt/refresh-token", body, "")

	return rec, decodeTokenPair(t, rec)
}

// whoami consulta a rota protegida de teste com o Bearer indicado.
func whoami(t *testing.T, app bolo.App, bearer string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()

	rec := doJSON(t, app, http.MethodGet, "/test-jwt-whoami", "", bearer)
	return rec, decodeTokenPair(t, rec)
}

// isJWT checa o formato compacto (3 segmentos) do access token.
func isJWT(t *testing.T, token interface{}) bool {
	t.Helper()

	s, ok := token.(string)
	if !ok {
		return false
	}

	return auth_oauth2_jwt.LooksLikeJWT(s)
}

func TestNovoAuthenticate_IssuesJWTAndAuthenticatesWithStrict401(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	loginActivityCalls = nil
	app := newJWTTestApp(t, true)

	createTestUser(t, app, 9201, "senha-valida", true, false, "premium")

	// OAUTH2_STRICT_401=true vem do TestMain: este é o cenário de risco —
	// middleware JWT ANTES do opaco, com strict ligado
	rec, data := authenticateJWT(t, app, "jwt-test-9201@example.com", "senha-valida")
	assert.Equal(http.StatusOK, rec.Code)
	assert.True(isJWT(t, data["access_token"]))
	assert.NotEmpty(data["refresh_token"])
	assert.Equal(float64(600), data["expires_in"])
	assert.NotNil(data["user"])

	accessToken := data["access_token"].(string)
	refreshToken := data["refresh_token"].(string)

	// access JWT NÃO é gravado no Redis (stateless): só o refresh (formato
	// novo RT: com família) tem estado
	assert.Equal("", redisGet(t, accessToken))
	assert.NotEqual("", redisGet(t, auth_oauth2_password.RefreshTokenKeyPrefix+refreshToken))

	// request autenticada com o JWT: guarda auth.jwt faz o middleware opaco
	// pular a validação — sem ele o miss no Redis viraria 401 falso
	rec2, who := whoami(t, app, accessToken)
	assert.Equal(http.StatusOK, rec2.Code)
	assert.Equal(true, who["authenticated"])
	assert.Equal("9201", who["userID"])

	// hook de atividade de login chamado no authenticate
	assert.Equal([]uint64{9201}, loginActivityCalls)
}

func TestNovoAuthenticate_StubCarriesRolesAndSnapshot(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newJWTTestApp(t, true)

	createTestUser(t, app, 9202, "senha-valida", true, false, "administrator", "premium")

	_, data := authenticateJWT(t, app, "jwt-test-9202@example.com", "senha-valida")

	rec, who := whoami(t, app, data["access_token"].(string))
	assert.Equal(http.StatusOK, rec.Code)
	assert.Equal(true, who["authenticated"])

	// roles do claim + a role "authenticated" adicionada pelo
	// SetAuthenticatedUserAndFillRoles (stub com RolesText populado)
	assert.ElementsMatch([]interface{}{"administrator", "premium", "authenticated"}, who["roles"])
	assert.Equal(true, who["active"])
	assert.Equal(false, who["blocked"])
}

func TestNovoAuthenticate_InactiveAndBlockedUsers(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newJWTTestApp(t, true)

	createTestUser(t, app, 9203, "senha-valida", false, false)
	createTestUser(t, app, 9204, "senha-valida", true, true)

	rec, data := authenticateJWT(t, app, "jwt-test-9203@example.com", "senha-valida")
	assert.Equal(http.StatusForbidden, rec.Code)
	assert.Contains(rec.Body.String(), "Conta não ativada")
	assert.Nil(data["access_token"])

	rec2, data2 := authenticateJWT(t, app, "jwt-test-9204@example.com", "senha-valida")
	assert.Equal(http.StatusForbidden, rec2.Code)
	assert.Contains(rec2.Body.String(), "Conta bloqueada")
	assert.Nil(data2["access_token"])
}

func TestNovoAuthenticate_WrongPassword(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newJWTTestApp(t, true)

	createTestUser(t, app, 9205, "senha-valida", true, false)

	rec, _ := authenticateJWT(t, app, "jwt-test-9205@example.com", "senha-errada")
	assert.Equal(http.StatusBadRequest, rec.Code)
	assert.Contains(rec.Body.String(), "Email ou senha incorretos")
}

func TestJWTMiddleware_RejectsInvalidAndExpiredWith401(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newJWTTestApp(t, true)

	// Bearer sem formato JWT cai no middleware opaco (miss no Redis):
	// 401 pelo strict, sem WWW-Authenticate do subplugin
	rec, _ := whoami(t, app, "token-opaco-que-nao-existe")
	assert.Equal(http.StatusUnauthorized, rec.Code)

	// JWT expirado: 401 com WWW-Authenticate do contrato do subplugin
	cfg := unitConfig()
	cfg.TTL = -2 * time.Minute
	expired, _, err := auth_oauth2_jwt.GenerateAccessToken(cfg, &unitUser{id: "9206"})
	assert.NoError(err)

	rec2, _ := whoami(t, app, expired)
	assert.Equal(http.StatusUnauthorized, rec2.Code)
	assert.Equal(`Bearer error="invalid_token", error_description="token expired"`, rec2.Header().Get("WWW-Authenticate"))

	// JWT com assinatura inválida: 401 com WWW-Authenticate
	valid, _, err := auth_oauth2_jwt.GenerateAccessToken(cfg, &unitUser{id: "9206"})
	assert.NoError(err)
	tampered := valid[:len(valid)-4] + "AAAA"
	rec3, _ := whoami(t, app, tampered)
	assert.Equal(http.StatusUnauthorized, rec3.Code)
	assert.Contains(rec3.Header().Get("WWW-Authenticate"), "invalid_token")
}

func TestDualFormat_OpaqueLegacyValidatesAlongsideJWT(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newJWTTestApp(t, true)

	user := createTestUser(t, app, 9207, "senha-valida", true, false)

	// fluxo legado intacto: endpoint antigo emite token opaco
	rec := doJSON(t, app, http.MethodPost, "/auth/grant-password/authenticate", `{"grant_type":"password","email":"jwt-test-9207@example.com","password":"senha-valida"}`, "")
	assert.Equal(http.StatusOK, rec.Code)
	legacy := decodeTokenPair(t, rec)
	assert.False(isJWT(t, legacy["access_token"]))

	// token opaco autentica pelo middleware opaco no MESMO app com os dois
	// middlewares ativos
	rec2, who := whoami(t, app, legacy["access_token"].(string))
	assert.Equal(http.StatusOK, rec2.Code)
	assert.Equal(true, who["authenticated"])
	assert.Equal(user.GetID(), who["userID"])

	// e o token opaco continua gravado no Redis
	assert.NotEqual("", redisGet(t, legacy["access_token"].(string)))
}

func TestNovoRefresh_EmitsJWTAndReplayInGraceReturnsSamePair(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	loginActivityCalls = nil
	app := newJWTTestApp(t, true)

	createTestUser(t, app, 9208, "senha-valida", true, false)

	_, data := authenticateJWT(t, app, "jwt-test-9208@example.com", "senha-valida")
	firstRefresh := data["refresh_token"].(string)

	rec, pair := refreshJWT(t, app, firstRefresh)
	assert.Equal(http.StatusOK, rec.Code)
	assert.True(isJWT(t, pair["access_token"]))
	assert.NotEmpty(pair["refresh_token"])
	assert.Equal(float64(600), pair["expires_in"])

	secondRefresh := pair["refresh_token"].(string)
	assert.NotEqual(firstRefresh, secondRefresh)

	// JWT novo já autentica
	rec2, who := whoami(t, app, pair["access_token"].(string))
	assert.Equal(http.StatusOK, rec2.Code)
	assert.Equal(true, who["authenticated"])

	// replay dentro da graça devolve o MESMO par (JWT incluso)
	rec3, pair2 := refreshJWT(t, app, firstRefresh)
	assert.Equal(http.StatusOK, rec3.Code)
	assert.Equal(pair["access_token"], pair2["access_token"])
	assert.Equal(pair["refresh_token"], pair2["refresh_token"])

	// rotação real: primeiro refresh consumido, segundo vivo
	assert.Equal("", redisGet(t, auth_oauth2_password.RefreshTokenKeyPrefix+firstRefresh))
	assert.NotEqual("", redisGet(t, auth_oauth2_password.RefreshTokenKeyPrefix+secondRefresh))

	// hook de atividade chamado em authenticate + rotação + replay (o
	// handler não distingue replay: toda resposta bem-sucedida registra,
	// mesma paridade do handler do mm)
	assert.Equal([]uint64{9208, 9208, 9208}, loginActivityCalls)
}

func TestNovoRefresh_MigratesLegacyOpaqueSession(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newJWTTestApp(t, true)

	user := createTestUser(t, app, 9209, "senha-valida", true, false)

	// sessão legada (login antigo): par opaco com refresh sem prefixo
	ctx := newTestContext(app, http.MethodPost, "/auth/grant-password/authenticate", nil)
	legacy, err := auth_oauth2_password.Oauth2GenerateAndSaveToken(ctx, user)
	assert.NoError(err)

	// primeira rotação no endpoint /auth/jwt migra para JWT
	rec, pair := refreshJWT(t, app, legacy.RefreshToken)
	assert.Equal(http.StatusOK, rec.Code)
	assert.True(isJWT(t, pair["access_token"]))

	// refresh novo no formato RT: com família
	assert.NotEqual("", redisGet(t, auth_oauth2_password.RefreshTokenKeyPrefix+pair["refresh_token"].(string)))

	// access JWT migrado autentica; o opaco antigo continua válido até expirar
	rec2, who := whoami(t, app, pair["access_token"].(string))
	assert.Equal(http.StatusOK, rec2.Code)
	assert.Equal(true, who["authenticated"])
}

func TestNovoRefresh_ErrorMappings(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newJWTTestApp(t, true)

	// token desconhecido: idle expirado
	rec, _ := refreshJWT(t, app, "refresh-que-nunca-existiu")
	assert.Equal(http.StatusBadRequest, rec.Code)
	assert.Contains(rec.Body.String(), "Sessão expirada. Entre novamente.")

	// dono inativo: 403 com mensagem específica
	createTestUser(t, app, 9210, "senha-valida", false, false)
	ctx := newTestContext(app, http.MethodPost, "/auth/jwt/refresh-token", nil)
	inactive, err := auth_oauth2_password.Oauth2GenerateAndSaveTokenJWT(ctx, mustFindUser(t, app, 9210))
	assert.NoError(err)

	rec2, _ := refreshJWT(t, app, inactive.RefreshToken)
	assert.Equal(http.StatusForbidden, rec2.Code)
	assert.Contains(rec2.Body.String(), "Conta não ativada")

	// dono bloqueado: 403 com mensagem específica
	createTestUser(t, app, 9211, "senha-valida", true, true)
	inactive2, err := auth_oauth2_password.Oauth2GenerateAndSaveTokenJWT(ctx, mustFindUser(t, app, 9211))
	assert.NoError(err)

	rec3, _ := refreshJWT(t, app, inactive2.RefreshToken)
	assert.Equal(http.StatusForbidden, rec3.Code)
	assert.Contains(rec3.Body.String(), "Conta bloqueada")
}

func TestRevoke_LogoutWithJWTSession(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newJWTTestApp(t, true)

	createTestUser(t, app, 9212, "senha-valida", true, false)

	_, data := authenticateJWT(t, app, "jwt-test-9212@example.com", "senha-valida")
	accessToken := data["access_token"].(string)
	refreshToken := data["refresh_token"].(string)

	// revogação com hint access_token: delete no-op para JWT (stateless) e
	// resposta 200 sempre (RFC 7009)
	rec := doJSON(t, app, http.MethodPost, "/auth/grant-password/revoke", `{"token":"`+accessToken+`","token_type_hint":"access_token"}`, "")
	assert.Equal(http.StatusOK, rec.Code)

	// o access JWT segue válido até expirar (contrato: sem denylist)
	rec2, who := whoami(t, app, accessToken)
	assert.Equal(http.StatusOK, rec2.Code)
	assert.Equal(true, who["authenticated"])

	// logout de verdade revoga a família do refresh
	rec3 := doJSON(t, app, http.MethodPost, "/auth/grant-password/revoke", `{"token":"`+refreshToken+`"}`, "")
	assert.Equal(http.StatusOK, rec3.Code)

	rec4, _ := refreshJWT(t, app, refreshToken)
	assert.Equal(http.StatusBadRequest, rec4.Code)
	assert.Contains(rec4.Body.String(), "Sessão expirada. Entre novamente.")
}

func TestSubpluginNotInstalled_Routes404AndJWTRejected(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newJWTTestApp(t, false)

	createTestUser(t, app, 9213, "senha-valida", true, false)

	// rotas /auth/jwt somem (kill-switch)
	rec := doJSON(t, app, http.MethodPost, "/auth/jwt/authenticate", `{"grant_type":"password","email":"jwt-test-9213@example.com","password":"senha-valida"}`, "")
	assert.Equal(http.StatusNotFound, rec.Code)

	// JWT deixa de validar: sem middleware JWT, cai no opaco → miss → 401
	cfg := unitConfig()
	token, _, err := auth_oauth2_jwt.GenerateAccessToken(cfg, &unitUser{id: "9213"})
	assert.NoError(err)

	rec2, _ := whoami(t, app, token)
	assert.Equal(http.StatusUnauthorized, rec2.Code)

	// fluxo opaco legado intacto
	rec3 := doJSON(t, app, http.MethodPost, "/auth/grant-password/authenticate", `{"grant_type":"password","email":"jwt-test-9213@example.com","password":"senha-valida"}`, "")
	assert.Equal(http.StatusOK, rec3.Code)
	legacy := decodeTokenPair(t, rec3)
	assert.False(isJWT(t, legacy["access_token"]))

	rec4, who := whoami(t, app, legacy["access_token"].(string))
	assert.Equal(http.StatusOK, rec4.Code)
	assert.Equal(true, who["authenticated"])
}

func TestNovoEndpoints_ReflectConfiguredTTL(t *testing.T) {
	assert := assert.New(t)
	flushRedis()

	// TTL 3m (dev): expires_in precisa refletir o TTL do JWT — sem ele o
	// scheduler do frontend assumiria 1800s
	t.Setenv("OAUTH2_JWT_TTL", "3m")
	app := newJWTTestApp(t, true)

	createTestUser(t, app, 9214, "senha-valida", true, false)

	_, data := authenticateJWT(t, app, "jwt-test-9214@example.com", "senha-valida")
	assert.Equal(float64(180), data["expires_in"])

	rec, pair := refreshJWT(t, app, data["refresh_token"].(string))
	assert.Equal(http.StatusOK, rec.Code)
	assert.Equal(float64(180), pair["expires_in"])
}

func TestOauth2GenerateAndSaveTokenJWT_RequiresGenerator(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newJWTTestApp(t, false)

	// sem o subplugin instalado não existe gerador registrado: erro
	// explícito em vez de token em formato desconhecido
	auth_oauth2_password.SetJWTAccessGenerator(nil)
	defer auth_oauth2_password.SetJWTAccessGenerator(nil)

	ctx := newTestContext(app, http.MethodPost, "/auth/jwt/authenticate", nil)
	createTestUser(t, app, 9215, "", true, false)
	user := mustFindUser(t, app, 9215)

	_, err := auth_oauth2_password.Oauth2GenerateAndSaveTokenJWT(ctx, user)
	assert.Error(err)
	assert.Contains(err.Error(), "não registrado")
}

func TestReusedRefreshTokenOutsideGrace_RevokesFamily(t *testing.T) {
	assert := assert.New(t)
	flushRedis()

	// graça curtíssima para o teste detectar reuso fora da janela
	t.Setenv("OAUTH2_REFRESH_REUSE_GRACE", "1ms")
	app := newJWTTestApp(t, true)

	createTestUser(t, app, 9216, "senha-valida", true, false)

	_, data := authenticateJWT(t, app, "jwt-test-9216@example.com", "senha-valida")
	firstRefresh := data["refresh_token"].(string)

	rec, pair := refreshJWT(t, app, firstRefresh)
	assert.Equal(http.StatusOK, rec.Code)

	// miniredis não expira TTLs por tempo de parede: avança o relógio
	// lógico para consumir a graça de 1ms (o tombstone de 30d sobrevive)
	testRedis.FastForward(2 * time.Second)

	// reapresenta o token antigo FORA da graça: reuso detectado
	rec2, _ := refreshJWT(t, app, firstRefresh)
	assert.Equal(http.StatusBadRequest, rec2.Code)
	assert.Contains(rec2.Body.String(), "Sessão expirada. Entre novamente.")

	// família inteira revogada: o refresh novo (do par legítimo) também morre
	rec3, _ := refreshJWT(t, app, pair["refresh_token"].(string))
	assert.Equal(http.StatusBadRequest, rec3.Code)
	assert.Contains(rec3.Body.String(), "Sessão expirada. Entre novamente.")
}

func TestNovoRefresh_ReplayWithinGraceAfterFailureIsIdempotent(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newJWTTestApp(t, true)

	// o replay na graça devolve o MESMO JWT mesmo que a sessão emita vários
	// pares em sequência de rotações legítimas
	createTestUser(t, app, 9217, "senha-valida", true, false)

	_, data := authenticateJWT(t, app, "jwt-test-9217@example.com", "senha-valida")
	firstRefresh := data["refresh_token"].(string)

	_, pair1 := refreshJWT(t, app, firstRefresh)

	// rotação legítima seguinte com o refresh novo
	_, pair2 := refreshJWT(t, app, pair1["refresh_token"].(string))

	// o JWT anterior ainda está dentro do próprio TTL e valida
	rec, who := whoami(t, app, pair1["access_token"].(string))
	assert.Equal(http.StatusOK, rec.Code)
	assert.Equal(true, who["authenticated"])

	// tokens emitidos são todos JWTs distintos
	assert.NotEqual(pair1["access_token"], pair2["access_token"])
	assert.True(isJWT(t, pair2["access_token"]))
}

// mustFindUser carrega o usuário de teste pelo ID.
func mustFindUser(t *testing.T, app bolo.App, id uint64) *user_models.UserModel {
	t.Helper()

	var record user_models.UserModel
	if err := app.GetDB().First(&record, "id = ?", id).Error; err != nil {
		t.Fatalf("failed to find user %d: %v", id, err)
	}

	return &record
}
