package user_oauth2_password_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-bolo/bolo"
	auth_oauth2_password "github.com/go-bolo/user/oauth2_password"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestOauth2TokenAuthentication_Strict401(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newOAuthTestApp(t)

	// rota protegida para observar o resultado do middleware
	app.GetRouter().GET("/test-whoami", func(c echo.Context) error {
		ctx := c.(*bolo.RequestContext)
		if ctx.IsAuthenticated {
			return c.JSON(http.StatusOK, map[string]interface{}{"authenticated": true})
		}
		return c.JSON(http.StatusOK, map[string]interface{}{"authenticated": false})
	})

	user := createTestUser(t, app, 9111, true, false)
	ctx := newTestContext(app, http.MethodGet, "/test-whoami", nil)

	data, err := auth_oauth2_password.Oauth2GenerateAndSaveToken(ctx, user)
	assert.NoError(err)

	// "expira" o access token mantendo a chave viva no redis (caso !IsValid)
	str, err := testRedis.Get(data.AccessToken)
	assert.NoError(err)

	var tokenData auth_oauth2_password.Oauth2TokenData
	assert.NoError(json.Unmarshal([]byte(str), &tokenData))
	tokenData.ExpireDate = time.Now().Add(-time.Minute)
	expiredJSON, err := json.Marshal(tokenData)
	assert.NoError(err)
	assert.NoError(auth_oauth2_password.StorageDBWriter.Set(context.Background(), data.AccessToken, string(expiredJSON), 10*time.Minute).Err())

	unknownToken := uuid.New().String()

	doReq := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/test-whoami", nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
		req.Header.Set(echo.HeaderAccept, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		app.GetRouter().ServeHTTP(rec, req)
		return rec
	}

	assertWWWAuthenticate := func(rec *httptest.ResponseRecorder) {
		assert.Equal(`Bearer error="invalid_token", error_description="token expired"`, rec.Header().Get("WWW-Authenticate"))
		// corpo no formato bolo.BaseErrorResponse:
		assert.Contains(rec.Body.String(), `"messages"`)
		assert.Contains(rec.Body.String(), `"token expired"`)
	}

	// Decodifica o corpo em vez de comparar strings: com echo.Debug (ex.
	// GO_ENV=development no container) o JSON sai indentado.
	isAuthenticated := func(rec *httptest.ResponseRecorder) bool {
		var body struct {
			Authenticated bool `json:"authenticated"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("resposta não é JSON válido: %v — corpo: %s", err, rec.Body.String())
		}
		return body.Authenticated
	}

	t.Run("off: unknown token stays anonymous", func(t *testing.T) {
		t.Setenv("OAUTH2_STRICT_401", "false")

		rec := doReq(unknownToken)
		assert.Equal(http.StatusOK, rec.Code)
		assert.False(isAuthenticated(rec))
	})

	t.Run("off: expired token stays anonymous like unknown token", func(t *testing.T) {
		t.Setenv("OAUTH2_STRICT_401", "false")

		rec := doReq(data.AccessToken)
		assert.Equal(http.StatusOK, rec.Code)
		assert.False(isAuthenticated(rec))
	})

	t.Run("off: valid token authenticates", func(t *testing.T) {
		data2, err := auth_oauth2_password.Oauth2GenerateAndSaveToken(ctx, user)
		assert.NoError(err)

		rec := doReq(data2.AccessToken)
		assert.Equal(http.StatusOK, rec.Code)
		assert.True(isAuthenticated(rec))
	})

	t.Run("on: unknown token gets explicit 401", func(t *testing.T) {
		t.Setenv("OAUTH2_STRICT_401", "true")

		rec := doReq(unknownToken)
		assert.Equal(http.StatusUnauthorized, rec.Code)
		assertWWWAuthenticate(rec)
	})

	t.Run("on: expired token gets explicit 401", func(t *testing.T) {
		t.Setenv("OAUTH2_STRICT_401", "true")

		rec := doReq(data.AccessToken)
		assert.Equal(http.StatusUnauthorized, rec.Code)
		assertWWWAuthenticate(rec)
	})

	t.Run("on: valid token still authenticates", func(t *testing.T) {
		data2, err := auth_oauth2_password.Oauth2GenerateAndSaveToken(ctx, user)
		assert.NoError(err)

		rec := doReq(data2.AccessToken)
		assert.Equal(http.StatusOK, rec.Code)
		assert.True(isAuthenticated(rec))
	})
}
