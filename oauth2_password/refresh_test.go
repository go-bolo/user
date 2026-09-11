package user_oauth2_password_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth_oauth2_password "github.com/go-bolo/user/oauth2_password"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

// storageCtx contexto para acesso direto ao storage nos testes
var storageCtx = context.Background()

// seedNewRefreshToken grava um refresh token no formato novo (RT:) apontando
// para o dono e devolve o token puro.
func seedNewRefreshToken(t *testing.T, ownerID string) string {
	t.Helper()

	token := uuid.New().String()
	record := auth_oauth2_password.RefreshTokenRecord{
		OwnerID:          json.Number(ownerID),
		FamilyID:         uuid.New().String(),
		CreatedAt:        time.Now(),
		AbsoluteDeadline: time.Now().Add(auth_oauth2_password.DefaultRefreshAbsoluteTTL),
	}

	data, err := json.Marshal(record)
	assert.NoError(t, err)

	err = auth_oauth2_password.StorageDBWriter.Set(storageCtx, auth_oauth2_password.RefreshTokenKeyPrefix+token, string(data), 72*time.Hour).Err()
	assert.NoError(t, err)

	return token
}

// getFamilyID devolve o ID da família associado ao token pelo tombstone.
func getFamilyID(t *testing.T, refreshToken string) string {
	t.Helper()

	familyID, err := testRedis.Get(auth_oauth2_password.RefreshTokenTombKeyPrefix + refreshToken)
	assert.NoError(t, err)
	assert.NotEmpty(t, familyID)

	return familyID
}

func TestRotateRefreshToken_HappyPath(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newOAuthTestApp(t)
	user := createTestUser(t, app, 9101, true, false)

	refreshToken := seedNewRefreshToken(t, "9101")
	ctx := newTestContext(app, http.MethodPost, "/auth/grant-password/refresh-token", nil)

	pair, gotUser, rerr := auth_oauth2_password.RotateRefreshToken(ctx, refreshToken)
	assert.Nil(rerr)
	assert.NotNil(pair)
	assert.NotEmpty(pair.AccessToken)
	assert.NotEmpty(pair.RefreshToken)
	assert.NotEqual(refreshToken, pair.RefreshToken)
	assert.NotZero(pair.ExpiresIn)
	assert.NotNil(gotUser)
	assert.Equal(user.GetID(), gotUser.GetID())

	// access token novo gravado e utilizável:
	assert.True(testRedis.Exists(pair.AccessToken))

	// rotação: refresh velho consumido, graça e tombstone criados:
	assert.False(testRedis.Exists(refreshToken))
	assert.True(testRedis.Exists(auth_oauth2_password.RefreshTokenUsedKeyPrefix + refreshToken))
	assert.True(testRedis.Exists(auth_oauth2_password.RefreshTokenTombKeyPrefix + refreshToken))

	// refresh novo no formato novo:
	assert.True(testRedis.Exists(auth_oauth2_password.RefreshTokenKeyPrefix + pair.RefreshToken))

	// família populada com os tokens envolvidos (velho + novo):
	familyID := getFamilyID(t, refreshToken)
	members, err := testRedis.SMembers(auth_oauth2_password.RefreshTokenFamilyKeyPrefix + familyID)
	assert.NoError(err)
	assert.ElementsMatch([]string{refreshToken, pair.RefreshToken}, members)
}

func TestRotateRefreshToken_ReplayWithinGraceIsIdempotent(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newOAuthTestApp(t)
	createTestUser(t, app, 9102, true, false)

	refreshToken := seedNewRefreshToken(t, "9102")
	ctx := newTestContext(app, http.MethodPost, "/auth/grant-password/refresh-token", nil)

	pair1, _, rerr := auth_oauth2_password.RotateRefreshToken(ctx, refreshToken)
	assert.Nil(rerr)

	// segunda aba perde a corrida e reapresenta o MESMO token dentro da graça:
	pair2, gotUser, rerr := auth_oauth2_password.RotateRefreshToken(ctx, refreshToken)
	assert.Nil(rerr)
	assert.NotNil(pair2)
	assert.Equal(pair1.AccessToken, pair2.AccessToken)
	assert.Equal(pair1.RefreshToken, pair2.RefreshToken)
	assert.Equal(pair1.ExpiresIn, pair2.ExpiresIn)
	assert.NotNil(gotUser)

	// idempotente: nenhum terceiro token foi gerado
	assert.True(testRedis.Exists(auth_oauth2_password.RefreshTokenKeyPrefix + pair1.RefreshToken))

	familyID := getFamilyID(t, refreshToken)
	members, err := testRedis.SMembers(auth_oauth2_password.RefreshTokenFamilyKeyPrefix + familyID)
	assert.NoError(err)
	assert.Len(members, 2)
}

func TestRotateRefreshToken_ReuseAfterGraceRevokesFamily(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newOAuthTestApp(t)
	createTestUser(t, app, 9103, true, false)

	refreshToken := seedNewRefreshToken(t, "9103")
	ctx := newTestContext(app, http.MethodPost, "/auth/grant-password/refresh-token", nil)

	pair1, _, rerr := auth_oauth2_password.RotateRefreshToken(ctx, refreshToken)
	assert.Nil(rerr)

	familyID := getFamilyID(t, refreshToken)

	// avança o relógio além da janela de graça (default 30s): RTUSED expira,
	// tombstone continua
	testRedis.FastForward(31 * time.Second)
	assert.False(testRedis.Exists(auth_oauth2_password.RefreshTokenUsedKeyPrefix + refreshToken))

	pair2, user, rerr := auth_oauth2_password.RotateRefreshToken(ctx, refreshToken)
	assert.Nil(pair2)
	assert.Nil(user)
	assert.NotNil(rerr)
	assert.Equal(auth_oauth2_password.ErrReuseDetected, rerr.Kind)

	// reuso derruba a família inteira, incluindo o refresh do par emitido
	// (access tokens não são membros da família e expiram sozinhos):
	assert.False(testRedis.Exists(auth_oauth2_password.RefreshTokenKeyPrefix + pair1.RefreshToken))
	assert.False(testRedis.Exists(auth_oauth2_password.RefreshTokenFamilyKeyPrefix + familyID))
}

func TestRotateRefreshToken_IdleExpired(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newOAuthTestApp(t)
	user := createTestUser(t, app, 9104, true, false)

	ctx := newTestContext(app, http.MethodPost, "/auth/grant-password/refresh-token", nil)

	// login atual grava o refresh token no formato legado (sem prefixo)
	data, err := auth_oauth2_password.Oauth2GenerateAndSaveToken(ctx, user)
	assert.NoError(err)
	assert.True(testRedis.Exists(data.RefreshToken))

	// simula o TTL vencendo: encurta a chave e avança o relógio do miniredis
	testRedis.SetTTL(data.RefreshToken, 2*time.Second)
	testRedis.FastForward(3 * time.Second)

	pair, user, rerr := auth_oauth2_password.RotateRefreshToken(ctx, data.RefreshToken)
	assert.Nil(pair)
	assert.Nil(user)
	assert.NotNil(rerr)
	assert.Equal(auth_oauth2_password.ErrExpiredIdle, rerr.Kind)
}

func TestRotateRefreshToken_AbsoluteExpiredRevokesFamily(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newOAuthTestApp(t)
	createTestUser(t, app, 9105, true, false)

	refreshToken := seedNewRefreshToken(t, "9105")
	ctx := newTestContext(app, http.MethodPost, "/auth/grant-password/refresh-token", nil)

	pair1, _, rerr := auth_oauth2_password.RotateRefreshToken(ctx, refreshToken)
	assert.Nil(rerr)

	familyID := getFamilyID(t, refreshToken)

	// força o teto absoluto no passado no record do refresh novo
	str, err := testRedis.Get(auth_oauth2_password.RefreshTokenKeyPrefix + pair1.RefreshToken)
	assert.NoError(err)

	var record auth_oauth2_password.RefreshTokenRecord
	assert.NoError(json.Unmarshal([]byte(str), &record))
	record.AbsoluteDeadline = time.Now().Add(-time.Hour)
	data, err := json.Marshal(record)
	assert.NoError(err)
	assert.NoError(testRedis.Set(auth_oauth2_password.RefreshTokenKeyPrefix+pair1.RefreshToken, string(data)))

	pair2, user, rerr := auth_oauth2_password.RotateRefreshToken(ctx, pair1.RefreshToken)
	assert.Nil(pair2)
	assert.Nil(user)
	assert.NotNil(rerr)
	assert.Equal(auth_oauth2_password.ErrExpiredAbsolute, rerr.Kind)

	// família revogada:
	assert.False(testRedis.Exists(auth_oauth2_password.RefreshTokenKeyPrefix + pair1.RefreshToken))
	assert.False(testRedis.Exists(auth_oauth2_password.RefreshTokenFamilyKeyPrefix + familyID))
}

func TestRotateRefreshToken_LegacyTokenMigratesToNewFormat(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newOAuthTestApp(t)
	user := createTestUser(t, app, 9106, true, false)

	ctx := newTestContext(app, http.MethodPost, "/auth/grant-password/refresh-token", nil)

	// SetRefreshToken grava no formato antigo: chave sem prefixo com o JSON
	// completo de Oauth2TokenData
	data, err := auth_oauth2_password.Oauth2GenerateAndSaveToken(ctx, user)
	assert.NoError(err)
	assert.True(testRedis.Exists(data.RefreshToken))

	pair, gotUser, rerr := auth_oauth2_password.RotateRefreshToken(ctx, data.RefreshToken)
	assert.Nil(rerr)
	assert.NotNil(pair)
	assert.Equal(user.GetID(), gotUser.GetID())

	// chave legado consumida...
	assert.False(testRedis.Exists(data.RefreshToken))

	// ...e token migrado para o formato novo com record completo:
	str, err := testRedis.Get(auth_oauth2_password.RefreshTokenKeyPrefix + pair.RefreshToken)
	assert.NoError(err)

	var record auth_oauth2_password.RefreshTokenRecord
	assert.NoError(json.Unmarshal([]byte(str), &record))
	assert.Equal(user.GetID(), record.OwnerID.String())
	assert.NotEmpty(record.FamilyID)
	assert.True(record.AbsoluteDeadline.After(time.Now()))

	// cadeia segue no formato novo: a rotação seguinte funciona
	pair2, _, rerr := auth_oauth2_password.RotateRefreshToken(ctx, pair.RefreshToken)
	assert.Nil(rerr)
	assert.NotNil(pair2)
	assert.NotEqual(pair.RefreshToken, pair2.RefreshToken)
}

func TestRotateRefreshToken_UserInvalid(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newOAuthTestApp(t)
	createTestUser(t, app, 9107, true, true)   // bloqueado
	createTestUser(t, app, 9108, false, false) // inativo

	ctx := newTestContext(app, http.MethodPost, "/auth/grant-password/refresh-token", nil)

	tests := []struct {
		name    string
		ownerID string
	}{
		{name: "blocked user", ownerID: "9107"},
		{name: "inactive user", ownerID: "9108"},
		{name: "user does not exist", ownerID: "999999"},
		{name: "empty owner", ownerID: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refreshToken := seedNewRefreshToken(t, tt.ownerID)

			pair, user, rerr := auth_oauth2_password.RotateRefreshToken(ctx, refreshToken)
			assert.Nil(pair)
			assert.NotNil(rerr)
			assert.Equal(auth_oauth2_password.ErrUserInvalid, rerr.Kind)

			// usuário inexistente não vem preenchido; inválido pode
			if tt.ownerID == "999999" || tt.ownerID == "" {
				assert.True(user == nil || user.ID == 0)
			}
		})
	}
}

func TestRevokeByRefreshToken(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newOAuthTestApp(t)
	user := createTestUser(t, app, 9109, true, false)

	ctx := newTestContext(app, http.MethodPost, "/auth/grant-password/refresh-token", nil)

	t.Run("revokes family from active token", func(t *testing.T) {
		refreshToken := seedNewRefreshToken(t, "9109")
		pair, _, rerr := auth_oauth2_password.RotateRefreshToken(ctx, refreshToken)
		assert.Nil(rerr)
		familyID := getFamilyID(t, refreshToken)

		err := auth_oauth2_password.RevokeByRefreshToken(pair.RefreshToken)
		assert.NoError(err)

		assert.False(testRedis.Exists(auth_oauth2_password.RefreshTokenKeyPrefix + pair.RefreshToken))
		assert.False(testRedis.Exists(auth_oauth2_password.RefreshTokenFamilyKeyPrefix + familyID))
	})

	t.Run("revokes family from used token tombstone", func(t *testing.T) {
		refreshToken := seedNewRefreshToken(t, "9109")
		pair, _, rerr := auth_oauth2_password.RotateRefreshToken(ctx, refreshToken)
		assert.Nil(rerr)
		familyID := getFamilyID(t, refreshToken)

		// revoga pelo token VELHO (já usado): tombstone resolve a família
		err := auth_oauth2_password.RevokeByRefreshToken(refreshToken)
		assert.NoError(err)

		assert.False(testRedis.Exists(auth_oauth2_password.RefreshTokenKeyPrefix + pair.RefreshToken))
		assert.False(testRedis.Exists(auth_oauth2_password.RefreshTokenFamilyKeyPrefix + familyID))
	})

	t.Run("revokes legacy token", func(t *testing.T) {
		data, err := auth_oauth2_password.Oauth2GenerateAndSaveToken(ctx, user)
		assert.NoError(err)
		assert.True(testRedis.Exists(data.RefreshToken))

		err = auth_oauth2_password.RevokeByRefreshToken(data.RefreshToken)
		assert.NoError(err)
		assert.False(testRedis.Exists(data.RefreshToken))
	})

	t.Run("unknown token is not an error", func(t *testing.T) {
		err := auth_oauth2_password.RevokeByRefreshToken(uuid.New().String())
		assert.NoError(err)

		err = auth_oauth2_password.RevokeByRefreshToken("")
		assert.NoError(err)
	})
}

func TestRevokeOauth2TokenHandler(t *testing.T) {
	assert := assert.New(t)
	flushRedis()
	app := newOAuthTestApp(t)
	user := createTestUser(t, app, 9110, true, false)

	ctx := newTestContext(app, http.MethodPost, "/auth/grant-password/revoke", nil)

	doRevoke := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/grant-password/revoke", strings.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderAccept, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		app.GetRouter().ServeHTTP(rec, req)
		return rec
	}

	t.Run("revokes refresh token with default hint and always answers 200", func(t *testing.T) {
		data, err := auth_oauth2_password.Oauth2GenerateAndSaveToken(ctx, user)
		assert.NoError(err)

		rec := doRevoke(`{"token":"` + data.RefreshToken + `"}`)
		assert.Equal(http.StatusOK, rec.Code)
		assert.JSONEq(`{}`, rec.Body.String())

		// token deixa de funcionar:
		assert.False(testRedis.Exists(data.RefreshToken))
	})

	t.Run("revokes rotated token family with refresh_token hint", func(t *testing.T) {
		refreshToken := seedNewRefreshToken(t, "9110")
		pair, _, rerr := auth_oauth2_password.RotateRefreshToken(ctx, refreshToken)
		assert.Nil(rerr)

		rec := doRevoke(`{"token":"` + pair.RefreshToken + `","token_type_hint":"refresh_token"}`)
		assert.Equal(http.StatusOK, rec.Code)
		assert.False(testRedis.Exists(auth_oauth2_password.RefreshTokenKeyPrefix + pair.RefreshToken))
	})

	t.Run("revokes access token with access_token hint", func(t *testing.T) {
		data, err := auth_oauth2_password.Oauth2GenerateAndSaveToken(ctx, user)
		assert.NoError(err)
		assert.True(testRedis.Exists(data.AccessToken))

		rec := doRevoke(`{"token":"` + data.AccessToken + `","token_type_hint":"access_token"}`)
		assert.Equal(http.StatusOK, rec.Code)
		assert.False(testRedis.Exists(data.AccessToken))
	})

	t.Run("unknown but well formed token still answers 200", func(t *testing.T) {
		rec := doRevoke(`{"token":"nao-existe-` + uuid.New().String() + `"}`)
		assert.Equal(http.StatusOK, rec.Code)
	})

	t.Run("missing token fails validation", func(t *testing.T) {
		rec := doRevoke(`{}`)
		assert.NotEqual(http.StatusOK, rec.Code)
	})

	t.Run("invalid body returns 404 like other handlers", func(t *testing.T) {
		rec := doRevoke(`not-json`)
		assert.Equal(http.StatusNotFound, rec.Code)
	})
}
