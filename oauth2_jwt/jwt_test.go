package user_oauth2_jwt_test

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	auth_oauth2_jwt "github.com/go-bolo/user/oauth2_jwt"
)

// unitUser é um bolo.UserInterface mínimo para emissão de tokens.
type unitUser struct {
	id      string
	roles   []string
	active  bool
	blocked bool
}

func (u *unitUser) GetID() string                 { return u.id }
func (u *unitUser) SetID(id string) error         { u.id = id; return nil }
func (u *unitUser) GetRoles() []string            { return u.roles }
func (u *unitUser) SetRoles(v []string) error     { u.roles = v; return nil }
func (u *unitUser) AddRole(role string) error     { return nil }
func (u *unitUser) RemoveRole(role string) error  { return nil }
func (u *unitUser) GetEmail() string              { return "" }
func (u *unitUser) SetEmail(v string) error       { return nil }
func (u *unitUser) GetUsername() string           { return "" }
func (u *unitUser) SetUsername(v string) error    { return nil }
func (u *unitUser) GetDisplayName() string        { return "" }
func (u *unitUser) SetDisplayName(v string) error { return nil }
func (u *unitUser) GetFullName() string           { return "" }
func (u *unitUser) SetFullName(v string) error    { return nil }
func (u *unitUser) GetLanguage() string           { return "" }
func (u *unitUser) SetLanguage(v string) error    { return nil }
func (u *unitUser) IsActive() bool                { return u.active }
func (u *unitUser) SetActive(v bool) error        { u.active = v; return nil }
func (u *unitUser) IsBlocked() bool               { return u.blocked }
func (u *unitUser) SetBlocked(v bool) error       { u.blocked = v; return nil }
func (u *unitUser) FillById(ID string) error      { return nil }

func TestGenerateAccessToken_HappyPath(t *testing.T) {
	assert := assert.New(t)
	cfg := unitConfig()

	user := &unitUser{id: "42", roles: []string{"authenticated", "premium"}, active: true, blocked: false}

	token, expiresIn, err := auth_oauth2_jwt.GenerateAccessToken(cfg, user)
	assert.NoError(err)
	assert.Equal(int64(600), expiresIn)
	assert.True(auth_oauth2_jwt.LooksLikeJWT(token))

	// header: alg pinado + kid da chave única
	parts := splitToken(t, token)
	var header map[string]interface{}
	decodeJSONSegment(t, parts[0], &header)
	assert.Equal("HS256", header["alg"])
	assert.Equal(auth_oauth2_jwt.KeyID, header["kid"])

	claims, err := auth_oauth2_jwt.ValidateAccessToken(cfg, token)
	assert.NoError(err)
	assert.Equal("42", claims.Subject)
	assert.Equal(cfg.Issuer, claims.Issuer)
	assert.Equal(cfg.Audience, claims.Audience)
	assert.NotEmpty(claims.Id)
	assert.Equal([]string{"authenticated", "premium"}, claims.Roles)
	assert.True(claims.Active)
	assert.False(claims.Blocked)

	// jti é uuid v4 novo a cada emissão
	token2, _, err := auth_oauth2_jwt.GenerateAccessToken(cfg, user)
	assert.NoError(err)
	claims2, err := auth_oauth2_jwt.ValidateAccessToken(cfg, token2)
	assert.NoError(err)
	assert.NotEqual(claims.Id, claims2.Id)
	_, err = uuid.Parse(claims.Id)
	assert.NoError(err)

	// snapshot bloqueado entra no claim
	blockedUser := &unitUser{id: "42", active: true, blocked: true}
	token3, _, err := auth_oauth2_jwt.GenerateAccessToken(cfg, blockedUser)
	assert.NoError(err)
	claims3, err := auth_oauth2_jwt.ValidateAccessToken(cfg, token3)
	assert.NoError(err)
	assert.True(claims3.Blocked)
}

func TestValidateAccessToken_Expired(t *testing.T) {
	assert := assert.New(t)
	cfg := unitConfig()
	cfg.TTL = -2 * time.Minute

	token, _, err := auth_oauth2_jwt.GenerateAccessToken(cfg, &unitUser{id: "42"})
	assert.NoError(err)

	_, err = auth_oauth2_jwt.ValidateAccessToken(unitConfig(), token)
	assert.Equal(auth_oauth2_jwt.ErrTokenExpired, err)
}

func TestValidateAccessToken_Leeway(t *testing.T) {
	assert := assert.New(t)

	// expirado há 20s com leeway 30s: ainda aceito
	cfg := unitConfig()
	cfg.TTL = -20 * time.Second
	token, _, err := auth_oauth2_jwt.GenerateAccessToken(cfg, &unitUser{id: "42"})
	assert.NoError(err)
	_, err = auth_oauth2_jwt.ValidateAccessToken(unitConfig(), token)
	assert.NoError(err)

	// expirado há 40s com leeway 30s: rejeitado
	cfgFar := unitConfig()
	cfgFar.TTL = -40 * time.Second
	tokenFar, _, err := auth_oauth2_jwt.GenerateAccessToken(cfgFar, &unitUser{id: "42"})
	assert.NoError(err)
	_, err = auth_oauth2_jwt.ValidateAccessToken(unitConfig(), tokenFar)
	assert.Equal(auth_oauth2_jwt.ErrTokenExpired, err)

	// leeway também cobre nbf no futuro próximo: token emitido "agora" com
	// relógio do validador 10s atrás ainda é aceito
	cfgFuture := unitConfig()
	cfgFuture.Leeway = 30 * time.Second
	tokenFuture, _, err := auth_oauth2_jwt.GenerateAccessToken(cfgFuture, &unitUser{id: "42"})
	assert.NoError(err)

	cfgBehind := unitConfig()
	cfgBehind.Leeway = 30 * time.Second
	_, err = auth_oauth2_jwt.ValidateAccessToken(cfgBehind, tokenFuture)
	assert.NoError(err)
}

func TestValidateAccessToken_RejectsAlgNone(t *testing.T) {
	assert := assert.New(t)
	cfg := unitConfig()

	// token alg:none sem assinatura, claims válidos
	claims := auth_oauth2_jwt.AccessClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  cfg.Audience,
			ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
			Id:        uuid.New().String(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    cfg.Issuer,
			NotBefore: time.Now().Unix(),
			Subject:   "42",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	assert.NoError(err)

	_, err = auth_oauth2_jwt.ValidateAccessToken(cfg, signed)
	assert.Error(err)
}

func TestValidateAccessToken_RejectsAlgorithmConfusion(t *testing.T) {
	assert := assert.New(t)
	cfg := unitConfig()

	claims := auth_oauth2_jwt.AccessClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  cfg.Audience,
			ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
			Id:        uuid.New().String(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    cfg.Issuer,
			NotBefore: time.Now().Unix(),
			Subject:   "42",
		},
	}

	// HS384 assinado com o MESMO secret: assinatura válida, algoritmo errado
	t384 := jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	signed384, err := t384.SignedString([]byte(cfg.Secret))
	assert.NoError(err)
	_, err = auth_oauth2_jwt.ValidateAccessToken(cfg, signed384)
	assert.Error(err)

	// HS512 idem
	t512 := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signed512, err := t512.SignedString([]byte(cfg.Secret))
	assert.NoError(err)
	_, err = auth_oauth2_jwt.ValidateAccessToken(cfg, signed512)
	assert.Error(err)

	// RS256 (assimétrico) com assinatura qualquer
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"42","exp":` + strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10) + `}`))
	rs256Token := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
	_, err = auth_oauth2_jwt.ValidateAccessToken(cfg, rs256Token)
	assert.Error(err)
}

func TestValidateAccessToken_RejectsWrongSecretAndKid(t *testing.T) {
	assert := assert.New(t)
	cfg := unitConfig()

	token, _, err := auth_oauth2_jwt.GenerateAccessToken(cfg, &unitUser{id: "42"})
	assert.NoError(err)

	// secret diferente
	other := unitConfig()
	other.Secret = "outra-chave-super-secreta-diferente"
	_, err = auth_oauth2_jwt.ValidateAccessToken(other, token)
	assert.Error(err)

	// kid desconhecido com assinatura correta
	claims := auth_oauth2_jwt.AccessClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  cfg.Audience,
			ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
			Id:        uuid.New().String(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    cfg.Issuer,
			NotBefore: time.Now().Unix(),
			Subject:   "42",
		},
	}
	t9 := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t9.Header["kid"] = "9"
	signed9, err := t9.SignedString([]byte(cfg.Secret))
	assert.NoError(err)
	_, err = auth_oauth2_jwt.ValidateAccessToken(cfg, signed9)
	assert.Error(err)
}

func TestValidateAccessToken_RejectsWrongIssuerAudienceAndMissingClaims(t *testing.T) {
	assert := assert.New(t)
	cfg := unitConfig()

	craft := func(mutate func(*auth_oauth2_jwt.AccessClaims)) string {
		c := auth_oauth2_jwt.AccessClaims{
			StandardClaims: jwt.StandardClaims{
				Audience:  cfg.Audience,
				ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
				Id:        uuid.New().String(),
				IssuedAt:  time.Now().Unix(),
				Issuer:    cfg.Issuer,
				NotBefore: time.Now().Unix(),
				Subject:   "42",
			},
		}
		mutate(&c)

		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
		tok.Header["kid"] = auth_oauth2_jwt.KeyID
		signed, err := tok.SignedString([]byte(cfg.Secret))
		assert.NoError(err)
		return signed
	}

	_, err := auth_oauth2_jwt.ValidateAccessToken(cfg, craft(func(c *auth_oauth2_jwt.AccessClaims) { c.Issuer = "https://evil.example" }))
	assert.Error(err, "issuer errado deve ser rejeitado")

	_, err = auth_oauth2_jwt.ValidateAccessToken(cfg, craft(func(c *auth_oauth2_jwt.AccessClaims) { c.Audience = "outro-app" }))
	assert.Error(err, "audience errada deve ser rejeitada")

	_, err = auth_oauth2_jwt.ValidateAccessToken(cfg, craft(func(c *auth_oauth2_jwt.AccessClaims) { c.Subject = "" }))
	assert.Error(err, "subject vazio deve ser rejeitado")

	_, err = auth_oauth2_jwt.ValidateAccessToken(cfg, craft(func(c *auth_oauth2_jwt.AccessClaims) { c.Id = "" }))
	assert.Error(err, "jti vazio deve ser rejeitado")

	_, err = auth_oauth2_jwt.ValidateAccessToken(cfg, craft(func(c *auth_oauth2_jwt.AccessClaims) { c.Subject = "não-é-número" }))
	assert.Error(err, "subject não numérico deve ser rejeitado")

	// payload adulterado: assinatura deixa de bater
	valid, _, err := auth_oauth2_jwt.GenerateAccessToken(cfg, &unitUser{id: "42"})
	assert.NoError(err)
	parts := splitToken(t, valid)
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"43"}`)) + "." + parts[2]
	_, err = auth_oauth2_jwt.ValidateAccessToken(cfg, tampered)
	assert.Error(err)
}

func TestLooksLikeJWT(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{"JWS compacto de três segmentos", "aaa.bbb.ccc", true},
		{"token opaco do fluxo legado", "6ba7b810-9dad-11d1-80b4-00c04fd430c8RaNdoM35", false},
		{"apenas dois segmentos", "a.b", false},
		{"quatro segmentos", "a.b.c.d", false},
		{"segmento vazio", ".b.", false},
		{"string vazia", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, auth_oauth2_jwt.LooksLikeJWT(tt.token))
		})
	}
}

func splitToken(t *testing.T, token string) []string {
	t.Helper()
	parts := make([]string, 0, 3)
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	if len(parts) != 3 {
		t.Fatalf("token não tem 3 segmentos: %s", token)
	}
	return parts
}

func decodeJSONSegment(t *testing.T, segment string, out interface{}) {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("segmento não é base64url: %v", err)
	}

	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("segmento não é JSON: %v", err)
	}
}
