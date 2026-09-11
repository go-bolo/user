package user_oauth2_jwt_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	auth_oauth2_jwt "github.com/go-bolo/user/oauth2_jwt"
)

// tokenOption customiza a emissão artesanal de tokens para a tabela de
// validação: claims mutadas, algoritmo, secret e kid alternativos.
type tokenOption struct {
	mutateClaims func(*auth_oauth2_jwt.AccessClaims)
	alg          jwt.SigningMethod
	secret       string
	kid          string
}

// craftToken emite um HS256 válido por padrão (mesma forma do
// GenerateAccessToken) e aplica só as mutações pedidas — cada caso da tabela
// quebra exclusivamente a propriedade que quer testar.
func craftToken(t *testing.T, cfg *auth_oauth2_jwt.Config, opt tokenOption) string {
	t.Helper()

	claims := auth_oauth2_jwt.AccessClaims{
		Roles:  []string{"authenticated"},
		Active: true,
		StandardClaims: jwt.StandardClaims{
			Audience:  cfg.Audience,
			ExpiresAt: time.Now().Add(cfg.TTL).Unix(),
			Id:        uuid.New().String(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    cfg.Issuer,
			NotBefore: time.Now().Unix(),
			Subject:   "42",
		},
	}

	if opt.mutateClaims != nil {
		opt.mutateClaims(&claims)
	}

	var alg jwt.SigningMethod = jwt.SigningMethodHS256
	if opt.alg != nil {
		alg = opt.alg
	}

	secret := cfg.Secret
	if opt.secret != "" {
		secret = opt.secret
	}

	kid := auth_oauth2_jwt.KeyID
	if opt.kid != "" {
		kid = opt.kid
	}

	tok := jwt.NewWithClaims(alg, claims)
	tok.Header["kid"] = kid

	signed, err := tok.SignedString([]byte(secret))
	assert.NoError(t, err)

	return signed
}

// TestValidateAccessToken percorre em tabela o contrato completo do
// validador: assinatura/secret, algoritmo pinado, kid, iss/aud, sub, jti e
// janelas temporais (exp/nbf/iat) com o leeway configurado. Fail-closed:
// claim ausente rejeita.
func TestValidateAccessToken(t *testing.T) {
	cfg := unitConfig()

	tests := []struct {
		name      string
		build     func(t *testing.T) string
		wantErr   bool
		wantErrIs error
	}{
		{
			name: "token emitido pelo GenerateAccessToken",
			build: func(t *testing.T) string {
				token, _, err := auth_oauth2_jwt.GenerateAccessToken(cfg, &unitUser{id: "42"})
				assert.NoError(t, err)
				return token
			},
		},
		{
			name: "token artesanal com todas as claims corretas",
			build: func(t *testing.T) string {
				return craftToken(t, cfg, tokenOption{})
			},
		},
		{
			name: "expirado dentro do leeway ainda aceita",
			build: func(t *testing.T) string {
				expired := unitConfig()
				expired.TTL = -(cfg.Leeway - 10*time.Second)
				token, _, err := auth_oauth2_jwt.GenerateAccessToken(expired, &unitUser{id: "42"})
				assert.NoError(t, err)
				return token
			},
		},
		{
			name: "expirado além do leeway",
			build: func(t *testing.T) string {
				expired := unitConfig()
				expired.TTL = -(cfg.Leeway + time.Minute)
				token, _, err := auth_oauth2_jwt.GenerateAccessToken(expired, &unitUser{id: "42"})
				assert.NoError(t, err)
				return token
			},
			wantErr:   true,
			wantErrIs: auth_oauth2_jwt.ErrTokenExpired,
		},
		{
			name: "exp ausente rejeita fail-closed",
			build: func(t *testing.T) string {
				return craftToken(t, cfg, tokenOption{mutateClaims: func(c *auth_oauth2_jwt.AccessClaims) {
					c.ExpiresAt = 0
				}})
			},
			wantErr:   true,
			wantErrIs: auth_oauth2_jwt.ErrTokenExpired,
		},
		{
			name: "issuer diferente do configurado",
			build: func(t *testing.T) string {
				return craftToken(t, cfg, tokenOption{mutateClaims: func(c *auth_oauth2_jwt.AccessClaims) {
					c.Issuer = "https://evil.example"
				}})
			},
			wantErr: true,
		},
		{
			name: "audience diferente da configurada",
			build: func(t *testing.T) string {
				return craftToken(t, cfg, tokenOption{mutateClaims: func(c *auth_oauth2_jwt.AccessClaims) {
					c.Audience = "outro-app"
				}})
			},
			wantErr: true,
		},
		{
			name: "subject vazio",
			build: func(t *testing.T) string {
				return craftToken(t, cfg, tokenOption{mutateClaims: func(c *auth_oauth2_jwt.AccessClaims) {
					c.Subject = ""
				}})
			},
			wantErr: true,
		},
		{
			name: "subject não numérico",
			build: func(t *testing.T) string {
				return craftToken(t, cfg, tokenOption{mutateClaims: func(c *auth_oauth2_jwt.AccessClaims) {
					c.Subject = "quarenta-e-dois"
				}})
			},
			wantErr: true,
		},
		{
			name: "jti vazio",
			build: func(t *testing.T) string {
				return craftToken(t, cfg, tokenOption{mutateClaims: func(c *auth_oauth2_jwt.AccessClaims) {
					c.Id = ""
				}})
			},
			wantErr: true,
		},
		{
			name: "nbf no futuro além do leeway",
			build: func(t *testing.T) string {
				return craftToken(t, cfg, tokenOption{mutateClaims: func(c *auth_oauth2_jwt.AccessClaims) {
					c.NotBefore = time.Now().Add(5 * time.Minute).Unix()
				}})
			},
			wantErr: true,
		},
		{
			name: "iat no futuro além do leeway",
			build: func(t *testing.T) string {
				return craftToken(t, cfg, tokenOption{mutateClaims: func(c *auth_oauth2_jwt.AccessClaims) {
					c.IssuedAt = time.Now().Add(5 * time.Minute).Unix()
				}})
			},
			wantErr: true,
		},
		{
			name: "assinado com secret diferente",
			build: func(t *testing.T) string {
				return craftToken(t, cfg, tokenOption{secret: "outra-chave-super-secreta-diferente"})
			},
			wantErr: true,
		},
		{
			name: "kid desconhecido no header",
			build: func(t *testing.T) string {
				return craftToken(t, cfg, tokenOption{kid: "9"})
			},
			wantErr: true,
		},
		{
			name: "algoritmo HS384 com o mesmo secret",
			build: func(t *testing.T) string {
				return craftToken(t, cfg, tokenOption{alg: jwt.SigningMethodHS384})
			},
			wantErr: true,
		},
		{
			name: "algoritmo HS512 com o mesmo secret",
			build: func(t *testing.T) string {
				return craftToken(t, cfg, tokenOption{alg: jwt.SigningMethodHS512})
			},
			wantErr: true,
		},
		{
			name: "alg none sem assinatura",
			build: func(t *testing.T) string {
				tok := jwt.NewWithClaims(jwt.SigningMethodNone, auth_oauth2_jwt.AccessClaims{})
				signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
				assert.NoError(t, err)
				return signed
			},
			wantErr: true,
		},
		{
			name: "payload adulterado quebra a assinatura",
			build: func(t *testing.T) string {
				valid := craftToken(t, cfg, tokenOption{})
				parts := splitToken(t, valid)
				return parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"43"}`)) + "." + parts[2]
			},
			wantErr: true,
		},
		{
			name: "token opaco do fluxo legado",
			build: func(t *testing.T) string {
				return "6ba7b810-9dad-11d1-80b4-00c04fd430c8RaNdoM35"
			},
			wantErr: true,
		},
		{
			name: "string vazia",
			build: func(t *testing.T) string {
				return ""
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			claims, err := auth_oauth2_jwt.ValidateAccessToken(cfg, tt.build(t))

			if tt.wantErr {
				assert.Error(err)
				assert.Nil(claims)
				if tt.wantErrIs != nil {
					assert.ErrorIs(err, tt.wantErrIs)
				}
				return
			}

			assert.NoError(err)
			assert.NotNil(claims)
			assert.Equal("42", claims.Subject)
		})
	}
}

// TestGenerateAccessToken_Table verifica em tabela a emissão: expires_in
// reflete o TTL configurado e o snapshot do usuário (roles/active/blocked)
// sobrevive intacto ao roundtrip emissão->validação.
func TestGenerateAccessToken_Table(t *testing.T) {
	tests := []struct {
		name          string
		user          *unitUser
		ttl           time.Duration
		wantExpiresIn int64
	}{
		{
			name:          "usuário ativo com roles",
			user:          &unitUser{id: "42", roles: []string{"authenticated", "premium"}, active: true},
			ttl:           10 * time.Minute,
			wantExpiresIn: 600,
		},
		{
			name:          "usuário bloqueado entra no snapshot",
			user:          &unitUser{id: "7", active: true, blocked: true},
			ttl:           15 * time.Minute,
			wantExpiresIn: 900,
		},
		{
			name:          "sem roles omite o claim",
			user:          &unitUser{id: "9", active: true},
			ttl:           time.Minute,
			wantExpiresIn: 60,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			cfg := unitConfig()
			cfg.TTL = tt.ttl

			token, expiresIn, err := auth_oauth2_jwt.GenerateAccessToken(cfg, tt.user)
			assert.NoError(err)
			assert.Equal(tt.wantExpiresIn, expiresIn)
			assert.True(auth_oauth2_jwt.LooksLikeJWT(token))

			claims, err := auth_oauth2_jwt.ValidateAccessToken(cfg, token)
			assert.NoError(err)
			assert.Equal(tt.user.id, claims.Subject)
			assert.Equal(tt.user.roles, claims.Roles)
			assert.Equal(tt.user.active, claims.Active)
			assert.Equal(tt.user.blocked, claims.Blocked)
		})
	}
}

// TestBuildUserStubFromClaims_Table verifica em tabela o stub de usuário
// montado pelo middleware: ID parseado do subject, snapshot active/blocked e
// RolesText alimentado com o JSON das roles do claim.
func TestBuildUserStubFromClaims_Table(t *testing.T) {
	tests := []struct {
		name        string
		claims      *auth_oauth2_jwt.AccessClaims
		wantID      uint64
		wantActive  bool
		wantBlocked bool
		wantRoles   []string
	}{
		{
			name: "claims completos",
			claims: &auth_oauth2_jwt.AccessClaims{
				Roles:   []string{"administrator", "premium"},
				Active:  true,
				Blocked: false,
				StandardClaims: jwt.StandardClaims{
					Subject: "42",
				},
			},
			wantID:     42,
			wantActive: true,
			wantRoles:  []string{"administrator", "premium"},
		},
		{
			name: "snapshot inativo e bloqueado",
			claims: &auth_oauth2_jwt.AccessClaims{
				Active:  false,
				Blocked: true,
				StandardClaims: jwt.StandardClaims{
					Subject: "7",
				},
			},
			wantID:      7,
			wantBlocked: true,
		},
		{
			name: "subject não numérico zera o ID",
			claims: &auth_oauth2_jwt.AccessClaims{
				Active: true,
				StandardClaims: jwt.StandardClaims{
					Subject: "abc",
				},
			},
			wantID:     0,
			wantActive: true,
		},
		{
			name: "roles vazia devolve RolesText null",
			claims: &auth_oauth2_jwt.AccessClaims{
				Active: true,
				StandardClaims: jwt.StandardClaims{
					Subject: "9",
				},
			},
			wantID:     9,
			wantActive: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			stub := auth_oauth2_jwt.BuildUserStubFromClaims(tt.claims)

			assert.Equal(tt.wantID, stub.ID)
			assert.Equal(tt.wantActive, stub.IsActive())
			assert.Equal(tt.wantBlocked, stub.IsBlocked())

			var roles []string
			assert.NoError(json.Unmarshal([]byte(stub.RolesText), &roles))
			assert.Equal(tt.wantRoles, roles)
		})
	}
}
