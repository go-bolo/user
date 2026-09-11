package user_oauth2_password

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/go-bolo/bolo"
	"github.com/go-bolo/bolo/helpers"
	"github.com/google/uuid"
)

// AccessTokenFormat seleciona o formato do access token emitido nos fluxos de
// geração/rotação de tokens.
type AccessTokenFormat int

const (
	// FormatOpaque: access token opaco (uuid + random) gravado no Redis e
	// validado pelo middleware oauth2TokenAuthentication. Fluxo legado.
	FormatOpaque AccessTokenFormat = iota
	// FormatJWT: access JWT stateless — NÃO é gravado no Redis; a validação é
	// criptográfica (middleware do subplugin oauth2_jwt). Apenas o refresh
	// token mantém estado no Redis.
	FormatJWT
)

// JWTAccessGenerator emite o access token no formato JWT. Registrado pelo
// subplugin oauth2_jwt no evento configuration (dono do segredo e dos
// claims); este pacote permanece agnóstico aos detalhes criptográficos.
type JWTAccessGenerator func(ctx *bolo.RequestContext, u bolo.UserInterface) (accessToken string, expiresIn int64, err error)

var (
	jwtAccessGeneratorMu sync.RWMutex
	jwtAccessGenerator   JWTAccessGenerator
)

// SetJWTAccessGenerator registra o gerador de access tokens JWT usado por
// Oauth2GenerateAndSaveTokenJWT e RotateRefreshTokenWithFormat.
func SetJWTAccessGenerator(gen JWTAccessGenerator) {
	jwtAccessGeneratorMu.Lock()
	defer jwtAccessGeneratorMu.Unlock()
	jwtAccessGenerator = gen
}

// generateJWTAccess devolve o access JWT via gerador registrado; sem gerador
// (subplugin oauth2_jwt não instalado) devolve erro explícito em vez de
// emitir token em formato desconhecido.
func generateJWTAccess(ctx *bolo.RequestContext, u bolo.UserInterface) (string, int64, error) {
	jwtAccessGeneratorMu.RLock()
	gen := jwtAccessGenerator
	jwtAccessGeneratorMu.RUnlock()

	if gen == nil {
		return "", 0, errors.New("oauth2_password: gerador de access token JWT não registrado (subplugin oauth2_jwt não instalado?)")
	}

	return gen(ctx, u)
}

// generateAccessTokenForFormat emite o access token no formato pedido e
// persiste o que cada formato precisa: o opaco é gravado no Redis (fluxo
// legado); o JWT é stateless e não toca o storage.
func generateAccessTokenForFormat(reqCtx *bolo.RequestContext, u bolo.UserInterface, format AccessTokenFormat) (string, int64, error) {
	if format == FormatJWT {
		return generateJWTAccess(reqCtx, u)
	}

	data, err := Oauth2GenerateToken(reqCtx, u)
	if err != nil {
		return "", 0, err
	}

	dataJSON, _ := json.MarshalIndent(data, "", "  ")

	if err := SetAccessToken(reqCtx, data.AccessToken, string(dataJSON)); err != nil {
		return "", 0, err
	}

	return data.AccessToken, data.ExpiresIn, nil
}

// generateRefreshToken devolve um refresh token opaco: o uuid v4 carrega a
// entropia dominante (mesma construção do fluxo legado).
func generateRefreshToken() string {
	return uuid.New().String() + helpers.RandStringBytes(35)
}
