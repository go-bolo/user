package user_oauth2_password

import (
	"github.com/go-bolo/bolo"
	"github.com/redis/go-redis/v9"
)

var storageInitialized bool

// var accessTokenPrefix string = "AT:"
// var refreshTokenPrefix string = "RT:"

var accessTokenPrefix string = ""
var refreshTokenPrefix string = ""

var (
	// StorageDBWriter - Oauth tokens redis cache connection
	StorageDBWriter *redis.Client
	// StorageDBReader - Oauth tokens redis cache connection
	StorageDBReader *redis.Client
)

// InitStorage - Start the redis cache connection
func InitStorage(app bolo.App) {
	if !storageInitialized {
		cfgs := app.GetConfiguration()

		addrWriter := cfgs.Get("SITE_OAUTH2_ADDR_WRITER")
		addrReader := cfgs.Get("SITE_OAUTH2_ADDR_READER")
		db := cfgs.GetIntF("SITE_OAUTH2_DB", 1)
		password := cfgs.GetF("SITE_OAUTH2_PASSWORD", "")

		if StorageDBWriter == nil {
			StorageDBWriter = redis.NewClient(&redis.Options{
				Addr:     addrWriter, // ex localhost:6379
				Password: password,
				DB:       db,
			})
		}

		if StorageDBReader == nil {
			StorageDBReader = redis.NewClient(&redis.Options{
				Addr:     addrReader, // ex localhost:6379
				Password: password,
				DB:       db,
			})
		}

		storageInitialized = true
	}
}

func GetAccessToken(accessToken string) (string, error) {
	key := accessTokenPrefix + accessToken
	return StorageDBReader.Get(ctx, key).Result()
}

func SetAccessToken(c *bolo.RequestContext, accessToken string, value string) error {
	// TTL configurável com unidade (OAUTH2_ACCESS_TOKEN_TTL); erro de config
	// é explícito — não grava token com prazo errado
	expire, err := AccessTokenTTL(c.App.GetConfiguration())
	if err != nil {
		return err
	}

	key := accessTokenPrefix + accessToken
	return StorageDBWriter.Set(ctx, key, value, expire).Err()
}

func DeleteAccessToken(c *bolo.RequestContext, accessToken string) error {
	key := accessTokenPrefix + accessToken
	return StorageDBWriter.Del(ctx, key).Err()
}

// GetRefreshToken lê a chave legada (sem prefixo) do refresh token.
//
// Deprecated: o formato legado é somente leitura/migração; use
// RotateRefreshToken/RevokeByRefreshToken, que enxergam os dois formatos.
func GetRefreshToken(refreshToken string) (string, error) {
	key := refreshTokenPrefix + refreshToken
	return StorageDBReader.Get(ctx, key).Result()
}

func SetRefreshToken(c *bolo.RequestContext, refreshToken string, value string) error {
	cfgs := c.App.GetConfiguration()

	// Mesma fonte de verdade da rotação: o login grava o refresh legado já
	// com o TTL idle configurado (evita primeiro ciclo com prazo diferente).
	idleTTL, err := RefreshIdleTTL(cfgs)
	if err != nil {
		return err
	}

	key := refreshTokenPrefix + refreshToken
	return StorageDBWriter.Set(ctx, key, value, idleTTL).Err()
}
