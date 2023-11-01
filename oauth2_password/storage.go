package user_oauth2_password

import (
	"time"

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

// initStorage - Start the redis cache connection
func initStorage(app bolo.App) {
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
	cfgs := c.App.GetConfiguration()
	expiration := cfgs.GetInt64F("OAUTH2_ACCESS_TOKEN_EXPIRATION", 30)

	key := accessTokenPrefix + accessToken
	expire := time.Duration(expiration) * time.Minute
	return StorageDBWriter.Set(ctx, key, value, expire).Err()
}

func DeleteAccessToken(c *bolo.RequestContext, accessToken string) error {
	key := accessTokenPrefix + accessToken
	return StorageDBWriter.Del(ctx, key).Err()
}

func GetRefreshToken(refreshToken string) (string, error) {
	key := refreshTokenPrefix + refreshToken
	return StorageDBReader.Get(ctx, key).Result()
}

func SetRefreshToken(c *bolo.RequestContext, refreshToken string, value string) error {
	cfgs := c.App.GetConfiguration()
	expiration := cfgs.GetInt64F("OAUTH2_REFRESH_TOKEN_EXPIRATION", 3*1440)

	key := refreshTokenPrefix + refreshToken
	expire := time.Duration(expiration) * time.Minute
	return StorageDBWriter.Set(ctx, key, value, expire).Err()
}
