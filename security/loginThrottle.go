package security

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-bolo/bolo"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

var (
	MaxErrors = 3
	ResetTime = time.Minute * 10
	WaitTime  = time.Minute * 10
)

type LoginThrottleInterface interface {
	CanLogin(userID string, c echo.Context) (bool, error)
	OnLoginFail(userID string, c echo.Context) error
	OnLoginSuccess(userID string, c echo.Context) error
	BuildKey(ip, userID string) string
}

func NewLoginThrottle(app bolo.App) *LoginThrottle {
	db := app.GetConfiguration().GetIntF("SITE_OAUTH2_DB", 1)
	writerAddr := app.GetConfiguration().GetF("AUTH_THROTTLE_REDIS_ADDR_WRITER", "127.0.0.1:6379")
	readerAddr := app.GetConfiguration().GetF("AUTH_THROTTLE_REDIS_ADDR_READER", "127.0.0.1:6379")

	DBWriter := redis.NewClient(&redis.Options{
		Addr: writerAddr, // ex localhost:6379
		DB:   db,
	})

	DBReader := redis.NewClient(&redis.Options{
		Addr: readerAddr, // ex localhost:6379
		DB:   db,
	})

	return &LoginThrottle{
		DBWriter: DBWriter,
		DBReader: DBReader,
	}
}

type DBRedisInterface interface {
	Get(ctx context.Context, key string) *redis.StringCmd
}

type LoginThrottle struct {
	DBWriter *redis.Client
	DBReader *redis.Client
}

func (l *LoginThrottle) BuildKey(ip, userID string) string {
	return ip + "_" + userID
}

func (l *LoginThrottle) GetAccessRegistry(key string) *LoginThrottleStatus {
	ctx := context.Background()

	v, err := l.DBReader.Get(ctx, key).Result()
	if err != nil {
		return nil
	}

	lts := LoginThrottleStatus{}
	err = json.Unmarshal([]byte(v), &lts)
	if err != nil {
		return nil
	}

	return &lts
}

func (l *LoginThrottle) SetAccessRegistry(lts *LoginThrottleStatus) error {
	ctx := context.Background()
	err := l.DBReader.Set(ctx, lts.Key, lts.ToJSON(), ResetTime).Err()
	if err != nil {
		return nil
	}

	return nil
}

func (l *LoginThrottle) CanLogin(userID string, c echo.Context) (bool, error) {
	ip := c.RealIP()
	key := l.BuildKey(ip, userID)

	f := l.GetAccessRegistry(key)

	if f == nil || f.Can() {
		return true, nil
	}

	return false, nil
}

func (l *LoginThrottle) OnLoginFail(userID string, c echo.Context) error {
	ip := c.RealIP()
	key := l.BuildKey(ip, userID)

	f := l.GetAccessRegistry(key)
	if f == nil {
		f = &LoginThrottleStatus{
			Key:   key,
			Count: 0,
		}
	} else {
		if f.Count >= 3 {
			f.WaitTime = time.Now().Add(WaitTime).Unix()
		}

		f.Count++
	}

	return l.SetAccessRegistry(f)
}

func (l *LoginThrottle) OnLoginSuccess(userID string, c echo.Context) error {
	ip := c.RealIP()
	key := l.BuildKey(ip, userID)

	f := l.GetAccessRegistry(key)
	if f != nil {
		f.Count = 0
		f.WaitTime = 0
		return l.SetAccessRegistry(f)
	}

	return nil
}

type LoginThrottleStatus struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
	// unix timestamp
	WaitTime int64 `json:"wait_time"`
}

func (lts *LoginThrottleStatus) Can() bool {
	now := time.Now().Unix()

	if now > lts.WaitTime {
		return true
	}

	lts.OnError()

	return false
}

func (lts *LoginThrottleStatus) OnError() {
	lts.Count++

	if lts.Count >= MaxErrors {
		lts.WaitTime = time.Now().Add(WaitTime).Unix()
	}
}

func (lts *LoginThrottleStatus) ToJSON() string {
	jsonString, _ := json.Marshal(lts)
	return string(jsonString)
}
