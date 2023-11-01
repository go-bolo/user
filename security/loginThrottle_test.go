package security_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-bolo/bolo"
	"github.com/go-bolo/user/security"
	"github.com/go-redis/redismock/v9"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

func NewLoginThottleBaseTestContext(userID, ip string) (*security.LoginThrottle, echo.Context, redismock.ClientMock) {
	db, mock := redismock.NewClientMock()
	app := GetAppInstance()

	lInstance := security.NewLoginThrottle(app)
	lInstance.DBWriter = db
	lInstance.DBReader = db

	e := app.GetRouter()

	payload := `{}`
	req, err := http.NewRequest(http.MethodPost, "/any", strings.NewReader(payload))
	if err != nil {
		panic(err)
	}

	req.Header.Add("X-Forwarded-For", ip)

	res := httptest.NewRecorder()

	user1Ctx := e.NewContext(req, res)

	return lInstance, user1Ctx, mock
}

func TestLoginThottle_canLogin(t *testing.T) {
	userID := "10"
	ip := "127.0.0.1"

	lInstance, user1Ctx, redisMock := NewLoginThottleBaseTestContext(userID, ip)

	type args struct {
		c echo.Context
	}
	tests := []struct {
		name             string
		l                security.LoginThrottleInterface
		args             args
		want             bool
		wantErr          bool
		redisRecordIsNil bool
		redisStoredData  *security.LoginThrottleStatus
	}{
		{
			name: "success",
			l:    lInstance,
			args: args{
				c: user1Ctx,
			},
			want:             true,
			wantErr:          false,
			redisRecordIsNil: true,
		},
		{
			name: "error on locked by login errors count",
			l:    lInstance,
			args: args{
				c: user1Ctx,
			},
			want:             false,
			wantErr:          false,
			redisRecordIsNil: false,
			redisStoredData: &security.LoginThrottleStatus{
				Count:    3,
				WaitTime: time.Now().Add(time.Minute * 2).Unix(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.redisRecordIsNil {
				redisMock.ExpectGet(tt.l.BuildKey(ip, userID)).RedisNil()
			} else {
				redisMock.ExpectGet(tt.l.BuildKey(ip, userID)).SetVal(tt.redisStoredData.ToJSON())
			}

			got, err := tt.l.CanLogin(userID, tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoginThottle.canLogin() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("LoginThottle.canLogin() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoginThottle_onLoginFail(t *testing.T) {
	db, mock := redismock.NewClientMock()
	app := GetAppInstance()

	userID := "11"

	lInstance := security.NewLoginThrottle(app)
	lInstance.DBWriter = db
	lInstance.DBReader = db

	e := app.GetRouter()

	payload := `{}`
	req, err := http.NewRequest(http.MethodPost, "/any", strings.NewReader(payload))
	if err != nil {
		t.Errorf("TestCreateOne error: %v", err)
	}

	req.Header.Add("X-Forwarded-For", "127.0.0.1")

	res := httptest.NewRecorder()

	user1Ctx := e.NewContext(req, res)

	type args struct {
		userID string
		c      echo.Context
	}
	tests := []struct {
		name             string
		l                security.LoginThrottleInterface
		args             args
		want             bool
		wantErr          bool
		redisRecordIsNil bool
		redisStoredData  *security.LoginThrottleStatus
	}{
		{
			name: "success",
			l:    lInstance,
			args: args{
				c:      user1Ctx,
				userID: "13",
			},
			want:             true,
			wantErr:          false,
			redisRecordIsNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.redisRecordIsNil {
				mock.ExpectGet("127.0.0.1").RedisNil()
			} else {
				mock.ExpectGet("127.0.0.1").SetVal(tt.redisStoredData.ToJSON())
			}

			if err := tt.l.OnLoginFail(userID, tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("LoginThottle.onLoginFail() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoginThottle_onLoginSuccess(t *testing.T) {
	type args struct {
		userID string
		c      echo.Context
	}
	tests := []struct {
		name    string
		l       *security.LoginThrottle
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &security.LoginThrottle{}
			if err := l.OnLoginSuccess(tt.args.userID, tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("LoginThottle.onLoginSuccess() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func NewTestLoginThrottle(app bolo.App) *security.LoginThrottle {
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

	return &security.LoginThrottle{
		DBWriter: DBWriter,
		DBReader: DBReader,
	}
}
