package user_oauth2_password_test

import (
	"testing"
	"time"

	"github.com/go-bolo/bolo/configuration"
	auth_oauth2_password "github.com/go-bolo/user/oauth2_password"
	"github.com/stretchr/testify/assert"
)

func TestParseTTL(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		fallback time.Duration
		want     time.Duration
		wantErr  bool
	}{
		{name: "minutes", value: "30m", want: 30 * time.Minute},
		{name: "hours", value: "12h", want: 12 * time.Hour},
		{name: "seconds", value: "45s", want: 45 * time.Second},
		{name: "days", value: "7d", want: 168 * time.Hour},
		{name: "30d", value: "30d", want: 720 * time.Hour},
		{name: "combined days and hours", value: "2d12h", want: 60 * time.Hour},
		{name: "combined days hours and minutes", value: "1d1h30m", want: 25*time.Hour + 30*time.Minute},
		{name: "fractional days", value: "1.5d", want: 36 * time.Hour},
		{name: "empty uses fallback", value: "", fallback: 5 * time.Minute, want: 5 * time.Minute},
		{name: "spaces are trimmed", value: "  30m  ", want: 30 * time.Minute},
		{name: "invalid value", value: "xpto", wantErr: true},
		{name: "missing unit", value: "30", wantErr: true},
		{name: "invalid unit", value: "30x", wantErr: true},
		{name: "zero is rejected", value: "0s", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := auth_oauth2_password.ParseTTL(tt.value, tt.fallback)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetOauth2TokenFromAuthorization(t *testing.T) {
	assert := assert.New(t)

	// Bearer é aceito:
	assert.Equal("abc", auth_oauth2_password.GetOauth2TokenFromAuthorization("Bearer abc"))
	// mais de um espaço quebra o formato (compatível com o comportamento atual):
	assert.Equal("", auth_oauth2_password.GetOauth2TokenFromAuthorization("Bearer abc "))

	// outros esquemas NÃO viram token (bug do split duplo corrigido):
	assert.Equal("", auth_oauth2_password.GetOauth2TokenFromAuthorization("Basic abc"))
	assert.Equal("", auth_oauth2_password.GetOauth2TokenFromAuthorization("Token abc"))

	// formatos quebrados:
	assert.Equal("", auth_oauth2_password.GetOauth2TokenFromAuthorization(""))
	assert.Equal("", auth_oauth2_password.GetOauth2TokenFromAuthorization("Bearer"))
	assert.Equal("", auth_oauth2_password.GetOauth2TokenFromAuthorization("Bearer a b"))
}

func TestAccessTokenTTL(t *testing.T) {
	assert := assert.New(t)
	cfgs := configuration.NewCfg()

	t.Run("default", func(t *testing.T) {
		got, err := auth_oauth2_password.AccessTokenTTL(cfgs)
		assert.NoError(err)
		assert.Equal(30*time.Minute, got)
	})

	t.Run("new env with unit", func(t *testing.T) {
		t.Setenv("OAUTH2_ACCESS_TOKEN_TTL", "45m")

		got, err := auth_oauth2_password.AccessTokenTTL(cfgs)
		assert.NoError(err)
		assert.Equal(45*time.Minute, got)
	})

	t.Run("falls back to deprecated env in minutes", func(t *testing.T) {
		t.Setenv("OAUTH2_ACCESS_TOKEN_EXPIRATION", "131400")

		got, err := auth_oauth2_password.AccessTokenTTL(cfgs)
		assert.NoError(err)
		assert.Equal(131400*time.Minute, got)
	})

	t.Run("new env wins over deprecated", func(t *testing.T) {
		t.Setenv("OAUTH2_ACCESS_TOKEN_TTL", "5m")
		t.Setenv("OAUTH2_ACCESS_TOKEN_EXPIRATION", "131400")

		got, err := auth_oauth2_password.AccessTokenTTL(cfgs)
		assert.NoError(err)
		assert.Equal(5*time.Minute, got)
	})

	t.Run("invalid value fails loud", func(t *testing.T) {
		t.Setenv("OAUTH2_ACCESS_TOKEN_TTL", "xpto")

		_, err := auth_oauth2_password.AccessTokenTTL(cfgs)
		assert.Error(err)
	})
}

func TestRefreshIdleTTL(t *testing.T) {
	assert := assert.New(t)
	cfgs := configuration.NewCfg()

	t.Run("default", func(t *testing.T) {
		got, err := auth_oauth2_password.RefreshIdleTTL(cfgs)
		assert.NoError(err)
		assert.Equal(72*time.Hour, got)
	})

	t.Run("new env with unit", func(t *testing.T) {
		t.Setenv("OAUTH2_REFRESH_IDLE_TTL", "7d")

		got, err := auth_oauth2_password.RefreshIdleTTL(cfgs)
		assert.NoError(err)
		assert.Equal(168*time.Hour, got)
	})

	t.Run("falls back to deprecated env in minutes", func(t *testing.T) {
		t.Setenv("OAUTH2_REFRESH_TOKEN_EXPIRATION", "10080")

		got, err := auth_oauth2_password.RefreshIdleTTL(cfgs)
		assert.NoError(err)
		assert.Equal(10080*time.Minute, got)
	})

	t.Run("invalid value fails loud", func(t *testing.T) {
		t.Setenv("OAUTH2_REFRESH_IDLE_TTL", "xpto")

		_, err := auth_oauth2_password.RefreshIdleTTL(cfgs)
		assert.Error(err)
	})
}

func TestRefreshAbsoluteTTL(t *testing.T) {
	assert := assert.New(t)
	cfgs := configuration.NewCfg()

	got, err := auth_oauth2_password.RefreshAbsoluteTTL(cfgs)
	assert.NoError(err)
	assert.Equal(720*time.Hour, got)

	t.Setenv("OAUTH2_REFRESH_ABSOLUTE_TTL", "30d")
	got, err = auth_oauth2_password.RefreshAbsoluteTTL(cfgs)
	assert.NoError(err)
	assert.Equal(720*time.Hour, got)
}

func TestRefreshReuseGrace(t *testing.T) {
	assert := assert.New(t)
	cfgs := configuration.NewCfg()

	got, err := auth_oauth2_password.RefreshReuseGrace(cfgs)
	assert.NoError(err)
	assert.Equal(30*time.Second, got)

	t.Setenv("OAUTH2_REFRESH_REUSE_GRACE", "1m")
	got, err = auth_oauth2_password.RefreshReuseGrace(cfgs)
	assert.NoError(err)
	assert.Equal(time.Minute, got)
}

func TestStrict401Enabled(t *testing.T) {
	assert := assert.New(t)
	cfgs := configuration.NewCfg()

	assert.False(auth_oauth2_password.Strict401Enabled(cfgs))

	t.Setenv("OAUTH2_STRICT_401", "true")
	assert.True(auth_oauth2_password.Strict401Enabled(cfgs))
}
