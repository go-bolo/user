package user_oauth2_jwt

import (
	"log"
	"sync"
	"time"

	"github.com/go-bolo/bolo"
	user_oauth2_password "github.com/go-bolo/user/oauth2_password"
	"github.com/sirupsen/logrus"
)

// Defaults do access JWT (valem quando a env correspondente não está
// presente). O secret NÃO tem default: InitConfig aplica fail-fast.
const (
	DefaultJWTAudience = "mm"
	DefaultJWTTTL      = 10 * time.Minute
	DefaultJWTLeeway   = 30 * time.Second
)

// Config carrega a configuração do access token JWT (envs OAUTH2_JWT_*).
type Config struct {
	Secret   string
	Issuer   string
	Audience string
	TTL      time.Duration
	Leeway   time.Duration
}

var (
	configMu  sync.RWMutex
	activeCfg *Config
)

// InitConfig lê as envs OAUTH2_JWT_* no evento configuration e registra o
// gerador de access tokens JWT no oauth2_password. Fail-fast quando o
// subplugin está instalado sem secret: um secret vazio/implícito aceitaria
// tokens forjados (anti-padrão do default hardcoded, não repetido aqui).
func InitConfig(app bolo.App) {
	cfgs := app.GetConfiguration()

	secret := cfgs.Get("OAUTH2_JWT_SECRET")
	if secret == "" {
		log.Fatal("oauth2_jwt: OAUTH2_JWT_SECRET é obrigatório quando o subplugin está instalado (não existe secret default; use um segredo aleatório de pelo menos 32 bytes)")
	}

	cfg := &Config{
		Secret:   secret,
		Issuer:   cfgs.GetF("OAUTH2_JWT_ISSUER", ""),
		Audience: cfgs.GetF("OAUTH2_JWT_AUDIENCE", DefaultJWTAudience),
	}

	ttl, err := user_oauth2_password.ParseTTL(cfgs.Get("OAUTH2_JWT_TTL"), DefaultJWTTTL)
	if err != nil {
		log.Fatal("oauth2_jwt: configuração inválida: ", err)
	}
	cfg.TTL = ttl

	leeway, err := user_oauth2_password.ParseTTL(cfgs.Get("OAUTH2_JWT_LEEWAY"), DefaultJWTLeeway)
	if err != nil {
		log.Fatal("oauth2_jwt: configuração inválida: ", err)
	}
	cfg.Leeway = leeway

	configMu.Lock()
	activeCfg = cfg
	configMu.Unlock()

	user_oauth2_password.SetJWTAccessGenerator(func(ctx *bolo.RequestContext, u bolo.UserInterface) (string, int64, error) {
		return GenerateAccessToken(cfg, u)
	})

	logrus.WithFields(logrus.Fields{
		"issuer":   cfg.Issuer,
		"audience": cfg.Audience,
		"ttl":      cfg.TTL.String(),
		"leeway":   cfg.Leeway.String(),
	}).Info("oauth2_jwt: configuração carregada e gerador de access token JWT registrado")
}

// GetConfig devolve a configuração ativa (nil antes do evento
// configuration — nesse estado o middleware devolve 401, fail-closed).
func GetConfig() *Config {
	configMu.RLock()
	defer configMu.RUnlock()
	return activeCfg
}
