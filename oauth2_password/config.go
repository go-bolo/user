package user_oauth2_password

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-bolo/bolo/configuration"
	"github.com/sirupsen/logrus"
)

// TTLs padrão usados na cascata de configuração: valem quando nenhuma
// variável de ambiente (nova ou legada) é encontrada.
const (
	DefaultAccessTokenTTL     = 30 * time.Minute
	DefaultRefreshIdleTTL     = 72 * time.Hour
	DefaultRefreshAbsoluteTTL = 720 * time.Hour // 30 dias
	DefaultRefreshReuseGrace  = 30 * time.Second
)

// ttlTokenRE reconhece os pares "número + unidade" aceitos pelo parser de TTL
var ttlTokenRE = regexp.MustCompile(`(\d+(?:\.\d+)?)(us|µs|μs|ms|s|m|h|d)`)

// ParseTTL converte um valor de duração com unidade (ex.: "30m", "7d",
// "2d12h") em time.Duration. Além das unidades de time.ParseDuration aceita o
// sufixo "d" de dias (7d => 168h). Valor vazio devolve o fallback; valor
// inválido devolve erro explícito — configuração quebrada não pode ser
// silenciada.
func ParseTTL(value string, fallback time.Duration) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}

	// time.ParseDuration não suporta dias: converte "d" em horas antes de parsear
	normalized := ttlTokenRE.ReplaceAllStringFunc(value, func(token string) string {
		i := strings.IndexFunc(token, func(r rune) bool {
			return !unicode.IsDigit(r) && r != '.'
		})
		num, unit := token[:i], token[i:]
		if unit != "d" {
			return token
		}

		days, err := strconv.ParseFloat(num, 64)
		if err != nil {
			// segue em frente: o ParseDuration abaixo reporta o erro
			return token
		}

		return strconv.FormatFloat(days*24, 'f', -1, 64) + "h"
	})

	d, err := time.ParseDuration(normalized)
	if err != nil {
		return fallback, fmt.Errorf("invalid TTL %q: %w", value, err)
	}

	if d <= 0 {
		return fallback, fmt.Errorf("invalid TTL %q: must be greater than zero", value)
	}

	return d, nil
}

// AccessTokenTTL lê o TTL do access token em cascata:
// OAUTH2_ACCESS_TOKEN_TTL (string com unidade, ex.: "30m") =>
// OAUTH2_ACCESS_TOKEN_EXPIRATION (inteiro em MINUTOS, comportamento legado,
// loga warn de deprecação) => 30m.
func AccessTokenTTL(cfgs configuration.ConfigurationInterface) (time.Duration, error) {
	if value := cfgs.Get("OAUTH2_ACCESS_TOKEN_TTL"); value != "" {
		return ParseTTL(value, DefaultAccessTokenTTL)
	}

	if expiration := cfgs.GetInt64("OAUTH2_ACCESS_TOKEN_EXPIRATION"); expiration > 0 {
		logrus.WithFields(logrus.Fields{
			"expirationMinutes": expiration,
		}).Warn("OAUTH2_ACCESS_TOKEN_EXPIRATION is deprecated, use OAUTH2_ACCESS_TOKEN_TTL with unit (ex: 30m)")

		return time.Duration(expiration) * time.Minute, nil
	}

	return DefaultAccessTokenTTL, nil
}

// RefreshIdleTTL lê o TTL idle do refresh token (renovado a cada rotação) em
// cascata: OAUTH2_REFRESH_IDLE_TTL (com unidade) =>
// OAUTH2_REFRESH_TOKEN_EXPIRATION (inteiro em MINUTOS, legado) => 72h.
func RefreshIdleTTL(cfgs configuration.ConfigurationInterface) (time.Duration, error) {
	if value := cfgs.Get("OAUTH2_REFRESH_IDLE_TTL"); value != "" {
		return ParseTTL(value, DefaultRefreshIdleTTL)
	}

	if expiration := cfgs.GetInt64("OAUTH2_REFRESH_TOKEN_EXPIRATION"); expiration > 0 {
		return time.Duration(expiration) * time.Minute, nil
	}

	return DefaultRefreshIdleTTL, nil
}

// RefreshAbsoluteTTL lê o teto absoluto da família de refresh tokens: mesmo
// com rotações contínuas a família morre nesse prazo
// (OAUTH2_REFRESH_ABSOLUTE_TTL, default 720h/30 dias).
func RefreshAbsoluteTTL(cfgs configuration.ConfigurationInterface) (time.Duration, error) {
	return ParseTTL(cfgs.Get("OAUTH2_REFRESH_ABSOLUTE_TTL"), DefaultRefreshAbsoluteTTL)
}

// RefreshReuseGrace lê a janela de graça do reuso idempotente do refresh
// token: dentro dela, replay do token antigo devolve o MESMO par emitido
// (OAUTH2_REFRESH_REUSE_GRACE, default 30s).
func RefreshReuseGrace(cfgs configuration.ConfigurationInterface) (time.Duration, error) {
	return ParseTTL(cfgs.Get("OAUTH2_REFRESH_REUSE_GRACE"), DefaultRefreshReuseGrace)
}

// Strict401Enabled indica se o middleware deve responder 401 explícito
// (com WWW-Authenticate) para access token inexistente/expirado em vez de
// seguir a requisição como anônima (OAUTH2_STRICT_401, default false).
func Strict401Enabled(cfgs configuration.ConfigurationInterface) bool {
	return cfgs.GetBoolF("OAUTH2_STRICT_401", false)
}
