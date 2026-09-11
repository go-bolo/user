package user_oauth2_jwt

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-bolo/bolo"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// KeyID identifica a chave de assinatura atual no header kid (RFC 8725
// §3.5): desde o v1 todo token emitido carrega o kid da chave única HS256;
// rotação futura de chaves adiciona entradas novas aqui.
const KeyID = "1"

// ErrTokenExpired sinaliza expiração (exp) para o middleware distinguir a
// descrição do WWW-Authenticate ("token expired" vs "invalid token").
var ErrTokenExpired = fmt.Errorf("token expirado")

// AccessClaims é o payload do access token JWT: SEM PII. As roles e o
// snapshot active/blocked permitem ao middleware montar o stub de usuário
// sem consultar o banco — a defasagem em relação ao banco (bloqueio,
// desativação, troca de roles) vale por no máximo o TTL do token, contrato
// aceito no desenho (TTL curto + checagem de verdade no gate do refresh).
type AccessClaims struct {
	Roles   []string `json:"roles,omitempty"`
	Active  bool     `json:"active"`
	Blocked bool     `json:"blocked"`
	jwt.RegisteredClaims
}

// GenerateAccessToken emite o access JWT HS256: claims iss/aud/sub/jti/iat/
// nbf/exp + roles + snapshot active/blocked, header kid fixo. Devolve o TTL
// em segundos (expires_in) para o contrato oauth2 da resposta.
func GenerateAccessToken(cfg *Config, u bolo.UserInterface) (accessToken string, expiresIn int64, err error) {
	now := time.Now()
	expiresIn = int64(cfg.TTL / time.Second)

	claims := AccessClaims{
		Roles:   u.GetRoles(),
		Active:  u.IsActive(),
		Blocked: u.IsBlocked(),
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{cfg.Audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(cfg.TTL)),
			ID:        uuid.New().String(),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    cfg.Issuer,
			NotBefore: jwt.NewNumericDate(now),
			Subject:   u.GetID(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = KeyID

	signed, err := token.SignedString([]byte(cfg.Secret))
	if err != nil {
		return "", 0, err
	}

	return signed, expiresIn, nil
}

// jwtParser pina HS256 (ValidMethods rejeita alg:none e qualquer troca de
// algoritmo) e desliga a validação automática de claims — exp/nbf/iat são
// validados em ValidateAccessToken com o leeway configurado.
var jwtParser = jwt.NewParser(
	jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	jwt.WithoutClaimsValidation(),
)

// ValidateAccessToken valida criptográfica e semanticamente o access JWT:
// assinatura HS256 com o secret configurado, kid conhecido, iss/aud
// exatamente iguais aos configurados, sub (userID) e jti presentes, e
// exp/nbf/iat dentro do leeway. Fail-closed: claim ausente rejeita.
func ValidateAccessToken(cfg *Config, tokenString string) (*AccessClaims, error) {
	token, err := jwtParser.ParseWithClaims(tokenString, &AccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		// dupla checagem do algoritmo: além de ValidMethods, garante o tipo
		// concreto do método (mitiga key-confusion)
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("algoritmo de assinatura inesperado: %v", t.Header["alg"])
		}
		// kid (quando presente) precisa bater com a chave atual
		if kid, ok := t.Header["kid"].(string); ok && kid != KeyID {
			return nil, fmt.Errorf("kid desconhecido: %q", kid)
		}
		return []byte(cfg.Secret), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*AccessClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("token inválido")
	}

	now := time.Now()

	if claims.Issuer != cfg.Issuer {
		return nil, fmt.Errorf("issuer inválido")
	}

	// aud precisa ser exatamente a configurada: um único valor (fail-closed
	// para array com múltiplas audiences)
	if len(claims.Audience) != 1 || claims.Audience[0] != cfg.Audience {
		return nil, fmt.Errorf("audience inválida")
	}

	if claims.Subject == "" {
		return nil, fmt.Errorf("subject vazio")
	}

	if _, err := strconv.ParseUint(claims.Subject, 10, 64); err != nil {
		return nil, fmt.Errorf("subject não é um userID válido")
	}

	if claims.ID == "" {
		return nil, fmt.Errorf("jti vazio")
	}

	// exp ausente (nil) ou no passado além do leeway rejeita (fail-closed)
	if claims.ExpiresAt == nil || !now.Before(claims.ExpiresAt.Add(cfg.Leeway)) {
		return nil, ErrTokenExpired
	}

	if claims.NotBefore != nil && claims.NotBefore.After(now.Add(cfg.Leeway)) {
		return nil, fmt.Errorf("token ainda não é válido (nbf)")
	}

	if claims.IssuedAt != nil && claims.IssuedAt.After(now.Add(cfg.Leeway)) {
		return nil, fmt.Errorf("token emitido no futuro (iat)")
	}

	return claims, nil
}

// LooksLikeJWT discrimina o formato sem parsear: um JWS compacto tem
// exatamente dois pontos e três segmentos não vazios. Tokens opacos do
// fluxo legado (uuid + random) não contêm pontos.
func LooksLikeJWT(token string) bool {
	if strings.Count(token, ".") != 2 {
		return false
	}

	for _, part := range strings.Split(token, ".") {
		if part == "" {
			return false
		}
	}

	return true
}
