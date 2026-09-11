package user_oauth2_password

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-bolo/bolo"
	user_models "github.com/go-bolo/user/models"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// Prefixos das chaves Redis do fluxo de refresh seguro (mesmo Redis/DB do
// storage atual). Tokens legados continuam gravados sem prefixo e lidos em
// dupla para não derrubar sessões vivas no deploy. Exportados para que os
// consumidores (e suites de teste) não dupliquem literais sujeitos a drift.
const (
	RefreshTokenKeyPrefix       = "RT:"     // refresh token ativo (formato novo)
	RefreshTokenUsedKeyPrefix   = "RTUSED:" // par já emitido dentro da graça de reuso
	RefreshTokenTombKeyPrefix   = "RTTOMB:" // marca o token como usado (detecta reuso fora da graça)
	RefreshTokenFamilyKeyPrefix = "RTFAM:"  // SET com os refresh tokens da família
)

// Janela de espera de quem perdeu a claim atômica da rotação (GETDEL): o
// vencedor publica o par na graça em milissegundos; espera limitada evita
// classificar como expirado um token que acabou de ser consumido por outra
// aba/dispositivo.
const (
	claimWaitTimeout  = 1 * time.Second
	claimWaitInterval = 25 * time.Millisecond
)

// RefreshErrKind classifica a falha do fluxo de refresh para o chamador mapear
// em status/mensagens HTTP sem conhecer detalhes de Redis.
type RefreshErrKind int

const (
	// ErrInternal - erro de infra (Redis fora, dados corrompidos, config
	// inválida): o chamador deve responder 500 e NADA é revogado.
	ErrInternal RefreshErrKind = iota
	// ErrExpiredIdle - token nunca usado e vencido pelo tempo de inatividade.
	ErrExpiredIdle
	// ErrExpiredAbsolute - família venceu o teto absoluto desde o primeiro token.
	ErrExpiredAbsolute
	// ErrReuseDetected - token já usado reapresentado fora da graça: possível
	// roubo, a família inteira é revogada.
	ErrReuseDetected
	// ErrUserInvalid - dono do token não existe mais, está inativo ou bloqueado.
	ErrUserInvalid
)

// String devolve um rótulo curto do tipo de erro para logs e respostas.
func (k RefreshErrKind) String() string {
	switch k {
	case ErrExpiredIdle:
		return "expired_idle"
	case ErrExpiredAbsolute:
		return "expired_absolute"
	case ErrReuseDetected:
		return "reuse_detected"
	case ErrUserInvalid:
		return "user_invalid"
	default:
		return "internal"
	}
}

// RefreshError é o erro retornado pelas funções de refresh/revogação.
// Err carrega a causa original quando existe (erros de infra).
type RefreshError struct {
	Kind RefreshErrKind
	Err  error
}

// Error torna o tipo compatível com a interface `error`.
func (e *RefreshError) Error() string {
	if e == nil {
		return "<nil>"
	}

	if e.Err != nil {
		return fmt.Sprintf("refresh token error (kind=%s): %v", e.Kind, e.Err)
	}

	return fmt.Sprintf("refresh token error (kind=%s)", e.Kind)
}

// Unwrap expõe a causa original para errors.Is/As.
func (e *RefreshError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// RefreshTokenRecord é o conteúdo persistido em RT:<refresh token>. É o
// formato novo, com família e teto absoluto.
type RefreshTokenRecord struct {
	OwnerID  json.Number `json:"ownerId"`
	FamilyID string      `json:"familyId"` // uuid da família de tokens
	// CreatedAt é diagnóstico/forense (quando cada token da família foi
	// emitido); nenhum fluxo decide por ele.
	CreatedAt        time.Time `json:"createdAt"`
	AbsoluteDeadline time.Time `json:"absoluteDeadline"`
}

// TokenPair é o par oauth2 devolvido nas rotações (mesmo formato do corpo da
// resposta do grant password).
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// refreshUsedRecord é o valor persistido em RTUSED:<token antigo>: o par
// emitido na rotação + o dono, para o replay dentro da graça devolver o MESMO
// par e carregar o usuário. O JSON é compatível com TokenPair.
type refreshUsedRecord struct {
	TokenPair
	OwnerID json.Number `json:"ownerId"`
}

// refreshInternalError normaliza erros de infra: o chamador responde 500 e
// nada é revogado (fail-closed sem destruição).
func refreshInternalError(err error) *RefreshError {
	return &RefreshError{Kind: ErrInternal, Err: err}
}

// getUsedTokenPair lê RTUSED:<refresh>. Retorna (nil, nil) quando a chave não
// existe (fora da graça ou token nunca usado).
func getUsedTokenPair(refreshToken string) (*refreshUsedRecord, error) {
	strData, err := StorageDBReader.Get(ctx, RefreshTokenUsedKeyPrefix+refreshToken).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}

	var used refreshUsedRecord
	if err := json.Unmarshal([]byte(strData), &used); err != nil {
		return nil, err
	}

	return &used, nil
}

// getNewRecord lê RT:<refresh> (formato novo). Retorna (nil, nil) quando a
// chave não existe.
func getNewRecord(refreshToken string) (*RefreshTokenRecord, error) {
	strData, err := StorageDBReader.Get(ctx, RefreshTokenKeyPrefix+refreshToken).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}

	var record RefreshTokenRecord
	if err := json.Unmarshal([]byte(strData), &record); err != nil {
		return nil, err
	}

	return &record, nil
}

// getLegacyRecord lê a chave sem prefixo (formato antigo gravado pelo login
// via SetRefreshToken). Retorna (nil, nil) quando a chave não existe.
func getLegacyRecord(refreshToken string) (*Oauth2TokenData, error) {
	strData, err := StorageDBReader.Get(ctx, refreshTokenPrefix+refreshToken).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}

	var data Oauth2TokenData
	if err := json.Unmarshal([]byte(strData), &data); err != nil {
		return nil, err
	}

	return &data, nil
}

// getTombstoneFamily lê RTTOMB:<refresh> devolvendo o ID da família (ou "").
func getTombstoneFamily(refreshToken string) (string, error) {
	familyID, err := StorageDBReader.Get(ctx, RefreshTokenTombKeyPrefix+refreshToken).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", nil
		}
		return "", err
	}

	return familyID, nil
}

// RotateRefreshToken troca um refresh token válido por um par novo (formato
// opaco legado), com rotação single-use e graça de reuso idempotente.
// Veja RotateRefreshTokenWithFormat para a semântica completa.
func RotateRefreshToken(c echo.Context, refreshToken string) (*TokenPair, *user_models.UserModel, *RefreshError) {
	return RotateRefreshTokenWithFormat(c, refreshToken, FormatOpaque)
}

// RotateRefreshTokenWithFormat troca um refresh token válido por um par novo
// no formato pedido, com rotação single-use e graça de reuso idempotente:
//
//  1. RTUSED hit (dentro da graça) => devolve o MESMO par já emitido,
//     sem nova rotação (a aba que perdeu a corrida também recebe 200);
//  2. RT: hit (formato novo) ou chave legada sem prefixo => valida o teto
//     absoluto e o usuário, gera par novo, indexa a família, marca o token
//     antigo como usado (RTUSED + RTTOMB) e o consome; o token legado migra
//     para o formato novo;
//  3. miss => se houver tombstone é reuso fora da graça (revoga a família e
//     retorna ErrReuseDetected); sem tombstone é sessão vencida por idle
//     (ErrExpiredIdle).
//
// Com FormatJWT o access novo é um JWT stateless (não gravado no Redis); o
// par publicado na graça (RTUSED) carrega a string JWT sem alteração, então
// o replay dentro da graça devolve o MESMO JWT. O refresh token do par é
// sempre opaco — a string de acesso é transparente para graça/famílias.
//
// Erros de infra (Redis fora, dados corrompidos, config inválida) vêm com
// Kind ErrInternal e NÃO revogam nada — o chamador decide o 500.
func RotateRefreshTokenWithFormat(c echo.Context, refreshToken string, format AccessTokenFormat) (*TokenPair, *user_models.UserModel, *RefreshError) {
	reqCtx, ok := c.(*bolo.RequestContext)
	if !ok {
		return nil, nil, refreshInternalError(errors.New("RotateRefreshToken requires a *bolo.RequestContext"))
	}

	cfgs := reqCtx.App.GetConfiguration()

	idleTTL, err := RefreshIdleTTL(cfgs)
	if err != nil {
		return nil, nil, refreshInternalError(err)
	}

	absoluteTTL, err := RefreshAbsoluteTTL(cfgs)
	if err != nil {
		return nil, nil, refreshInternalError(err)
	}

	graceTTL, err := RefreshReuseGrace(cfgs)
	if err != nil {
		return nil, nil, refreshInternalError(err)
	}

	// 1. replay dentro da janela de graça: idempotente
	used, err := getUsedTokenPair(refreshToken)
	if err != nil {
		return nil, nil, refreshInternalError(err)
	}

	if used != nil {
		return replayUsedPair(used)
	}

	now := time.Now()

	// 2. claim atômica do formato novo: GETDEL consome RT:<token> de forma
	// indivisível — apenas uma requisição concorrente vence; as demais caem
	// na espera do passo 4 e recebem o par do vencedor na graça.
	claimedJSON, err := getDelClaim(RefreshTokenKeyPrefix + refreshToken)
	if err != nil {
		return nil, nil, refreshInternalError(err)
	}

	if claimedJSON != "" {
		var record RefreshTokenRecord
		if err := json.Unmarshal([]byte(claimedJSON), &record); err != nil {
			return nil, nil, refreshInternalError(err)
		}

		return rotateClaimedRecord(reqCtx, &record, refreshToken, RefreshTokenKeyPrefix+refreshToken, claimedJSON, now, idleTTL, graceTTL, format)
	}

	// 3. claim legado (chave sem prefixo): sem deadline conhecida, a família
	// nova passa a valer a partir de agora com o teto absoluto
	legacyJSON, err := getDelClaim(refreshTokenPrefix + refreshToken)
	if err != nil {
		return nil, nil, refreshInternalError(err)
	}

	if legacyJSON != "" {
		var legacy Oauth2TokenData
		if err := json.Unmarshal([]byte(legacyJSON), &legacy); err != nil {
			return nil, nil, refreshInternalError(err)
		}

		record := &RefreshTokenRecord{
			OwnerID:          legacy.OwnerId,
			FamilyID:         uuid.New().String(),
			CreatedAt:        now,
			AbsoluteDeadline: now.Add(absoluteTTL),
		}

		return rotateClaimedRecord(reqCtx, record, refreshToken, refreshTokenPrefix+refreshToken, legacyJSON, now, idleTTL, graceTTL, format)
	}

	// 4. Miss nas claims: ou o token nunca existiu/expirou, ou outra
	// requisição acabou de consumi-lo (GETDEL) e ainda não publicou o par na
	// graça. Espera limitada para o vencedor publicar antes de classificar.
	deadline := time.Now().Add(claimWaitTimeout)
	for {
		used, err := getUsedTokenPair(refreshToken)
		if err != nil {
			return nil, nil, refreshInternalError(err)
		}

		if used != nil {
			return replayUsedPair(used)
		}

		familyID, err := getTombstoneFamily(refreshToken)
		if err != nil {
			return nil, nil, refreshInternalError(err)
		}

		if familyID != "" {
			// tombstone sem graça ativa = reuso fora da janela
			return revokeFamilyByReuse(familyID)
		}

		if !time.Now().Before(deadline) {
			break
		}

		time.Sleep(claimWaitInterval)
	}

	return nil, nil, &RefreshError{Kind: ErrExpiredIdle}
}

// replayUsedPair devolve o MESMO par já emitido na graça, revalidando o dono:
// usuário inativo/bloqueado/inexistente não renova sessão no replay (contrato
// de 403 do endpoint preservado também na janela de graça).
func replayUsedPair(used *refreshUsedRecord) (*TokenPair, *user_models.UserModel, *RefreshError) {
	logrus.WithFields(logrus.Fields{
		"ownerId": used.OwnerID.String(),
	}).Debug("RotateRefreshToken replay within reuse grace window")

	userRecord, userErr := findRefreshTokenUser(used.OwnerID.String())
	if userErr != nil {
		// falha de banco é infra: não devolve o par às cegas
		return nil, nil, refreshInternalError(userErr)
	}

	if userRecord == nil || userRecord.ID == 0 || !userRecord.Active || userRecord.Blocked {
		return nil, userRecord, &RefreshError{Kind: ErrUserInvalid}
	}

	pair := used.TokenPair
	return &pair, userRecord, nil
}

// revokeFamilyByReuse revoga a família ao detectar reapresentação de token já
// consumido fora da graça (indício de roubo).
func revokeFamilyByReuse(familyID string) (*TokenPair, *user_models.UserModel, *RefreshError) {
	logrus.WithFields(logrus.Fields{
		"familyId": familyID,
	}).Warn("RotateRefreshToken refresh token reuse detected outside grace window, revoking token family")

	if err := RevokeRefreshFamily(familyID); err != nil {
		logrus.WithFields(logrus.Fields{
			"error":    err,
			"familyId": familyID,
		}).Error("RotateRefreshToken error on revoke reused token family")
	}

	return nil, nil, &RefreshError{Kind: ErrReuseDetected}
}

// getDelClaim consome atomicamente a chave (GETDEL). Devolve "" quando a chave
// não existe (ninguém ganhou ainda ou token desconhecido).
func getDelClaim(key string) (string, error) {
	strData, err := StorageDBWriter.GetDel(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", nil
		}
		return "", err
	}

	return strData, nil
}

// rotateClaimedRecord executa a rotação de uma claim já consumida (GETDEL).
// Em falha sem efeitos colaterais (infra ou usuário inválido), devolve a
// chave ao storage (best-effort) para que retries do mesmo token produzam o
// mesmo resultado em vez de "sessão expirada". Erros que JÁ revogaram a
// família (teto absoluto) não restauram nada — a revogação prevalece.
func rotateClaimedRecord(reqCtx *bolo.RequestContext, record *RefreshTokenRecord, refreshToken, claimedKey, claimedJSON string, now time.Time, idleTTL, graceTTL time.Duration, format AccessTokenFormat) (*TokenPair, *user_models.UserModel, *RefreshError) {
	pair, user, rerr := rotateRecord(reqCtx, record, refreshToken, now, idleTTL, graceTTL, format)
	if rerr != nil && (rerr.Kind == ErrInternal || rerr.Kind == ErrUserInvalid) {
		if err := StorageDBWriter.Set(ctx, claimedKey, claimedJSON, idleTTL).Err(); err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Warn("RotateRefreshToken error on restore claimed refresh token key")
		}
	}

	return pair, user, rerr
}

// rotateRecord valida o record, gera o par novo e persiste toda a movimentação
// de chaves da rotação. O token antigo já foi consumido pela claim atômica
// (GETDEL) do chamador; refreshToken é usado apenas como membro do índice da
// família e das chaves de graça/tombstone.
func rotateRecord(reqCtx *bolo.RequestContext, record *RefreshTokenRecord, refreshToken string, now time.Time, idleTTL, graceTTL time.Duration, format AccessTokenFormat) (*TokenPair, *user_models.UserModel, *RefreshError) {
	// teto absoluto vencido: família inteira é encerrada (>= garante que o
	// restante do prazo usado nos TTLs abaixo é sempre positivo)
	if !now.Before(record.AbsoluteDeadline) {
		logrus.WithFields(logrus.Fields{
			"familyId": record.FamilyID,
		}).Warn("RotateRefreshToken token family expired by absolute deadline, revoking")

		if err := RevokeRefreshFamily(record.FamilyID); err != nil {
			logrus.WithFields(logrus.Fields{
				"error":    err,
				"familyId": record.FamilyID,
			}).Error("RotateRefreshToken error on revoke expired token family")
		}

		return nil, nil, &RefreshError{Kind: ErrExpiredAbsolute}
	}

	// dono do token precisa existir e estar em pé
	userRecord, userErr := findRefreshTokenUser(record.OwnerID.String())
	if userErr != nil {
		return nil, nil, refreshInternalError(userErr)
	}

	if userRecord == nil || userRecord.ID == 0 || !userRecord.Active || userRecord.Blocked {
		// devolve o record carregado (quando existir) para o chamador
		// distinguir inativo/bloqueado de inexistente
		return nil, userRecord, &RefreshError{Kind: ErrUserInvalid}
	}

	// gera o par novo no formato pedido (access token já usa o TTL
	// configurado; no formato JWT nada é gravado para o access)
	accessToken, expiresIn, err := generateAccessTokenForFormat(reqCtx, userRecord, format)
	if err != nil {
		return nil, nil, refreshInternalError(err)
	}

	newRefreshToken := generateRefreshToken()

	remainingAbsolute := record.AbsoluteDeadline.Sub(now)

	newRecord := RefreshTokenRecord{
		OwnerID:          record.OwnerID,
		FamilyID:         record.FamilyID,
		CreatedAt:        now,
		AbsoluteDeadline: record.AbsoluteDeadline,
	}

	recordJSON, err := json.Marshal(newRecord)
	if err != nil {
		return nil, nil, refreshInternalError(err)
	}

	// refresh token novo com TTL idle (renovado a cada rotação)
	if err := StorageDBWriter.Set(ctx, RefreshTokenKeyPrefix+newRefreshToken, string(recordJSON), idleTTL).Err(); err != nil {
		return nil, nil, refreshInternalError(err)
	}

	// família indexa os tokens envolvidos (velho + novo) com TTL do restante
	// do teto absoluto
	familyKey := RefreshTokenFamilyKeyPrefix + record.FamilyID
	if err := StorageDBWriter.SAdd(ctx, familyKey, refreshToken, newRefreshToken).Err(); err != nil {
		return nil, nil, refreshInternalError(err)
	}

	if err := StorageDBWriter.Expire(ctx, familyKey, remainingAbsolute).Err(); err != nil {
		return nil, nil, refreshInternalError(err)
	}

	used := refreshUsedRecord{
		TokenPair: TokenPair{
			AccessToken:  accessToken,
			RefreshToken: newRefreshToken,
			ExpiresIn:    expiresIn,
		},
		OwnerID: record.OwnerID,
	}

	usedJSON, err := json.Marshal(used)
	if err != nil {
		return nil, nil, refreshInternalError(err)
	}

	// par emitido fica disponível na graça para o replay idempotente
	if err := StorageDBWriter.Set(ctx, RefreshTokenUsedKeyPrefix+refreshToken, string(usedJSON), graceTTL).Err(); err != nil {
		return nil, nil, refreshInternalError(err)
	}

	// tombstone permite detectar reuso DEPOIS que a graça expira
	if err := StorageDBWriter.Set(ctx, RefreshTokenTombKeyPrefix+refreshToken, record.FamilyID, remainingAbsolute).Err(); err != nil {
		return nil, nil, refreshInternalError(err)
	}

	pair := TokenPair{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    expiresIn,
	}

	return &pair, userRecord, nil
}

// findRefreshTokenUser carrega o dono do refresh token. Retorna (nil, nil)
// quando o ID é vazio; erro somente para falhas de banco (infra).
func findRefreshTokenUser(ownerID string) (*user_models.UserModel, error) {
	if ownerID == "" {
		return nil, nil
	}

	var userRecord user_models.UserModel
	if err := user_models.UserFindOne(ownerID, &userRecord); err != nil {
		return nil, err
	}

	return &userRecord, nil
}

// RevokeRefreshFamily revoga todos os tokens de uma família: refresh tokens
// ativos, pares em graça e tombstones. Usado em reuso detectado, teto absoluto
// vencido e revogação explícita (logout/revoke). Todas as chaves são
// removidas num único DEL multi-key (1 round trip + 1 por índice).
func RevokeRefreshFamily(familyID string) error {
	if familyID == "" {
		return nil
	}

	familyKey := RefreshTokenFamilyKeyPrefix + familyID

	members, err := StorageDBWriter.SMembers(ctx, familyKey).Result()
	if err != nil {
		return err
	}

	// cobre o formato novo (RT:) e o legado (chave sem prefixo) de cada membro
	keys := make([]string, 0, len(members)*4+1)
	for _, member := range members {
		keys = append(keys,
			RefreshTokenKeyPrefix+member,
			RefreshTokenUsedKeyPrefix+member,
			RefreshTokenTombKeyPrefix+member,
			refreshTokenPrefix+member,
		)
	}

	return StorageDBWriter.Del(ctx, append(keys, familyKey)...).Err()
}

// RevokeByRefreshToken resolve a família à qual o token pertence (ativo, já
// usado ou legado) e revoga tudo. Token desconhecido não é erro (best-effort).
func RevokeByRefreshToken(token string) error {
	if token == "" {
		return nil
	}

	// formato novo: a família resolve os pares emitidos
	record, err := getNewRecord(token)
	if err != nil {
		return err
	}

	if record != nil {
		return RevokeRefreshFamily(record.FamilyID)
	}

	// token já usado: o tombstone aponta para a família
	familyID, err := getTombstoneFamily(token)
	if err != nil {
		return err
	}

	if familyID != "" {
		return RevokeRefreshFamily(familyID)
	}

	// legado (chave sem prefixo): sem família, remove a chave direto
	legacy, err := getLegacyRecord(token)
	if err != nil {
		return err
	}

	if legacy != nil {
		return StorageDBWriter.Del(ctx, refreshTokenPrefix+token).Err()
	}

	// resto de graça (família já revogada): limpa o que sobrou
	return StorageDBWriter.Del(ctx, RefreshTokenUsedKeyPrefix+token).Err()
}
