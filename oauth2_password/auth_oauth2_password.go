package user_oauth2_password

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-bolo/bolo"
	"github.com/go-bolo/bolo/helpers"
	user_models "github.com/go-bolo/user/models"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var ctx = context.Background()

func IsPublicRoute(url string) bool {
	return strings.HasPrefix(url, "/health") || strings.HasPrefix(url, "/public")
}

func HandleRequestAuthentication(c echo.Context) error {
	// 1- oauth2 password authentication
	err := oauth2TokenAuthentication(c)
	if err != nil {
		return err
	}

	return err
}

func oauth2TokenAuthentication(c echo.Context) error {
	ctx := c.(*bolo.RequestContext)
	var err error

	// Guard: request já autenticada pelo middleware JWT do subplugin
	// oauth2_jwt (Bearer JWT válido validado criptograficamente). O access
	// JWT não existe no Redis: sem este early return o miss abaixo viraria
	// 401 falso quando OAUTH2_STRICT_401=true.
	if v, ok := c.Get("auth.jwt").(bool); ok && v {
		return nil
	}

	authorizationToken := c.Request().Header.Get("Authorization")

	if authorizationToken == "" {
		return nil
	}

	token := GetOauth2TokenFromAuthorization(authorizationToken)
	if token == "" {
		// not is a oauth2 token
		return nil
	}

	strict401 := Strict401Enabled(ctx.App.GetConfiguration())

	strData, err := GetAccessToken(token)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			if strict401 {
				// token inexistente no redis (expirado/revogado): responde 401
				// explícito em vez de seguir anônimo
				return NewUnauthorizedTokenHTTPError(c, "token expired")
			}

			return nil
		}

		logrus.WithFields(logrus.Fields{
			"token": token,
			"error": err,
		}).Error("oauth2TokenAuthentication Error on get data from access token")

		return &ForbiddenHTTPError{
			Code:         401,
			Message:      errors.New("invalid token"),
			ErrorMessage: "invalid_grant",
			ErrorContext: "authentication",
		}
	}

	var data Oauth2TokenData
	err = json.Unmarshal([]byte(strData), &data)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"token": token,
			"data":  strData,
			"error": err,
		}).Error("oauth2TokenAuthentication Error on parse data from access result")

		return &echo.HTTPError{
			Code:    403,
			Message: errors.New("invalid token data"),
		}
	}

	if !data.IsValid() {
		if strict401 {
			return NewUnauthorizedTokenHTTPError(c, "token expired")
		}

		// Não-strict: token expirado segue anônimo, como a chave inexistente
		// acima. 403 fica reservado para inativo/bloqueado — o frontend trata
		// qualquer 403 como sinal definitivo de sessão inválida e um token
		// expirado nessa janela deslogaria o usuário sem tentar o refresh.
		return nil
	}

	// get user from DB:
	var userRecord user_models.UserModel
	err = user_models.UserFindOne(data.OwnerId.String(), &userRecord)
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return &echo.HTTPError{
				Code:    403,
				Message: errors.New("invalid token"),
			}
		}

		return &echo.HTTPError{
			Code:    500,
			Message: errors.New("internal server error"),
		}
	}

	if userRecord.Blocked {
		return &echo.HTTPError{
			Code:    403,
			Message: errors.New("user is blocked"),
		}
	}

	ctx.SetAuthenticatedUserAndFillRoles(&userRecord)

	return nil
}

// GetOauth2TokenFromAuthorization extrai o token oauth2 do header
// Authorization. Aceita SOMENTE o prefixo "Bearer": outros esquemas (ex.:
// "Basic") não carregam um access token oauth2 e devolvem "".
func GetOauth2TokenFromAuthorization(authorization string) string {
	if !strings.HasPrefix(authorization, "Bearer") {
		return ""
	}

	tokenData := strings.Split(authorization, " ")
	if len(tokenData) == 2 {
		return strings.TrimSpace(tokenData[1])
	}

	return ""
}

func ValidUsernamePassword(username, password string) (bool, error) {
	var passwordRecord user_models.PasswordModel

	err := user_models.FindPasswordByUsername(username, &passwordRecord)
	if err != nil {
		return false, err
	}

	isValid, err := passwordRecord.Compare(password)
	if err != nil && !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, err
	}

	if !isValid {
		return false, nil
	}

	return true, nil
}

func Oauth2FindUserWithToken(accessToken string) (bolo.UserInterface, error) {
	return nil, nil
}

type Oauth2TokenData struct {
	ID           string      `json:"id"`
	OwnerId      json.Number `json:"ownerId"`
	AccessToken  string      `json:"access_token"`
	RefreshToken string      `json:"refresh_token"`
	TokenType    string      `json:"token_type"`
	Scopes       []string    `json:"scopes"`
	ExpireDate   time.Time   `json:"expireDate"`
	ExpiresIn    int64       `json:"expiresIn"`
}

func (r *Oauth2TokenData) IsValid() bool {
	now := time.Now()

	return now.Before(r.ExpireDate)
}

func Oauth2GenerateToken(ctx *bolo.RequestContext, u bolo.UserInterface) (Oauth2TokenData, error) {
	var data Oauth2TokenData

	cfgs := ctx.App.GetConfiguration()

	accessToken := uuid.New().String() + helpers.RandStringBytes(35)
	refreshToken := uuid.New().String() + helpers.RandStringBytes(35)

	// TTL configurável com unidade (OAUTH2_ACCESS_TOKEN_TTL); erro de config
	// é explícito — não gera token com prazo errado
	expireD, err := AccessTokenTTL(cfgs)
	if err != nil {
		return data, err
	}

	expire := int64(expireD / time.Second)

	expireDate := time.Now()
	expireDate = expireDate.Add(expireD)

	data = Oauth2TokenData{
		ID:           accessToken,
		OwnerId:      json.Number(u.GetID()),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "",
		Scopes:       []string{},
		ExpireDate:   expireDate,
		ExpiresIn:    expire,
	}

	return data, nil
}

func Oauth2GenerateAndSaveToken(ctx *bolo.RequestContext, user bolo.UserInterface) (Oauth2TokenData, error) {
	data, err := Oauth2GenerateToken(ctx, user)
	if err != nil {
		return data, err
	}

	dataJSON, _ := json.MarshalIndent(data, "", "  ")

	err = SetAccessToken(ctx, data.AccessToken, string(dataJSON))
	if err != nil {
		return data, err
	}

	err = SetRefreshToken(ctx, data.RefreshToken, string(dataJSON))
	if err != nil {
		return data, err
	}

	return data, nil
}

// Oauth2GenerateAndSaveTokenJWT emite o par no formato JWT: access token
// stateless (validação criptográfica, NÃO gravado no Redis) + refresh token
// opaco rotativo já no formato novo (RT: com família e teto absoluto desde o
// login — a primeira rotação apenas continua a família).
//
// Exige o gerador JWT registrado via SetJWTAccessGenerator (feito pelo
// subplugin oauth2_jwt no evento configuration); sem ele devolve erro
// explícito em vez de emitir token em formato desconhecido.
func Oauth2GenerateAndSaveTokenJWT(reqCtx *bolo.RequestContext, user bolo.UserInterface) (Oauth2TokenData, error) {
	var data Oauth2TokenData

	accessToken, expiresIn, err := generateJWTAccess(reqCtx, user)
	if err != nil {
		return data, err
	}

	cfgs := reqCtx.App.GetConfiguration()

	idleTTL, err := RefreshIdleTTL(cfgs)
	if err != nil {
		return data, err
	}

	absoluteTTL, err := RefreshAbsoluteTTL(cfgs)
	if err != nil {
		return data, err
	}

	refreshToken := generateRefreshToken()

	now := time.Now()

	record := RefreshTokenRecord{
		OwnerID:          json.Number(user.GetID()),
		FamilyID:         uuid.New().String(),
		CreatedAt:        now,
		AbsoluteDeadline: now.Add(absoluteTTL),
	}

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return data, err
	}

	// refresh token novo com TTL idle (renovado a cada rotação)
	if err := StorageDBWriter.Set(ctx, RefreshTokenKeyPrefix+refreshToken, string(recordJSON), idleTTL).Err(); err != nil {
		return data, err
	}

	// família nasce indexando o token inicial, com o teto absoluto de vida
	familyKey := RefreshTokenFamilyKeyPrefix + record.FamilyID
	if err := StorageDBWriter.SAdd(ctx, familyKey, refreshToken).Err(); err != nil {
		return data, err
	}

	if err := StorageDBWriter.Expire(ctx, familyKey, absoluteTTL).Err(); err != nil {
		return data, err
	}

	data = Oauth2TokenData{
		ID:           accessToken,
		OwnerId:      json.Number(user.GetID()),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "",
		Scopes:       []string{},
		ExpireDate:   now.Add(time.Duration(expiresIn) * time.Second),
		ExpiresIn:    expiresIn,
	}

	return data, nil
}
