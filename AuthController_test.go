package user_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	approvals "github.com/approvals/go-approval-tests"
	"github.com/go-bolo/bolo"
	"github.com/go-bolo/user"
	user_models "github.com/go-bolo/user/models"
	auth_oauth2_password "github.com/go-bolo/user/oauth2_password"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"

	"github.com/alicebob/miniredis/v2"
	"github.com/brianvoe/gofakeit/v6"
)

func TestAuthController_GetCurrentUser(t *testing.T) {
	s := miniredis.RunT(t)

	mockedDB := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	user.SessionDBWriter = mockedDB
	user.SessionDBReader = mockedDB

	app := NewApp(t)
	u := GetCurrentUser(t)

	ctx := app.NewRequestContext(&bolo.RequestContextOpts{App: app})
	err := u.Save(ctx)
	assert.NoError(t, err)
	defer u.Delete()

	type fields struct {
		App bolo.App
	}
	type args struct {
		user *user_models.UserModel

		accept string
		data   io.Reader
		url    string
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		expectedBody   *user_models.UserModelPublic
		expectedStatus int
		wantErr        bool
	}{
		{
			name: "authenticatedRequest",
			fields: fields{
				App: app,
			},
			args: args{
				user: GetCurrentUser(t),

				url:    "/auth/current",
				accept: "application/json",
			},
			expectedBody:   user_models.NewUserModelPublicFromUserModel(GetCurrentUser(t)),
			expectedStatus: http.StatusOK,
			wantErr:        false,
		},
		{
			name: "unAuthenticated request",
			fields: fields{
				App: app,
			}, args: args{
				url:    "/auth/current",
				accept: "application/json",
			},
			expectedBody:   user_models.NewUserModelPublicFromUserModel(&user_models.UserModel{}),
			expectedStatus: http.StatusOK,
			wantErr:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := app.GetRouter()
			ctx := app.NewRequestContext(&bolo.RequestContextOpts{App: app})

			req := httptest.NewRequest(http.MethodGet, tt.args.url, tt.args.data)
			req.Header.Set(echo.HeaderAccept, tt.args.accept)
			// Body content type:
			req.Header.Set(echo.HeaderContentType, "application/json")

			if tt.args.user != nil {
				authToken, err := auth_oauth2_password.Oauth2GenerateAndSaveToken(ctx, tt.args.user)
				assert.Nil(t, err)
				req.Header.Set(echo.HeaderAuthorization, "Bearer "+authToken.AccessToken)
			}

			rec := httptest.NewRecorder() // run the request:
			e.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			switch tt.args.accept {
			case "application/json":
				approvals.VerifyJSONBytes(t, rec.Body.Bytes())
			}
		})
	}

}

func TestAuthController_Signup(t *testing.T) {
	s := miniredis.RunT(t)

	mockedDB := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	user.SessionDBWriter = mockedDB
	user.SessionDBReader = mockedDB

	app := NewApp(t)
	e := app.GetRouter()

	type fields struct {
		App bolo.App
	}
	type args struct {
		body user.SignupBody
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		expectedBody   user.SignupResponse
		expectedStatus int
		wantErr        bool
	}{
		{
			name: "success",
			fields: fields{
				App: app,
			}, args: args{
				body: user.SignupBody{
					AcceptTerms:  true,
					Username:     "alberto",
					Email:        "user@linkysystems.com",
					ConfirmEmail: "user@linkysystems.com",
					DisplayName:  "Alberto",
					FullName:     "Alberto Souza",
				},
			},
			expectedBody: user.SignupResponse{User: &user_models.UserModel{
				ID:           1,
				AcceptTerms:  true,
				Username:     "alberto",
				Email:        "user@linkysystems.com",
				ConfirmEmail: "",
				DisplayName:  "Alberto",
				FullName:     "Alberto Souza",
			}},
			expectedStatus: http.StatusOK,
			wantErr:        false,
		},
		{
			name: "error invalid username",
			fields: fields{
				App: app,
			}, args: args{
				body: user.SignupBody{
					AcceptTerms:  true,
					Username:     "alberto **{{",
					Email:        "user@linkysystems.com",
					ConfirmEmail: "user@linkysystems.com",
					DisplayName:  "Alberto",
					FullName:     "Alberto Souza",
				},
			},
			expectedBody: user.SignupResponse{
				Errors: []*bolo.ValidationFieldError{
					{
						Field:   "username",
						Message: "invalid username",
					},
				},
			},
			expectedStatus: http.StatusBadRequest,
			wantErr:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(tt.args.body.ToJSON()))
			assert.Nil(t, err)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Request().Header.Set("Accept", "application/json")
			c.Request().Header.Set("Content-Type", "application/json")

			ctx := bolo.NewRequestContext(&bolo.RequestContextOpts{EchoContext: c})

			ctl := &user.AuthController{
				App: tt.fields.App,
			}
			if err := ctl.Signup(ctx); (err != nil) != tt.wantErr {
				t.Errorf("AuthController.Signup() error = %v, wantErr %v", err, tt.wantErr)
			} else {
				var respBody user.SignupResponse
				err = json.Unmarshal(rec.Body.Bytes(), &respBody)
				assert.Nil(t, err)

				if respBody.User != nil {
					assert.NotEqual(t, respBody.User.ID, 0)
					tt.expectedBody.User.ID = respBody.User.ID
					respBody.User.UpdatedAt = tt.expectedBody.User.UpdatedAt
					respBody.User.CreatedAt = tt.expectedBody.User.CreatedAt
				}

				assert.Equal(t, tt.expectedBody, respBody)

				if respBody.User != nil {
					respBody.User.Delete()
				}
			}

			assert.Equal(t, tt.expectedStatus, rec.Result().StatusCode)
		})
	}
}

func TestAuthController_Logout(t *testing.T) {
	s := miniredis.RunT(t)

	mockedDB := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	user.SessionDBWriter = mockedDB
	user.SessionDBReader = mockedDB

	app := NewApp(t)

	type fields struct {
		App bolo.App
	}
	type args struct {
		method         string
		oauth2Password bool
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		wantErr        bool
		expectedStatus int
	}{
		{
			name: "successfully logout with GET",
			args: args{
				method:         http.MethodGet,
				oauth2Password: true,
			},
			expectedStatus: 200,
		},
		{
			name: "successfully logout with POST",
			args: args{
				method:         http.MethodPost,
				oauth2Password: true,
			},
			expectedStatus: 200,
		},
		{
			name: "successfully skip if not authenticated",
			args: args{
				method:         http.MethodGet,
				oauth2Password: false,
			},
			expectedStatus: 200,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := app.GetRouter()
			ctx := app.NewRequestContext(&bolo.RequestContextOpts{App: app})

			u := GetCurrentUser(t)
			err := u.Save(ctx)
			assert.NoError(t, err)
			defer u.Delete()

			// Request logout:
			req := httptest.NewRequest(tt.args.method, "/auth/logout", nil)
			rec := httptest.NewRecorder()

			var authToken auth_oauth2_password.Oauth2TokenData
			if tt.args.oauth2Password {
				var err error
				authToken, err = auth_oauth2_password.Oauth2GenerateAndSaveToken(ctx, u)
				assert.Nil(t, err)
				req.Header.Set(echo.HeaderAuthorization, "Bearer "+authToken.AccessToken)
			}

			e.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
			assert.Equal(t, "{}\n", rec.Body.String())

			// Check if the session still exists:
			req2 := httptest.NewRequest(http.MethodGet, "/auth/current", nil)
			if tt.args.oauth2Password {
				req2.Header.Set(echo.HeaderAuthorization, "Bearer "+authToken.AccessToken)
			}
			rec2 := httptest.NewRecorder()
			e.ServeHTTP(rec2, req2)

			assert.Equal(t, http.StatusOK, rec2.Code)
			assert.Equal(t, "{}\n", rec2.Body.String())
		})
	}
}

// TestAuthController_LogoutRevokesRefreshTokenFamily cobre o logout estendido:
// X-Refresh-Token (ou body) revoga a família de refresh tokens, não só o
// access token do header Authorization.
func TestAuthController_LogoutRevokesRefreshTokenFamily(t *testing.T) {
	s := miniredis.RunT(t)

	mockedDB := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	user.SessionDBWriter = mockedDB
	user.SessionDBReader = mockedDB

	app := NewApp(t)

	u := user_models.UserModel{
		Username:    gofakeit.UUID(),
		Email:       gofakeit.Email(),
		DisplayName: "Logout Refresh Test User",
		Active:      true,
	}

	ctx := app.NewRequestContext(&bolo.RequestContextOpts{App: app})
	err := u.Save(ctx)
	assert.NoError(t, err)
	defer u.Delete()

	// login (formato legado) + primeira rotação criam a família no storage:
	authToken, err := auth_oauth2_password.Oauth2GenerateAndSaveToken(ctx, &u)
	assert.Nil(t, err)

	pair, _, rerr := auth_oauth2_password.RotateRefreshToken(ctx, authToken.RefreshToken)
	assert.Nil(t, rerr)
	assert.NotNil(t, pair)

	storageCtx := context.Background()
	familyID, err := auth_oauth2_password.StorageDBWriter.Get(storageCtx, auth_oauth2_password.RefreshTokenTombKeyPrefix+authToken.RefreshToken).Result()
	assert.NoError(t, err)
	assert.NotEmpty(t, familyID)

	assert.Equal(t, int64(1), auth_oauth2_password.StorageDBWriter.Exists(storageCtx, auth_oauth2_password.RefreshTokenKeyPrefix+pair.RefreshToken).Val())

	// logout levando o refresh token do par novo via header:
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("X-Refresh-Token", pair.RefreshToken)
	rec := httptest.NewRecorder()
	app.GetRouter().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// família revogada: refresh ativo e índice da família sumiram do storage
	assert.Equal(t, int64(0), auth_oauth2_password.StorageDBWriter.Exists(storageCtx, auth_oauth2_password.RefreshTokenKeyPrefix+pair.RefreshToken).Val())
	assert.Equal(t, int64(0), auth_oauth2_password.StorageDBWriter.Exists(storageCtx, auth_oauth2_password.RefreshTokenFamilyKeyPrefix+familyID).Val())
}

func TestAuthController_Activate(t *testing.T) {
	type fields struct {
		App bolo.App
	}
	type args struct {
		c echo.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctl := &user.AuthController{
				App: tt.fields.App,
			}
			if err := ctl.Activate(tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("AuthController.Activate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthController_CheckIfResetPasswordTokenIsValid(t *testing.T) {
	type fields struct {
		App bolo.App
	}
	type args struct {
		c echo.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctl := &user.AuthController{
				App: tt.fields.App,
			}
			if err := ctl.CheckIfResetPasswordTokenIsValid(tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("AuthController.CheckIfResetPasswordTokenIsValid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthController_ForgotPasswordUpdate(t *testing.T) {
	type fields struct {
		App bolo.App
	}
	type args struct {
		c echo.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctl := &user.AuthController{
				App: tt.fields.App,
			}
			if err := ctl.ForgotPasswordUpdate(tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("AuthController.ForgotPasswordUpdate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthController_UpdatePassword(t *testing.T) {
	type fields struct {
		App bolo.App
	}
	type args struct {
		c echo.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctl := &user.AuthController{
				App: tt.fields.App,
			}
			if err := ctl.UpdatePassword(tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("AuthController.UpdatePassword() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewAuthController(t *testing.T) {
	type args struct {
		cfg *user.NewAuthControllerCFG
	}
	tests := []struct {
		name string
		args args
		want *user.AuthController
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := user.NewAuthController(tt.args.cfg); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAuthController() = %v, want %v", got, tt.want)
			}
		})
	}
}

// GetCurrentUser devolve o usuário padrão dos testes (dados casam com os
// approvals em testdata/approvals; timestamps vêm do clock mockado do app).
func GetCurrentUser(t *testing.T) *user_models.UserModel {
	t.Helper()

	return &user_models.UserModel{
		ID:          2,
		Username:    "alberto",
		Email:       "alberto@example.com",
		DisplayName: "Alberto Contato",
		Language:    "pt-br",
		Active:      true,
		CreatedAt:   time.Date(2017, 10, 11, 19, 46, 40, 0, time.UTC),
	}
}
