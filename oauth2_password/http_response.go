package user_oauth2_password

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

type ForbiddenHTTPError struct {
	Code         int         `json:"code"`
	Message      interface{} `json:"message"`
	Internal     error       `json:"-"` // Stores the error returned by an external dependency
	ErrorMessage string      `json:"error"`
	ErrorContext string      `json:"error_context"`
}

// Error makes it compatible with `error` interface.
func (e *ForbiddenHTTPError) Error() string {
	if e.Internal == nil {
		return fmt.Sprintf("code=%d, message=%v", e.Code, e.Message)
	}
	return fmt.Sprintf("code=%d, message=%v, internal=%v", e.Code, e.Message, e.Internal)
}

func (e *ForbiddenHTTPError) GetCode() int {
	return e.Code
}

func (e *ForbiddenHTTPError) SetCode(code int) error {
	e.Code = code
	return nil
}

func (e *ForbiddenHTTPError) GetMessage() interface{} {
	return e.Message
}

func (e *ForbiddenHTTPError) SetMessage(message interface{}) error {
	e.Message = message
	return nil
}

func (e *ForbiddenHTTPError) GetInternal() error {
	return e.Internal
}

func (e *ForbiddenHTTPError) SetInternal(internal error) error {
	e.Internal = internal
	return nil
}

// UnauthorizedHTTPError é o erro do modo strict 401: token Bearer
// inexistente/expirado responde 401 com header WWW-Authenticate (RFC 6750) e
// corpo no formato BaseErrorResponse. Embute ForbiddenHTTPError para não
// duplicar o contrato de corpo/JSON (mesma forma serializada; apenas a
// semântica do código difere — 401 via factory abaixo).
type UnauthorizedHTTPError struct {
	ForbiddenHTTPError
}

// NewUnauthorizedTokenHTTPError monta o 401 do modo strict: registra o header
// WWW-Authenticate na resposta e devolve o erro compatível com o handler do
// bolo (que renderiza o corpo no formato BaseErrorResponse para JSON).
func NewUnauthorizedTokenHTTPError(c echo.Context, description string) error {
	c.Response().Header().Set(echo.HeaderWWWAuthenticate, fmt.Sprintf(`Bearer error="invalid_token", error_description="%s"`, description))

	return &UnauthorizedHTTPError{
		ForbiddenHTTPError: ForbiddenHTTPError{
			Code:         http.StatusUnauthorized,
			Message:      description,
			ErrorMessage: "invalid_token",
			ErrorContext: "authentication",
		},
	}
}
