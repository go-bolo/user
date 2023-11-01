package user_oauth2_password

import "fmt"

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
