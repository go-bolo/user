package user

import (
	"github.com/labstack/echo/v4"
)

func sessionAuthenticationMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if isPublicRoute(c.Path()) {
				return next(c)
			}

			err := HandleRequestSessionAuthentication(c)
			if err != nil {
				return err
			}

			return next(c)
		}
	}
}
