package user_oauth2_password

import "github.com/labstack/echo/v4"

func oauth2AuthenticationMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if isPublicRoute(c.Path()) {
				return next(c)
			}

			err := HandleRequestAuthentication(c)
			if err != nil {
				return err
			}

			return next(c)
		}
	}
}
