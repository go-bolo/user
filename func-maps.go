package user

import (
	"bytes"
	"html/template"

	"github.com/go-bolo/bolo"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

type FlashMessageTPL struct {
	Ctx     *bolo.RequestContext
	Message *FlashMessage
}

func renderFlashMessages(c echo.Context) template.HTML {
	html := ""

	ctx := c.(*bolo.RequestContext)

	flashes, _ := GetFlashMessages(ctx)

	var htmlBuff bytes.Buffer

	for _, flash := range flashes {
		err := ctx.RenderTemplate(&htmlBuff, "blocks/notifications/flash-message", FlashMessageTPL{
			Ctx:     ctx,
			Message: flash,
		})
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"err": err.Error(),
			}).Error("renderFlashMessages error on render message")
		}
	}

	html += htmlBuff.String()

	return template.HTML(html)
}
