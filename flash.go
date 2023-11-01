package user

import (
	"encoding/json"
	"fmt"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

type FlashMessage struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Field   string `json:"field"`
	Tag     string `json:"tag"`
}

func (m *FlashMessage) ToJSON() []byte {
	mByte, _ := json.Marshal(m)
	return mByte
}

type FlashMessages []*FlashMessage

func AddFlashMessage(c echo.Context, m *FlashMessage) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return fmt.Errorf("AddFlashMessage: error on get session:%w", err)
	}

	sess.AddFlash(m.ToJSON(), "messages")
	return sess.Save(c.Request(), c.Response())
}

func GetFlashMessages(c echo.Context) (messages FlashMessages, err error) {
	sess, err := session.Get("session", c)
	if err != nil {
		return nil, fmt.Errorf("GetFlashMessages: error on get session:%w", err)
	}

	fls := sess.Flashes("messages")

	if len(fls) > 0 {
		sess.Save(c.Request(), c.Response())
		for _, fl := range fls {
			var m FlashMessage
			json.Unmarshal(fl.([]byte), &m)
			messages = append(messages, &m)
		}
		return messages, nil
	}

	return messages, nil
}
