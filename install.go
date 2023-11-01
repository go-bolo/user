package user

import (
	"github.com/go-bolo/bolo"
	"github.com/go-bolo/emails"
)

func InstallAuth(app bolo.App) error {
	return CreateDefaultEmailTemplates(app)
}

func CreateDefaultEmailTemplates(app bolo.App) error {
	tpl := emails.EmailTemplateModel{
		Subject: "Hello! This is a test.",
		Text:    "Hello!! This is a test in body field.",
		Css:     "",
		Html:    "<p>Hello! This is a test in html body field.</p>",
		Type:    "AuthChangePasswordEmail",
	}
	tpl.Save()

	return nil
}
