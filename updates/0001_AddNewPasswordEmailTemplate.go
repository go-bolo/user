package updates

import "github.com/go-bolo/bolo"

var AddNewPasswordEmailTemplateChange = bolo.Migration{
	Name: "AddNewPasswordEmailTemplate",
	Up: func(app bolo.App) error {

		return nil
	},
	Down: func(app bolo.App) error {

		return nil
	},
}
