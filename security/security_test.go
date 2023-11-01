package security_test

import (
	"github.com/go-bolo/bolo"
)

var appInstance bolo.App

func GetAppInstance() bolo.App {
	if appInstance != nil {
		return appInstance
	}

	app := bolo.Init(&bolo.AppOptions{})
	err := app.Bootstrap()
	if err != nil {
		panic(err)
	}

	return app
}
