package migrations_user

import (
	"fmt"

	"github.com/go-bolo/bolo"
	"gorm.io/gorm"
)

func GetInitMigration() *bolo.Migration {
	queries := []struct {
		table string
		up    string
		down  string
	}{
		{
			table: "users",
			up: `CREATE TABLE users (
				id int NOT NULL AUTO_INCREMENT,
				username varchar(191) DEFAULT NULL,
				displayName longtext,
				fullName longtext,
				biography text,
				gender longtext,
				email varchar(191) DEFAULT NULL,
				active tinyint(1) DEFAULT NULL,
				language longtext,
				acceptTerms tinyint(1) DEFAULT NULL,
				roles longtext,
				createdAt datetime(3) DEFAULT NULL,
				updatedAt datetime(3) DEFAULT NULL,
				blocked tinyint(1) DEFAULT NULL,
				birthdate longtext,
				phone longtext,
				locationState varchar(10) DEFAULT NULL,
				country varchar(5) DEFAULT 'BR',
				city varchar(255) DEFAULT NULL,
				investments longtext,
				receiveInformations tinyint(1) DEFAULT NULL,
				alreadyInvest longtext,
				capitalToInvest longtext,
				confirmEmail longtext,
				PRIMARY KEY (id),
				UNIQUE KEY email (email),
				UNIQUE KEY users_email_unique (email),
				UNIQUE KEY username (username),
				UNIQUE KEY users_username_unique (username),
				UNIQUE KEY email_2 (email),
				UNIQUE KEY username_2 (username)
			)`,
		},
		{
			table: "passwords",
			up: `CREATE TABLE passwords (
				id int NOT NULL AUTO_INCREMENT,
				userId bigint DEFAULT NULL,
				active tinyint(1) DEFAULT '1',
				password text,
				createdAt datetime NOT NULL,
				updatedAt datetime NOT NULL,
				PRIMARY KEY (id)
			)`,
		},
		{
			table: "authtokens",
			up: `CREATE TABLE authtokens (
				id int NOT NULL AUTO_INCREMENT,
				userId bigint NOT NULL,
				providerUserId bigint DEFAULT NULL,
				tokenProviderId varchar(255) DEFAULT NULL,
				tokenType varchar(255) DEFAULT NULL,
				token varchar(255) DEFAULT '1',
				isValid tinyint(1) DEFAULT '1',
				redirectUrl varchar(255) DEFAULT NULL,
				createdAt datetime NOT NULL,
				updatedAt datetime NOT NULL,
				PRIMARY KEY (id)
			)`,
		},
	}

	return &bolo.Migration{
		Name: "init",
		Up: func(app bolo.App) error {
			db := app.GetDB()
			return db.Transaction(func(tx *gorm.DB) error {
				for _, q := range queries {
					err := tx.Exec(q.up).Error
					if err != nil {
						return fmt.Errorf("failed to create "+q.table+" table: %w", err)
					}
				}

				return nil
			})
		},
		Down: func(app bolo.App) error {
			return nil
		},
	}
}
