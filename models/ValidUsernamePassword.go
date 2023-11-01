package user_models

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func ValidUsernamePassword(username, password string) (bool, error) {
	var passwordRecord PasswordModel

	err := FindPasswordByUsername(username, &passwordRecord)
	if err != nil {
		return false, err
	}

	isValid, err := passwordRecord.Compare(password)
	if err != nil && !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, err
	}

	if !isValid {
		return false, nil
	}

	return true, nil
}
