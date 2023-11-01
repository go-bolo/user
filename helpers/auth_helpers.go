package user_helpers

import (
	"regexp"
)

func ValidateUsername(username string) bool {
	matched, _ := regexp.MatchString(`^[A-Za-z0-9_-]{2,30}$`, username)
	return matched
}
