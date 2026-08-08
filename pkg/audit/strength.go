package audit

import (
	"github.com/nbutton23/zxcvbn-go"
)

// passwordStrength returns the zxcvbn score (0–4) for the given password.
// A score of 0 means trivially guessable; 4 means very strong.
func passwordStrength(password string) int {
	if password == "" {
		return 0
	}
	result := zxcvbn.PasswordStrength(password, nil)
	return result.Score
}
