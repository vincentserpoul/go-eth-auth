package goethauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GetChallenge returns a 64 char length string generated securely and randomly
func GetChallenge() (string, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "",
			fmt.Errorf("GetChallenge: error reading random bytes: %v", err)
	}

	return base64.StdEncoding.EncodeToString((b)), nil
}
