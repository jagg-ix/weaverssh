package evidencebinding

import (
	"crypto/rand"
	"encoding/base64"
)

func randomNonce(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
