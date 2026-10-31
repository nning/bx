package cmd

import (
	"fmt"

	"github.com/nning/bx/internal/crypto"
)

// encryptedLengthLimits are the maximum lengths of encrypted values that the
// Bitwarden server accepts (its EncryptedStringLength attributes; Vaultwarden
// enforces the notes limit).  Checking them before a request is sent turns an
// opaque 400 from the server into a message that names the field, and stops
// bx from encrypting arbitrarily large input.
var encryptedLengthLimits = map[string]int{
	"name":        1000,
	"notes":       10000,
	"username":    1000,
	"password":    5000,
	"totp":        1000,
	"uri":         10000,
	"field name":  1000,
	"field value": 5000,
	"folder name": 1000,
}

// encryptField encrypts plaintext with key and checks the result against the
// server limit for field (a key of encryptedLengthLimits).
func encryptField(field, plaintext string, key []byte) (string, error) {
	enc, err := crypto.Encrypt([]byte(plaintext), key)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt %s: %w", field, err)
	}
	if limit, ok := encryptedLengthLimits[field]; ok && len(enc) > limit {
		return "", fmt.Errorf("%s is too long: %d characters encrypt to %d, the server accepts at most %d", field, len([]rune(plaintext)), len(enc), limit)
	}
	return enc, nil
}
