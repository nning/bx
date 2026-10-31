package crypto

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// IsCipherString reports whether s has the shape of a Bitwarden cipher string:
// an encryption type prefix followed by the number of base64 segments that type
// uses, separated by "|" or ".".
//
// It is deliberately strict — every segment must be non-empty and decode as
// standard base64 — so that plaintext values (UUIDs, ISO-8601 dates, numbers)
// are never mistaken for ciphertext when walking a cipher's JSON to re-encrypt
// it under a different key.
//
// All of Bitwarden's encryption types are recognized, not just the two bx can
// decrypt.  A value that is encrypted but unsupported must be reported as
// ciphertext so that callers fail on it instead of silently passing it through
// as if it were plaintext, which would leave it encrypted with the wrong key.
func IsCipherString(s string) bool {
	encType, data, found := strings.Cut(s, ".")
	if !found {
		return false
	}

	var wantParts int
	switch encType {
	case "3", // Rsa2048_OaepSha256_B64
		"4": // Rsa2048_OaepSha1_B64
		wantParts = 1
	case "0", // AesCbc256_B64
		"5", // Rsa2048_OaepSha256_HmacSha256_B64
		"6": // Rsa2048_OaepSha1_HmacSha256_B64
		wantParts = 2
	case "1", // AesCbc128_HmacSha256_B64
		"2": // AesCbc256_HmacSha256_B64
		wantParts = 3
	default:
		return false
	}

	// Bitwarden uses either '|' or '.' as the segment separator.
	parts := []string{data}
	if wantParts > 1 {
		sep := "|"
		if !strings.Contains(data, "|") {
			sep = "."
		}
		parts = strings.Split(data, sep)
	}
	if len(parts) != wantParts {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		if _, err := base64.StdEncoding.DecodeString(p); err != nil {
			return false
		}
	}
	return true
}

// Reencrypt decrypts cipherString with oldKey and re-encrypts the plaintext
// with newKey, returning a fresh type-2 cipher string. It is used when an item
// changes ownership (e.g. a personal item moved into an organization) and its
// encrypted values must be re-wrapped under a different symmetric key.
func Reencrypt(cipherString string, oldKey, newKey []byte) (string, error) {
	plaintext, err := Decrypt(cipherString, oldKey)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	encrypted, err := Encrypt(plaintext, newKey)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	return encrypted, nil
}

// NormalizeSymmetricKey returns a 64-byte key (32 bytes AES + 32 bytes HMAC)
// suitable for Encrypt and Decrypt. A 64-byte key is returned unchanged; a
// 32-byte key is HKDF-expanded. Any other length is rejected.
func NormalizeSymmetricKey(key []byte) ([]byte, error) {
	switch len(key) {
	case 64:
		return key, nil
	case 32:
		return ExpandKey(key)
	default:
		return nil, fmt.Errorf("unsupported symmetric key length %d (want 32 or 64)", len(key))
	}
}
