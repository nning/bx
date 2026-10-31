package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // Bitwarden type-4 specifies SHA-1
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

// DecryptRSAOAEP decrypts a Bitwarden RSA-OAEP cipher string (type 3 or 4) using the
// provided DER-encoded PKCS8 RSA private key bytes.
func DecryptRSAOAEP(cipherString string, privateKeyDER []byte) ([]byte, error) {
	key, err := x509.ParsePKCS8PrivateKey(privateKeyDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	parts := strings.SplitN(cipherString, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid RSA cipher string format")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA ciphertext: %w", err)
	}

	switch parts[0] {
	case "4": // Rsa2048OaepSha1_B64
		//nolint:gosec // SHA-1 required by Bitwarden type-4 spec
		return rsa.DecryptOAEP(sha1.New(), rand.Reader, rsaKey, ciphertext, nil)
	case "3": // Rsa2048OaepSha256_B64
		return rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, ciphertext, nil)
	default:
		return nil, fmt.Errorf("unsupported RSA encryption type: %s", parts[0])
	}
}
