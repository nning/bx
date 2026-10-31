package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

type KdfType int

const (
	KdfTypePBKDF2   KdfType = 0
	KdfTypeArgon2id KdfType = 1
)

type KdfConfig struct {
	Type        KdfType
	Iterations  int
	Memory      int // MB (only for Argon2)
	Parallelism int // threads (only for Argon2)
}

// DeriveMasterKey derives the master key from the email and password.
func DeriveMasterKey(password, email string, config KdfConfig) ([]byte, error) {
	emailLower := strings.ToLower(email)
	pwBytes := []byte(password)

	switch config.Type {
	case KdfTypePBKDF2:
		if config.Iterations < 1 {
			return nil, fmt.Errorf("PBKDF2 iterations must be >= 1, got %d", config.Iterations)
		}
		return pbkdf2.Key(pwBytes, []byte(emailLower), config.Iterations, 32, sha256.New), nil
	case KdfTypeArgon2id:
		if config.Iterations < 1 {
			return nil, fmt.Errorf("Argon2id time parameter must be >= 1, got %d", config.Iterations)
		}
		if config.Memory < 1 {
			return nil, fmt.Errorf("Argon2id memory parameter must be >= 1 MB, got %d", config.Memory)
		}
		// Argon2id parallelism is passed as uint8; a zero or out-of-range value
		// causes argon2.IDKey to panic, so validate the range explicitly.
		if config.Parallelism < 1 || config.Parallelism > 255 {
			return nil, fmt.Errorf("Argon2id parallelism must be 1-255, got %d", config.Parallelism)
		}
		// Guard against uint32 overflow: config.Memory is in MB and is
		// multiplied by 1024 to convert to KB for argon2.IDKey.
		// The maximum uint32 value is 4,294,967,295 KB, so the safe upper
		// bound for the MB input is floor(4294967295 / 1024) = 4,194,303 MB.
		// Use 4096 MB (4 GB) as a generous but clearly-safe practical cap.
		const maxMemoryMB = 4096
		if config.Memory > maxMemoryMB {
			return nil, fmt.Errorf("Argon2id memory parameter too large: %d MB (max %d MB)", config.Memory, maxMemoryMB)
		}
		// Per Bitwarden spec, Argon2id uses SHA256(email) as salt (a
		// fixed-length 32-byte value), whereas PBKDF2 uses the raw email.
		saltHash := sha256.Sum256([]byte(emailLower))
		return argon2.IDKey(pwBytes, saltHash[:], uint32(config.Iterations), uint32(config.Memory)*1024, uint8(config.Parallelism), 32), nil
	default:
		return nil, fmt.Errorf("unknown KDF type: %d", config.Type)
	}
}

// HashMasterPassword hashes the master key for login.
// The derived master key is used as the password material, and the user's password is used as the salt.
func HashMasterPassword(masterKey []byte, password string) string {
	hash := pbkdf2.Key(masterKey, []byte(password), 1, 32, sha256.New)
	return base64.StdEncoding.EncodeToString(hash)
}
