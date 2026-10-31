package cmd

import (
	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
)

// cipherKey resolves the effective decryption key for a cipher.
// For organization ciphers the base key is the org's symmetric key (from orgKeys).
// If the cipher has its own per-item key field, it is decrypted with the base key.
// A decrypted key of 64 bytes is used directly; 32 bytes are HKDF-expanded to 64.
// Falls back to accountKey on any error.
func cipherKey(cipher client.Cipher, accountKey []byte, orgKeys map[string][]byte) []byte {
	return computeCipherKey(cipher, accountKey, orgKeys)
}

// computeCipherKey is the uncached implementation backing both cipherKey and
// cipherKeyResolver.
func computeCipherKey(cipher client.Cipher, accountKey []byte, orgKeys map[string][]byte) []byte {
	baseKey := accountKey
	if cipher.OrganizationID != nil && *cipher.OrganizationID != "" {
		if orgKey, ok := orgKeys[*cipher.OrganizationID]; ok {
			baseKey = orgKey
		}
	}

	if cipher.Key == nil || *cipher.Key == "" {
		return baseKey
	}
	decryptedKey, err := crypto.Decrypt(*cipher.Key, baseKey)
	if err != nil {
		return baseKey
	}
	switch len(decryptedKey) {
	case 64:
		return decryptedKey
	case 32:
		expandedKey, err := crypto.ExpandKey(decryptedKey)
		crypto.Wipe(decryptedKey)
		if err != nil {
			return baseKey
		}
		return expandedKey
	default:
		return baseKey
	}
}

// cipherKeyResolver caches per-cipher decryption keys so that the expensive
// Decrypt + ExpandKey operations are performed at most once per cipher ID.
// It is safe for use within a single command invocation; it is not safe for
// concurrent use.
type cipherKeyResolver struct {
	accountKey []byte
	orgKeys    map[string][]byte
	cache      map[string][]byte
}

// newCipherKeyResolver creates a resolver that caches cipher keys derived
// from accountKey and orgKeys.
func newCipherKeyResolver(accountKey []byte, orgKeys map[string][]byte) *cipherKeyResolver {
	return &cipherKeyResolver{
		accountKey: accountKey,
		orgKeys:    orgKeys,
		cache:      make(map[string][]byte),
	}
}

// key returns the effective decryption key for cipher, computing and caching
// it on first access. Subsequent calls for the same cipher.ID return the
// cached result without re-running Decrypt or ExpandKey.
func (r *cipherKeyResolver) key(cipher client.Cipher) []byte {
	if k, ok := r.cache[cipher.ID]; ok {
		return k
	}
	k := computeCipherKey(cipher, r.accountKey, r.orgKeys)
	r.cache[cipher.ID] = k
	return k
}
