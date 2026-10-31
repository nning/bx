package crypto

import (
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestDeriveMasterKey_PBKDF2(t *testing.T) {
	config := KdfConfig{
		Type:        KdfTypePBKDF2,
		Iterations:  100000,
		Memory:      0,
		Parallelism: 0,
	}

	key, err := DeriveMasterKey("password", "test@example.com", config)
	if err != nil {
		t.Fatalf("DeriveMasterKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Fatalf("Expected key length 32, got %d", len(key))
	}

	// Same input should produce same output
	key2, _ := DeriveMasterKey("password", "test@example.com", config)
	for i := 0; i < 32; i++ {
		if key[i] != key2[i] {
			t.Fatal("Deterministic output failed")
		}
	}

	// Different password should produce different output
	key3, _ := DeriveMasterKey("different", "test@example.com", config)
	different := false
	for i := 0; i < 32; i++ {
		if key[i] != key3[i] {
			different = true
			break
		}
	}
	if !different {
		t.Fatal("Different password should produce different key")
	}
}

func TestDeriveMasterKey_Argon2id(t *testing.T) {
	config := KdfConfig{
		Type:        KdfTypeArgon2id,
		Iterations:  3,
		Memory:      64,
		Parallelism: 4,
	}

	key, err := DeriveMasterKey("password", "test@example.com", config)
	if err != nil {
		t.Fatalf("DeriveMasterKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Fatalf("Expected key length 32, got %d", len(key))
	}

	// Verify deterministic output
	key2, _ := DeriveMasterKey("password", "test@example.com", config)
	for i := 0; i < 32; i++ {
		if key[i] != key2[i] {
			t.Fatal("Deterministic output failed for Argon2id")
		}
	}
}

func TestDeriveMasterKey_Argon2id_SHA256Salt(t *testing.T) {
	// Per Bitwarden spec, Argon2id uses SHA256(email) as salt rather than
	// the raw email bytes (which PBKDF2 uses). Verify by computing the
	// expected result directly with argon2.IDKey and a SHA256-hashed salt.
	config := KdfConfig{
		Type:        KdfTypeArgon2id,
		Iterations:  3,
		Memory:      64,
		Parallelism: 4,
	}

	key, err := DeriveMasterKey("password", "test@example.com", config)
	if err != nil {
		t.Fatalf("DeriveMasterKey failed: %v", err)
	}

	// Compute expected key using SHA256(email) salt directly.
	saltHash := sha256.Sum256([]byte("test@example.com"))
	want := argon2.IDKey([]byte("password"), saltHash[:], 3, 64*1024, 4, 32)

	for i := 0; i < 32; i++ {
		if key[i] != want[i] {
			t.Fatalf("Argon2id key mismatch at byte %d: got %02x, want %02x", i, key[i], want[i])
		}
	}
}

func TestDeriveMasterKey_InvalidKdfType(t *testing.T) {
	config := KdfConfig{
		Type:        999,
		Iterations:  100000,
		Memory:      0,
		Parallelism: 0,
	}

	_, err := DeriveMasterKey("password", "test@example.com", config)
	if err == nil {
		t.Fatal("Expected error for invalid KDF type")
	}
}

func TestDeriveMasterKey_PBKDF2_ZeroIterations(t *testing.T) {
	config := KdfConfig{
		Type:       KdfTypePBKDF2,
		Iterations: 0,
	}
	_, err := DeriveMasterKey("password", "test@example.com", config)
	if err == nil {
		t.Fatal("Expected error for PBKDF2 with zero iterations")
	}
}

func TestDeriveMasterKey_Argon2id_InvalidParams(t *testing.T) {
	tests := []struct {
		name   string
		config KdfConfig
	}{
		{
			name: "zero iterations",
			config: KdfConfig{
				Type:        KdfTypeArgon2id,
				Iterations:  0,
				Memory:      64,
				Parallelism: 4,
			},
		},
		{
			name: "zero memory",
			config: KdfConfig{
				Type:        KdfTypeArgon2id,
				Iterations:  3,
				Memory:      0,
				Parallelism: 4,
			},
		},
		{
			name: "zero parallelism",
			config: KdfConfig{
				Type:        KdfTypeArgon2id,
				Iterations:  3,
				Memory:      64,
				Parallelism: 0,
			},
		},
		{
			name: "parallelism 256 (uint8 overflow to 0)",
			config: KdfConfig{
				Type:        KdfTypeArgon2id,
				Iterations:  3,
				Memory:      64,
				Parallelism: 256,
			},
		},
		{
			name: "parallelism 512 (out of range)",
			config: KdfConfig{
				Type:        KdfTypeArgon2id,
				Iterations:  3,
				Memory:      64,
				Parallelism: 512,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeriveMasterKey("password", "test@example.com", tt.config)
			if err == nil {
				t.Fatalf("Expected error for Argon2id config: %+v", tt.config)
			}
		})
	}
}

func TestHashMasterPassword(t *testing.T) {
	masterKey := []byte("thirtytwobytemasternkeyforcrypto")
	password := "mypassword"

	hash := HashMasterPassword(masterKey, password)
	if hash == "" {
		t.Fatal("Hash should not be empty")
	}

	// Should produce deterministic output
	hash2 := HashMasterPassword(masterKey, password)
	if hash != hash2 {
		t.Fatal("Hash should be deterministic")
	}

	// Different password should produce different hash
	hash3 := HashMasterPassword(masterKey, "differentpassword")
	if hash == hash3 {
		t.Fatal("Different password should produce different hash")
	}
}

func TestExpandKey(t *testing.T) {
	// Test with valid 32-byte key
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}

	expanded, err := ExpandKey(key)
	if err != nil {
		t.Fatalf("ExpandKey failed: %v", err)
	}
	if len(expanded) != 64 {
		t.Fatalf("Expected expanded key length 64, got %d", len(expanded))
	}

	// First 32 bytes should not be the same as input
	sameAsInput := true
	for i := 0; i < 32; i++ {
		if expanded[i] != key[i] {
			sameAsInput = false
			break
		}
	}
	if sameAsInput {
		t.Fatal("Expanded key should differ from input")
	}
}

func TestExpandKey_InvalidKeyLength(t *testing.T) {
	// Test with non-32-byte key should return error
	shortKey := make([]byte, 16)
	_, err := ExpandKey(shortKey)
	if err == nil {
		t.Fatal("ExpandKey should return error for non-32-byte key")
	}

	longKey := make([]byte, 64)
	_, err = ExpandKey(longKey)
	if err == nil {
		t.Fatal("ExpandKey should return error for non-32-byte key")
	}
}

func TestExpandKey_Deterministic(t *testing.T) {
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}

	expanded1, _ := ExpandKey(key)
	expanded2, _ := ExpandKey(key)

	for i := 0; i < 64; i++ {
		if expanded1[i] != expanded2[i] {
			t.Fatal("ExpandKey should be deterministic")
		}
	}
}
