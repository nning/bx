package crypto

import (
	"bytes"
	"strings"
	"testing"
)

// testKey64 returns a deterministic 64-byte key.
func testKey64(seed byte) []byte {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i) + seed
	}
	return key
}

func TestIsCipherString(t *testing.T) {
	key := testKey64(1)
	encrypted, err := Encrypt([]byte("hello"), key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"type 2 pipe separated", encrypted, true},
		{"type 2 dot separated", "2.AAAAAAAAAAAAAAAAAAAAAA==.YWJj.ZGVm", true},
		{"type 0", "0.AAAAAAAAAAAAAAAAAAAAAA==|YWJj", true},
		{"empty", "", false},
		{"plain text", "hello world", false},
		{"uuid", "499e7dd1-e068-4837-850a-cf1e65eee67e", false},
		{"iso date", "2000-07-31T20:02:00.1234567Z", false},
		{"rsa type 4 single segment", "4.AAAA", true},
		{"rsa type 5 with mac", "5.AAAA|BBBB", true},
		{"legacy aes-128 type 1", "1.AAAAAAAAAAAAAAAAAAAAAA==|YWJj|ZGVm", true},
		{"unknown enc type", "9.AAAA|BBBB|CCCC", false},
		{"type 4 with two segments", "4.AAAA|BBBB", false},
		{"missing type prefix", "AAAA|BBBB|CCCC", false},
		{"too few segments", "2.AAAA|BBBB", false},
		{"too many segments", "2.AAAA|BBBB|CCCC|DDDD", false},
		{"type 3 with non base64 payload", "3.not base64!", false},
		{"empty segment", "2.AAAA||CCCC", false},
		{"non base64 segment", "2.AAAA|not base64!|CCCC", false},
		{"type 0 with three segments", "0.AAAA|BBBB|CCCC", false},
		{"numeric-looking value", "0.5", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCipherString(tt.input); got != tt.want {
				t.Errorf("IsCipherString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestReencrypt_RoundTrip(t *testing.T) {
	oldKey := testKey64(1)
	newKey := testKey64(100)

	original, err := Encrypt([]byte("s3cret value"), oldKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	reencrypted, err := Reencrypt(original, oldKey, newKey)
	if err != nil {
		t.Fatalf("Reencrypt: %v", err)
	}
	if reencrypted == original {
		t.Error("expected a different cipher string after re-encryption")
	}

	// The old key must no longer work, the new one must.
	if _, err := Decrypt(reencrypted, oldKey); err == nil {
		t.Error("expected the old key to fail on the re-encrypted value")
	}
	plaintext, err := Decrypt(reencrypted, newKey)
	if err != nil {
		t.Fatalf("Decrypt with new key: %v", err)
	}
	if string(plaintext) != "s3cret value" {
		t.Errorf("got %q, want %q", string(plaintext), "s3cret value")
	}
}

func TestReencrypt_EmptyPlaintext(t *testing.T) {
	oldKey := testKey64(1)
	newKey := testKey64(100)

	original, err := Encrypt([]byte(""), oldKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	reencrypted, err := Reencrypt(original, oldKey, newKey)
	if err != nil {
		t.Fatalf("Reencrypt: %v", err)
	}
	plaintext, err := Decrypt(reencrypted, newKey)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if len(plaintext) != 0 {
		t.Errorf("got %q, want empty", string(plaintext))
	}
}

func TestReencrypt_WrongOldKey(t *testing.T) {
	oldKey := testKey64(1)
	wrongKey := testKey64(2)
	newKey := testKey64(100)

	original, err := Encrypt([]byte("value"), oldKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Reencrypt(original, wrongKey, newKey); err == nil {
		t.Fatal("expected an error when decrypting with the wrong key")
	} else if !strings.Contains(err.Error(), "decrypt") {
		t.Errorf("expected a decrypt error, got %v", err)
	}
}

func TestReencrypt_InvalidNewKeyLength(t *testing.T) {
	oldKey := testKey64(1)
	original, err := Encrypt([]byte("value"), oldKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Reencrypt(original, oldKey, make([]byte, 32)); err == nil {
		t.Fatal("expected an error for a 32-byte target key")
	} else if !strings.Contains(err.Error(), "encrypt") {
		t.Errorf("expected an encrypt error, got %v", err)
	}
}

func TestNormalizeSymmetricKey(t *testing.T) {
	key64 := testKey64(1)
	got, err := NormalizeSymmetricKey(key64)
	if err != nil {
		t.Fatalf("NormalizeSymmetricKey(64): %v", err)
	}
	if !bytes.Equal(got, key64) {
		t.Error("a 64-byte key must be returned unchanged")
	}

	key32 := make([]byte, 32)
	for i := range key32 {
		key32[i] = byte(i)
	}
	got, err = NormalizeSymmetricKey(key32)
	if err != nil {
		t.Fatalf("NormalizeSymmetricKey(32): %v", err)
	}
	if len(got) != 64 {
		t.Errorf("expected a 64-byte expanded key, got %d bytes", len(got))
	}
	expanded, err := ExpandKey(key32)
	if err != nil {
		t.Fatalf("ExpandKey: %v", err)
	}
	if !bytes.Equal(got, expanded) {
		t.Error("expected the HKDF-expanded key")
	}

	if _, err := NormalizeSymmetricKey(make([]byte, 16)); err == nil {
		t.Error("expected an error for a 16-byte key")
	}
}

// TestReencrypt_UnsupportedEncryptionType documents that values bx recognizes as
// ciphertext but cannot decrypt cause a hard error, so that a caller re-keying an
// item aborts instead of forwarding a value encrypted with the old key.
func TestReencrypt_UnsupportedEncryptionType(t *testing.T) {
	const legacy = "1.AAAAAAAAAAAAAAAAAAAAAA==|YWJj|ZGVm"
	if !IsCipherString(legacy) {
		t.Fatal("a legacy AES-128 value must be recognized as ciphertext")
	}
	if _, err := Reencrypt(legacy, testKey64(1), testKey64(100)); err == nil {
		t.Fatal("expected an error for an unsupported encryption type")
	}
}
