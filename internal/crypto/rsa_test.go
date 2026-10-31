package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // Bitwarden type-4 specifies SHA-1
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

// generateTestRSAKey creates a 2048-bit RSA key pair for use in tests.
func generateTestRSAKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	privKeyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey: %v", err)
	}
	return privKey, privKeyDER
}

// TestDecryptRSAOAEP_InvalidPrivateKey verifies that an invalid DER key returns
// an error.
func TestDecryptRSAOAEP_InvalidPrivateKey(t *testing.T) {
	_, err := DecryptRSAOAEP("4.dGVzdA==", []byte("not-a-valid-der-key"))
	if err == nil {
		t.Fatal("expected error for invalid private key DER")
	}
}

// TestDecryptRSAOAEP_InvalidFormat verifies that a cipher string without a "."
// separator returns an error.
func TestDecryptRSAOAEP_InvalidFormat(t *testing.T) {
	_, privKeyDER := generateTestRSAKey(t)
	_, err := DecryptRSAOAEP("nodotinstring", privKeyDER)
	if err == nil {
		t.Fatal("expected error for cipher string missing '.' separator")
	}
}

// TestDecryptRSAOAEP_UnsupportedType verifies that an unknown encryption type
// prefix returns an error.
func TestDecryptRSAOAEP_UnsupportedType(t *testing.T) {
	_, privKeyDER := generateTestRSAKey(t)
	for _, prefix := range []string{"5", "6", "99"} {
		if _, err := DecryptRSAOAEP(prefix+".dGVzdA==", privKeyDER); err == nil {
			t.Fatalf("unsupported RSA encryption type %s was accepted", prefix)
		}
	}
}

// TestDecryptRSAOAEP_InvalidBase64Ciphertext verifies that a malformed base64
// ciphertext returns an error.
func TestDecryptRSAOAEP_InvalidBase64Ciphertext(t *testing.T) {
	_, privKeyDER := generateTestRSAKey(t)
	_, err := DecryptRSAOAEP("4.!!!invalid!!!", privKeyDER)
	if err == nil {
		t.Fatal("expected error for invalid base64 ciphertext")
	}
}

// TestDecryptRSAOAEP_ValidType4 verifies round-trip encryption/decryption using
// Bitwarden type 4 (RSA-OAEP-SHA1).
func TestDecryptRSAOAEP_ValidType4(t *testing.T) {
	privKey, privKeyDER := generateTestRSAKey(t)
	plaintext := []byte("type-4-test-secret")

	//nolint:gosec // SHA-1 is required for Bitwarden type-4 round-trip testing
	ciphertext, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &privKey.PublicKey, plaintext, nil)
	if err != nil {
		t.Fatalf("rsa.EncryptOAEP (type 4): %v", err)
	}
	cipherStr := "4." + base64.StdEncoding.EncodeToString(ciphertext)

	got, err := DecryptRSAOAEP(cipherStr, privKeyDER)
	if err != nil {
		t.Fatalf("DecryptRSAOAEP (type 4): %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("DecryptRSAOAEP (type 4): got %q, want %q", got, plaintext)
	}
}

// TestDecryptRSAOAEP_ValidType3 verifies round-trip encryption/decryption using
// Bitwarden type 3 (RSA-OAEP-SHA256).
func TestDecryptRSAOAEP_ValidType3(t *testing.T) {
	privKey, privKeyDER := generateTestRSAKey(t)
	plaintext := []byte("type-3-test-secret")

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privKey.PublicKey, plaintext, nil)
	if err != nil {
		t.Fatalf("rsa.EncryptOAEP (type 3): %v", err)
	}
	cipherStr := "3." + base64.StdEncoding.EncodeToString(ciphertext)

	got, err := DecryptRSAOAEP(cipherStr, privKeyDER)
	if err != nil {
		t.Fatalf("DecryptRSAOAEP (type 3): %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("DecryptRSAOAEP (type 3): got %q, want %q", got, plaintext)
	}
}
