package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestDecrypt_EmptyString(t *testing.T) {
	result, err := Decrypt("", []byte("key"))
	if err != nil {
		t.Fatalf("Decrypt empty string failed: %v", err)
	}
	if result != nil {
		t.Fatal("Decrypt empty string should return nil")
	}
}

func TestDecrypt_InvalidFormat(t *testing.T) {
	_, err := Decrypt("invalidformat", []byte("key"))
	if err == nil {
		t.Fatal("Expected error for invalid format")
	}
}

func TestDecrypt_UnsupportedType(t *testing.T) {
	_, err := Decrypt("99.somedata", []byte("key"))
	if err == nil {
		t.Fatal("Expected error for unsupported encryption type")
	}
}

func TestDecryptType2_InvalidMAC(t *testing.T) {
	iv := base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	ciphertext := base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	invalidMac := base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	cipherString := "2." + iv + "|" + ciphertext + "|" + invalidMac

	key := make([]byte, 64)
	_, err := Decrypt(cipherString, key)
	if err == nil {
		t.Fatal("Expected error for invalid MAC")
	}
}

func TestDecryptType2_InvalidFormat(t *testing.T) {
	key := make([]byte, 64)

	// Test with missing parts
	_, err := Decrypt("2.onlyonepart", key)
	if err == nil {
		t.Fatal("Expected error for invalid type 2 format")
	}
}

func TestDecryptType2_WrongKeyLength(t *testing.T) {
	iv := base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	ciphertext := base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	mac := base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})

	cipherString := "2." + iv + "|" + ciphertext + "|" + mac

	wrongKey := make([]byte, 32) // Should be 64
	_, err := Decrypt(cipherString, wrongKey)
	if err == nil {
		t.Fatal("Expected error for wrong key length")
	}
}

func TestDecryptType0_InvalidFormat(t *testing.T) {
	key := make([]byte, 32)

	// Test with missing parts
	_, err := Decrypt("0.onlyonepart|toomanyparts|andmore", key)
	if err == nil {
		t.Fatal("Expected error for invalid type 0 format")
	}
}

func TestDecryptType0_InvalidBase64(t *testing.T) {
	key := make([]byte, 32)

	cipherString := "0.!!!invalid!!!|!!!invalid!!!"
	_, err := Decrypt(cipherString, key)
	if err == nil {
		t.Fatal("Expected error for invalid base64")
	}
}

func TestPkcs7Unpad(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    []byte
		wantErr bool
	}{
		{
			name:    "valid padding 1",
			data:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1},
			want:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			wantErr: false,
		},
		{
			name:    "valid padding 16",
			data:    []byte{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
			want:    []byte{},
			wantErr: false,
		},
		{
			name:    "empty data",
			data:    []byte{},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid padding value",
			data:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid padding bytes",
			data:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 2},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "zero padding",
			data:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "padding equals data length returns empty",
			data:    []byte{5, 5, 5, 5, 5}, // padding=5 equals length=5, result is empty slice
			want:    []byte{},
			wantErr: false,
		},
		{
			name:    "padding strictly exceeds data length",
			data:    []byte{6, 6, 6, 6, 6}, // padding=6 but only 5 bytes, 6>5
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pkcs7Unpad(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("pkcs7Unpad error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(got) != len(tt.want) {
				t.Fatalf("pkcs7Unpad length mismatch: got %d, want %d", len(got), len(tt.want))
			}
		})
	}
}

// pkcs7PadTest pads data to a multiple of the AES block size using PKCS7.
func pkcs7PadTest(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

// buildType2CipherString produces a valid AES-CBC-HMAC-SHA256 (type 2) cipher
// string from plaintext using the provided 64-byte key and separator ("|" or ".").
func buildType2CipherString(t *testing.T, key []byte, plaintext []byte, sep string) string {
	t.Helper()
	encKey, macKey := key[:32], key[32:]
	padded := pkcs7PadTest(plaintext)

	iv := make([]byte, aes.BlockSize)
	for i := range iv {
		iv[i] = byte(i + 1)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ciphertext)
	mac := h.Sum(nil)

	return "2." +
		base64.StdEncoding.EncodeToString(iv) + sep +
		base64.StdEncoding.EncodeToString(ciphertext) + sep +
		base64.StdEncoding.EncodeToString(mac)
}

// TestDecryptType2_Success verifies a complete AES-CBC-HMAC round-trip with "|" separators.
func TestDecryptType2_Success(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i + 1)
	}
	plaintext := []byte("hello, bitwarden vault")
	cipherStr := buildType2CipherString(t, key, plaintext, "|")

	got, err := Decrypt(cipherStr, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Decrypt: got %q, want %q", got, plaintext)
	}
}

// TestDecryptType2_DotSeparatorSuccess verifies that type-2 cipher strings using
// "." separators are handled identically.
func TestDecryptType2_DotSeparatorSuccess(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i + 1)
	}
	plaintext := []byte("hello, bitwarden vault")
	cipherStr := buildType2CipherString(t, key, plaintext, ".")

	got, err := Decrypt(cipherStr, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Decrypt: got %q, want %q", got, plaintext)
	}
}

// TestDecryptType2_InvalidIVBase64 verifies that an invalid IV base64 string
// returns an error.
func TestDecryptType2_InvalidIVBase64(t *testing.T) {
	key := make([]byte, 64)
	_, err := Decrypt("2.!!!invalid!!!|dGVzdA==|dGVzdA==", key)
	if err == nil {
		t.Fatal("expected error for invalid IV base64")
	}
}

// TestDecryptType2_InvalidCiphertextBase64 verifies that an invalid ciphertext
// base64 string returns an error.
func TestDecryptType2_InvalidCiphertextBase64(t *testing.T) {
	key := make([]byte, 64)
	ivB64 := base64.StdEncoding.EncodeToString(make([]byte, 16))
	_, err := Decrypt("2."+ivB64+"|!!!invalid!!!|dGVzdA==", key)
	if err == nil {
		t.Fatal("expected error for invalid ciphertext base64")
	}
}

// TestDecryptType2_InvalidMACBase64 verifies that an invalid MAC base64 string
// returns an error.
func TestDecryptType2_InvalidMACBase64(t *testing.T) {
	key := make([]byte, 64)
	ivB64 := base64.StdEncoding.EncodeToString(make([]byte, 16))
	ctB64 := base64.StdEncoding.EncodeToString(make([]byte, 16))
	_, err := Decrypt("2."+ivB64+"|"+ctB64+"|!!!invalid!!!", key)
	if err == nil {
		t.Fatal("expected error for invalid MAC base64")
	}
}

// TestDecryptType2_NonBlockSizeCiphertext verifies that a ciphertext whose
// length is not a multiple of the AES block size returns an error.
func TestDecryptType2_NonBlockSizeCiphertext(t *testing.T) {
	key := make([]byte, 64)
	macKey := key[32:]
	iv := make([]byte, 16)
	ciphertext := make([]byte, 15) // 15 is not a multiple of 16

	// Compute a valid HMAC so we pass the HMAC check before the block-size check.
	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ciphertext)
	mac := h.Sum(nil)

	cipherStr := "2." +
		base64.StdEncoding.EncodeToString(iv) + "|" +
		base64.StdEncoding.EncodeToString(ciphertext) + "|" +
		base64.StdEncoding.EncodeToString(mac)

	_, err := Decrypt(cipherStr, key)
	if err == nil {
		t.Fatal("expected error for non-block-size ciphertext")
	}
}

// TestDecryptType0_Success verifies a complete AES-CBC (no HMAC) round-trip.
func TestDecryptType0_Success(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	plaintext := []byte("hello, bitwarden vault")
	padded := pkcs7PadTest(plaintext)

	iv := make([]byte, aes.BlockSize)
	for i := range iv {
		iv[i] = byte(i + 17)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	cipherStr := "0." +
		base64.StdEncoding.EncodeToString(iv) + "|" +
		base64.StdEncoding.EncodeToString(ciphertext)

	got, err := Decrypt(cipherStr, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Decrypt: got %q, want %q", got, plaintext)
	}
}

// TestDecryptType0_BadCiphertextBase64 verifies that a valid IV but invalid
// ciphertext base64 returns an error.
func TestDecryptType0_BadCiphertextBase64(t *testing.T) {
	key := make([]byte, 32)
	ivB64 := base64.StdEncoding.EncodeToString(make([]byte, 16))
	_, err := Decrypt("0."+ivB64+"|!!!invalid!!!", key)
	if err == nil {
		t.Fatal("expected error for invalid ciphertext base64")
	}
}

// TestDecryptType0_WrongKeyLength verifies that an AES-unsupported key length
// returns an error.
func TestDecryptType0_WrongKeyLength(t *testing.T) {
	key := make([]byte, 31) // Not 16, 24, or 32 bytes
	ivB64 := base64.StdEncoding.EncodeToString(make([]byte, 16))
	ctB64 := base64.StdEncoding.EncodeToString(make([]byte, 16))
	_, err := Decrypt("0."+ivB64+"|"+ctB64, key)
	if err == nil {
		t.Fatal("expected error for invalid AES key length")
	}
}

// TestDecryptType2_InvalidIVLength verifies that a type-2 cipher string with an
// IV that is not exactly 16 bytes returns an error instead of panicking.
func TestDecryptType2_InvalidIVLength(t *testing.T) {
	key := make([]byte, 64)
	macKey := key[32:]

	shortIV := make([]byte, 8) // only 8 bytes instead of 16
	ciphertext := make([]byte, 16)

	h := hmac.New(sha256.New, macKey)
	h.Write(shortIV)
	h.Write(ciphertext)
	mac := h.Sum(nil)

	cipherStr := "2." +
		base64.StdEncoding.EncodeToString(shortIV) + "|" +
		base64.StdEncoding.EncodeToString(ciphertext) + "|" +
		base64.StdEncoding.EncodeToString(mac)

	_, err := Decrypt(cipherStr, key)
	if err == nil {
		t.Fatal("expected error for invalid IV length in type 2 cipher string")
	}
}

// TestDecryptType0_InvalidIVLength verifies that a type-0 cipher string with an
// IV that is not exactly 16 bytes returns an error instead of panicking.
func TestDecryptType0_InvalidIVLength(t *testing.T) {
	key := make([]byte, 32)

	shortIV := make([]byte, 8) // only 8 bytes instead of 16
	ciphertext := make([]byte, 16)

	cipherStr := "0." +
		base64.StdEncoding.EncodeToString(shortIV) + "|" +
		base64.StdEncoding.EncodeToString(ciphertext)

	_, err := Decrypt(cipherStr, key)
	if err == nil {
		t.Fatal("expected error for invalid IV length in type 0 cipher string")
	}
}

// ---- Encrypt tests -------------------------------------------------------

// TestEncrypt_RoundTrip verifies that Encrypt followed by Decrypt returns the
// original plaintext.
func TestEncrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i + 1)
	}

	plaintexts := [][]byte{
		[]byte("hello, world"),
		[]byte(""),
		[]byte("exactly sixteen!"),
		[]byte("this is a much longer string that will span multiple AES blocks"),
		{0x00, 0x01, 0x02, 0x03}, // binary data
	}

	for _, plaintext := range plaintexts {
		cipherStr, err := Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", plaintext, err)
		}
		if !bytes.HasPrefix([]byte(cipherStr), []byte("2.")) {
			t.Fatalf("Encrypt result must start with '2.', got %q", cipherStr[:3])
		}

		got, err := Decrypt(cipherStr, key)
		if err != nil {
			t.Fatalf("Decrypt(%q): %v", plaintext, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
		}
	}
}

// TestEncrypt_WrongKeyLength verifies that Encrypt rejects keys that are not
// exactly 64 bytes.
func TestEncrypt_WrongKeyLength(t *testing.T) {
	for _, keyLen := range []int{0, 16, 32, 63, 65, 128} {
		_, err := Encrypt([]byte("test"), make([]byte, keyLen))
		if err == nil {
			t.Errorf("expected error for key length %d", keyLen)
		}
	}
}

// TestEncrypt_IVUniqueness verifies that two calls to Encrypt with the same
// key and plaintext produce different cipher strings (different IVs).
func TestEncrypt_IVUniqueness(t *testing.T) {
	key := make([]byte, 64)
	plaintext := []byte("same plaintext")

	s1, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	s2, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if s1 == s2 {
		t.Error("expected different cipher strings for two separate Encrypt calls (different IVs)")
	}
}

// TestDecryptType0_RejectedForFullKey verifies that an unauthenticated type 0
// value is refused under a 64-byte enc+mac key, so a tampered vault cache
// cannot downgrade a type 2 value to bypass the MAC check.
func TestDecryptType0_RejectedForFullKey(t *testing.T) {
	key := make([]byte, 64)
	ivB64 := base64.StdEncoding.EncodeToString(make([]byte, 16))
	ctB64 := base64.StdEncoding.EncodeToString(make([]byte, 16))
	_, err := Decrypt("0."+ivB64+"|"+ctB64, key)
	if err == nil || !strings.Contains(err.Error(), "unauthenticated") {
		t.Fatalf("expected type 0 to be refused for a 64-byte key, got %v", err)
	}
}

// TestDecryptType0_NonBlockSizeCiphertext verifies that a partial block is
// reported as an error instead of panicking inside CryptBlocks.
func TestDecryptType0_NonBlockSizeCiphertext(t *testing.T) {
	key := make([]byte, 32)
	ivB64 := base64.StdEncoding.EncodeToString(make([]byte, 16))
	ctB64 := base64.StdEncoding.EncodeToString(make([]byte, 15))
	_, err := Decrypt("0."+ivB64+"|"+ctB64, key)
	if err == nil {
		t.Fatal("expected error for non-block-size ciphertext")
	}
}

func TestWipe(t *testing.T) {
	b := []byte{1, 2, 3}
	Wipe(b)
	if !bytes.Equal(b, []byte{0, 0, 0}) {
		t.Errorf("Wipe: got %v, want all zeros", b)
	}
}

func BenchmarkDecryptType2(b *testing.B) {
	key := make([]byte, 64)
	cs, err := Encrypt([]byte("a typical vault item name"), key)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if _, err := Decrypt(cs, key); err != nil {
			b.Fatal(err)
		}
	}
}
