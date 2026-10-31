package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nning/bx/internal/crypto"
)

func TestLoadVaultOrganizationKeyErrorsAreReturned(t *testing.T) {
	home := withTempHome(t)
	data, accountKey := buildTestVaultJSON(t, "synthetic-password", "alice@example.com")
	var vault map[string]any
	if err := json.Unmarshal(data, &vault); err != nil {
		t.Fatal(err)
	}
	profile := vault["profile"].(map[string]any)
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	protectedPrivate, err := crypto.Encrypt(der, accountKey)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte{0x24}, 64)
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &private.PublicKey, want, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"3", "6"} {
		profile["privateKey"] = protectedPrivate
		profile["organizations"] = []any{map[string]any{"id": "org-1", "key": prefix + "." + base64.StdEncoding.EncodeToString(ciphertext)}}
		encoded, err := json.Marshal(vault)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".bx_vault.json"), encoded, 0600); err != nil {
			t.Fatal(err)
		}
		_, _, keys, err := LoadVault("synthetic-password")
		if prefix == "3" {
			if err != nil || !bytes.Equal(keys["org-1"], want) {
				t.Fatalf("official RSA type 3: %v", err)
			}
		} else if err == nil {
			t.Fatal("unsupported organization key was silently ignored")
		}
	}
}
