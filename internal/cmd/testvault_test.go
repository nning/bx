package cmd

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/vault"
	"github.com/spf13/viper"
)

// viperSetUnlockTimeout sets the unlock timeout for the duration of a test.
func viperSetUnlockTimeout(t *testing.T, minutes int) {
	t.Helper()
	viper.Set("unlock_timeout", minutes)
}

// writeVaultCache writes a local vault cache with the given ciphers, seeds an
// unlocked session with key, and returns the temp home directory.
func writeVaultCache(t *testing.T, key []byte, ciphers ...client.Cipher) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	resetViperAndAccount(t)
	viperSetUnlockTimeout(t, 15)

	raw, err := json.Marshal(struct {
		Profile client.Profile  `json:"profile"`
		Folders []client.Folder `json:"folders"`
		Ciphers []client.Cipher `json:"ciphers"`
	}{Profile: client.Profile{ID: "user-id", Email: "user@example.com", Key: "key"}, Ciphers: ciphers})
	if err != nil {
		t.Fatal(err)
	}
	path, err := vault.VaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Seed an unlocked session so that LoadVaultWithSession does not prompt
	// for the master password.
	if err := vault.SaveSession(key, nil); err != nil {
		t.Fatal(err)
	}
	return dir
}
