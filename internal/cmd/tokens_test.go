package cmd

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	keyring "github.com/zalando/go-keyring"
)

func TestStoreTokens_KeyringKeepsThemOutOfConfig(t *testing.T) {
	resetViperAndAccount(t)
	activeAccountName = "work"
	viper.Set("accounts.work.session_token", "old-plaintext")

	storeTokens(accountTokens{Session: "access", Refresh: "refresh"})

	if got := viper.GetString("accounts.work.session_token"); got != "" {
		t.Errorf("session token left in config: %q", got)
	}
	if got := viper.GetString("accounts.work.refresh_token"); got != "" {
		t.Errorf("refresh token left in config: %q", got)
	}
	if got := loadTokens(); got != (accountTokens{Session: "access", Refresh: "refresh"}) {
		t.Errorf("loadTokens() = %+v", got)
	}
}

func TestStoreTokens_FallsBackToConfigWithoutKeyring(t *testing.T) {
	resetViperAndAccount(t)
	keyring.MockInitWithError(errors.New("no keyring daemon"))
	t.Cleanup(keyring.MockInit)
	activeAccountName = "work"

	storeTokens(accountTokens{Session: "access", Refresh: "refresh"})

	if got := viper.GetString("accounts.work.session_token"); got != "access" {
		t.Errorf("session token in config = %q, want access", got)
	}
	if got := loadTokens(); got != (accountTokens{Session: "access", Refresh: "refresh"}) {
		t.Errorf("loadTokens() = %+v", got)
	}
}

func TestMigrateTokensToKeyring(t *testing.T) {
	resetViperAndAccount(t)
	viper.SetConfigFile(filepath.Join(t.TempDir(), ".bx.yaml"))
	activeAccountName = "work"
	// A stale keyring entry is overwritten: a plaintext copy is always newer.
	if err := keyring.Set(tokensKeyringService, tokensKeyringUser("work"), `{"session_token":"stale"}`); err != nil {
		t.Fatal(err)
	}
	viper.Set("accounts.work.session_token", "access")
	viper.Set("accounts.work.refresh_token", "refresh")

	migrateTokensToKeyring()

	if got := viper.GetString("accounts.work.session_token"); got != "" {
		t.Errorf("session token left in config: %q", got)
	}
	if got := loadTokens(); got != (accountTokens{Session: "access", Refresh: "refresh"}) {
		t.Errorf("loadTokens() = %+v", got)
	}
}

func TestMoveAndDeleteTokens(t *testing.T) {
	resetViperAndAccount(t)
	if err := keyring.Set(tokensKeyringService, tokensKeyringUser("old"), `{"session_token":"a"}`); err != nil {
		t.Fatal(err)
	}

	if err := moveTokens("old", "new"); err != nil {
		t.Fatalf("moveTokens: %v", err)
	}
	if _, err := keyring.Get(tokensKeyringService, tokensKeyringUser("old")); err != keyring.ErrNotFound {
		t.Errorf("old entry still present: %v", err)
	}
	activeAccountName = "new"
	if got := loadTokens().Session; got != "a" {
		t.Errorf("moved session token = %q, want a", got)
	}

	if err := deleteTokens("new"); err != nil {
		t.Fatalf("deleteTokens: %v", err)
	}
	if err := deleteTokens("new"); err != nil {
		t.Errorf("deleting a missing entry should succeed, got %v", err)
	}
	if err := moveTokens("missing", "other"); err != nil {
		t.Errorf("moving a missing entry should succeed, got %v", err)
	}
}
