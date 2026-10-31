package cmd

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// setupCompletionVault seeds an unlocked session and a local vault cache with
// two active items, one trash item and two folders, and points viper at an
// unlock timeout so that no password prompt is attempted.
func setupCompletionVault(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())

	resetViperAndAccount(t)
	viper.Set("unlock_timeout", 15)

	key := testKey()
	ciphers := []client.Cipher{
		makeCipherWithUsername(t, "11111111-1111-1111-1111-111111111111", "GitHub", "user", "", key),
		makeCipher(t, "22222222-2222-2222-2222-222222222222", "Google", "", key),
		makeDeletedCipher(t, "33333333-3333-3333-3333-333333333333", "OldEntry", key),
	}
	folders := []client.Folder{
		{ID: "folder-1", Name: encryptStr(t, key, "Work")},
		{ID: "folder-2", Name: encryptStr(t, key, "Personal")},
	}
	raw, err := json.Marshal(struct {
		Profile client.Profile  `json:"profile"`
		Folders []client.Folder `json:"folders"`
		Ciphers []client.Cipher `json:"ciphers"`
	}{Profile: client.Profile{ID: "user-id", Email: "user@example.com", Key: "key"}, Folders: folders, Ciphers: ciphers})
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
	if err := vault.SaveSession(key, nil); err != nil {
		t.Fatal(err)
	}
}

func TestItemCompletions_ActiveItems(t *testing.T) {
	setupCompletionVault(t)

	complete := itemCompletions(false)
	names, directive := complete(nil, nil, "")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("directive: %v", directive)
	}
	want := []string{"GitHub", "Google"}
	if len(names) != len(want) {
		t.Fatalf("got %v, want %v", names, want)
	}
	for i, w := range want {
		if names[i] != w {
			t.Errorf("names[%d] = %q, want %q", i, names[i], w)
		}
	}
}

func TestItemCompletions_Prefix(t *testing.T) {
	setupCompletionVault(t)

	complete := itemCompletions(false)
	names, _ := complete(nil, nil, "git")
	if len(names) != 1 || names[0] != "GitHub" {
		t.Errorf("got %v, want [GitHub]", names)
	}
}

func TestItemCompletions_DeletedItems(t *testing.T) {
	setupCompletionVault(t)

	complete := itemCompletions(true)
	names, _ := complete(nil, nil, "")
	if len(names) != 1 || names[0] != "OldEntry" {
		t.Errorf("got %v, want [OldEntry]", names)
	}
}

func TestItemCompletions_WithArgCompletesNothing(t *testing.T) {
	setupCompletionVault(t)

	complete := itemCompletions(false)
	names, _ := complete(nil, []string{"GitHub"}, "")
	if names != nil {
		t.Errorf("expected no completions with an item already given, got %v", names)
	}
}

func TestItemCompletions_LockedVaultCompletesNothing(t *testing.T) {
	setupCompletionVault(t)
	// Lock the vault: no session, and completion must not prompt.
	if err := vault.ClearSession(); err != nil {
		t.Fatal(err)
	}
	viper.Set("unlock_timeout", 0)

	complete := itemCompletions(false)
	names, directive := complete(nil, nil, "")
	if names != nil {
		t.Errorf("expected no completions for a locked vault, got %v", names)
	}
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("directive: %v", directive)
	}
}

func TestFolderCompletions(t *testing.T) {
	setupCompletionVault(t)

	names, directive := folderCompletions(nil, nil, "")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("directive: %v", directive)
	}
	if len(names) != 2 || names[0] != "Work" || names[1] != "Personal" {
		t.Errorf("got %v, want [Work Personal]", names)
	}

	names, _ = folderCompletions(nil, []string{"Work"}, "")
	if names != nil {
		t.Errorf("expected no completions with a folder already given, got %v", names)
	}
}

func TestFlagFolderCompletions(t *testing.T) {
	setupCompletionVault(t)

	names, _ := flagFolderCompletions(nil, nil, "per")
	if len(names) != 1 || names[0] != "Personal" {
		t.Errorf("got %v, want [Personal]", names)
	}
}

func TestFolderNamesWithPrefix_SkipsUndecryptable(t *testing.T) {
	key := testKey()
	folders := []client.Folder{
		{ID: "bad", Name: "not-a-cipher-string"},
		{ID: "ok", Name: encryptStr(t, key, "Work")},
	}
	names := folderNamesWithPrefix(folders, key, "")
	if len(names) != 1 || names[0] != "Work" {
		t.Errorf("got %v, want [Work]", names)
	}
}
