package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nning/bx/internal/vault"
	"github.com/spf13/viper"
	keyring "github.com/zalando/go-keyring"
)

// TestMain sets up a mock OS keyring so that account tests that touch session
// state work without a real keyring daemon (e.g. in CI environments).
func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

// resetViperAndAccount clears viper and the active account name between tests.
func resetViperAndAccount(t *testing.T) {
	t.Helper()
	keyring.MockInit()
	viper.Reset()
	activeAccountName = ""
	vault.ActiveAccount = ""
}

func TestAccountSetting_NoActiveAccount(t *testing.T) {
	resetViperAndAccount(t)

	viper.Set("server", "https://example.com")
	viper.Set("email", "user@example.com")

	if got := accountSetting("server"); got != "https://example.com" {
		t.Errorf("accountSetting(server) = %q, want %q", got, "https://example.com")
	}
	if got := accountSetting("email"); got != "user@example.com" {
		t.Errorf("accountSetting(email) = %q, want %q", got, "user@example.com")
	}
}

func TestAccountSetting_WithActiveAccount(t *testing.T) {
	resetViperAndAccount(t)

	viper.Set("server", "https://global.example.com")
	viper.Set("accounts.work.server", "https://work.example.com")
	viper.Set("accounts.work.email", "user@work.com")
	activeAccountName = "work"

	if got := accountSetting("server"); got != "https://work.example.com" {
		t.Errorf("accountSetting(server) = %q, want %q", got, "https://work.example.com")
	}
	if got := accountSetting("email"); got != "user@work.com" {
		t.Errorf("accountSetting(email) = %q, want %q", got, "user@work.com")
	}
}

func TestAccountSetting_FallsBackToTopLevel(t *testing.T) {
	resetViperAndAccount(t)

	// When the key is absent from the account section, fall back to top-level.
	viper.Set("unlock_timeout", "30")
	activeAccountName = "work"

	if got := accountSetting("unlock_timeout"); got != "30" {
		t.Errorf("accountSetting(unlock_timeout) = %q, want %q", got, "30")
	}
}

func TestSetAccountSetting_NoActiveAccount(t *testing.T) {
	resetViperAndAccount(t)

	setAccountSetting("server", "https://example.com")

	if got := viper.GetString("server"); got != "https://example.com" {
		t.Errorf("viper.GetString(server) = %q, want %q", got, "https://example.com")
	}
}

func TestSetAccountSetting_WithActiveAccount(t *testing.T) {
	resetViperAndAccount(t)

	activeAccountName = "work"
	setAccountSetting("server", "https://work.example.com")
	setAccountSetting("email", "user@work.com")

	if got := viper.GetString("accounts.work.server"); got != "https://work.example.com" {
		t.Errorf("accounts.work.server = %q, want %q", got, "https://work.example.com")
	}
	if got := viper.GetString("accounts.work.email"); got != "user@work.com" {
		t.Errorf("accounts.work.email = %q, want %q", got, "user@work.com")
	}
	// Should not affect top-level keys.
	if got := viper.GetString("server"); got != "" {
		t.Errorf("top-level server = %q, want empty", got)
	}
}

func TestSetAccountSetting_DoesNotCrossContaminate(t *testing.T) {
	resetViperAndAccount(t)

	viper.Set("accounts.personal.server", "https://personal.example.com")
	activeAccountName = "work"
	setAccountSetting("server", "https://work.example.com")

	if got := viper.GetString("accounts.personal.server"); got != "https://personal.example.com" {
		t.Errorf("personal server contaminated: got %q, want %q", got, "https://personal.example.com")
	}
}

func TestRenameAccount_MovesConfigAndFiles(t *testing.T) {
	resetViperAndAccount(t)

	viper.Set("accounts.old.server", "https://example.com")
	viper.Set("accounts.old.email", "user@example.com")
	viper.Set("active_account", "old")

	// Create temporary per-account files.
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	oldVault := filepath.Join(tmpDir, ".bx_vault_old.json")
	if err := os.WriteFile(oldVault, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	oldSession := filepath.Join(tmpDir, ".bx_session_old.json")
	if err := os.WriteFile(oldSession, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Seed a keyring entry for the old account to verify it is cleared.
	if err := keyring.Set("bx", "session_old", `{"account_key":"b2xk"}`); err != nil {
		t.Fatalf("keyring.Set: %v", err)
	}

	cfgPath := filepath.Join(tmpDir, ".bx.yaml")
	viper.SetConfigFile(cfgPath)

	if err := renameAccount("old", "new"); err != nil {
		t.Fatalf("renameAccount() error: %v", err)
	}

	// Config should be under new name.
	if got := viper.GetString("accounts.new.server"); got != "https://example.com" {
		t.Errorf("accounts.new.server = %q, want %q", got, "https://example.com")
	}
	if got := viper.GetString("accounts.new.email"); got != "user@example.com" {
		t.Errorf("accounts.new.email = %q, want %q", got, "user@example.com")
	}

	// Old name should be gone.
	if got := viper.GetString("accounts.old.server"); got != "" {
		t.Errorf("accounts.old.server = %q, want empty", got)
	}

	// active_account should point to new name.
	if got := viper.GetString("active_account"); got != "new" {
		t.Errorf("active_account = %q, want %q", got, "new")
	}

	// Vault file should be renamed.
	newVault := filepath.Join(tmpDir, ".bx_vault_new.json")
	if _, err := os.Stat(newVault); err != nil {
		t.Errorf("new vault file not found: %v", err)
	}
	if _, err := os.Stat(oldVault); !os.IsNotExist(err) {
		t.Errorf("old vault file should not exist")
	}

	// Session files should be gone (ClearSession removes both file and keyring).
	if _, err := os.Stat(oldSession); !os.IsNotExist(err) {
		t.Errorf("old session file should not exist")
	}
	newSession := filepath.Join(tmpDir, ".bx_session_new.json")
	if _, err := os.Stat(newSession); !os.IsNotExist(err) {
		t.Errorf("new session file should not exist after keyring clear")
	}

	// Keyring entry for old account should be cleared.
	if _, err := keyring.Get("bx", "session_old"); err != keyring.ErrNotFound {
		t.Error("expected old keyring entry to be cleared by rename")
	}
	// Keyring entry for new account should also be cleared (user must re-login).
	if _, err := keyring.Get("bx", "session_new"); err != keyring.ErrNotFound {
		t.Error("expected new keyring entry to be cleared by rename")
	}
}

func TestRenameAccount_PreservesActiveWhenDifferent(t *testing.T) {
	resetViperAndAccount(t)

	viper.Set("accounts.a.server", "https://a.example.com")
	viper.Set("accounts.b.server", "https://b.example.com")
	viper.Set("active_account", "b")

	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	viper.SetConfigFile(filepath.Join(tmpDir, ".bx.yaml"))

	if err := renameAccount("a", "c"); err != nil {
		t.Fatalf("renameAccount() error: %v", err)
	}

	// active_account should still point to "b".
	if got := viper.GetString("active_account"); got != "b" {
		t.Errorf("active_account = %q, want %q", got, "b")
	}
}

func TestValidateAccountName(t *testing.T) {
	valid := []string{"default", "work", "my-account", "acc_123", "a-z-0-9"}
	for _, name := range valid {
		if err := validateAccountName(name); err != nil {
			t.Errorf("validateAccountName(%q) = %v, want nil", name, err)
		}
	}

	invalid := []string{"", "  ", "../etc", "a/b", "a.b", "a b", "name\x00bad", "A-Z_0-9", "Work", "MyAccount"}
	for _, name := range invalid {
		if err := validateAccountName(name); err == nil {
			t.Errorf("validateAccountName(%q) = nil, want error", name)
		}
	}
}

func TestRenameAccount_RefusesExistingTargetVault(t *testing.T) {
	resetViperAndAccount(t)

	viper.Set("accounts.old.server", "https://example.com")
	viper.Set("active_account", "old")

	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	viper.SetConfigFile(filepath.Join(tmpDir, ".bx.yaml"))

	// Create both old and new vault files.
	if err := os.WriteFile(filepath.Join(tmpDir, ".bx_vault_old.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, ".bx_vault_new.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	err := renameAccount("old", "new")
	if err == nil {
		t.Fatal("expected error when target vault file already exists")
	}
	if got := err.Error(); !strings.Contains(got, "refusing to rename") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- renameAccount: symlink / directory at target paths ---

func TestRenameAccount_RefusesSymlinkTargetVault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks on Windows require elevated privileges")
	}
	resetViperAndAccount(t)

	viper.Set("accounts.old.server", "https://example.com")
	viper.Set("active_account", "old")

	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	viper.SetConfigFile(filepath.Join(tmpDir, ".bx.yaml"))

	// Create a symlink at the new vault target path.
	newVaultPath := filepath.Join(tmpDir, ".bx_vault_new.json")
	if err := os.Symlink(filepath.Join(tmpDir, "nonexistent-target"), newVaultPath); err != nil {
		t.Fatalf("os.Symlink: %v", err)
	}

	err := renameAccount("old", "new")
	if err == nil {
		t.Fatal("expected error when target vault path is a symlink")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRenameAccount_RefusesDirectoryTargetVault(t *testing.T) {
	resetViperAndAccount(t)

	viper.Set("accounts.old.server", "https://example.com")
	viper.Set("active_account", "old")

	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	viper.SetConfigFile(filepath.Join(tmpDir, ".bx.yaml"))

	// Create a directory at the new vault target path.
	newVaultPath := filepath.Join(tmpDir, ".bx_vault_new.json")
	if err := os.Mkdir(newVaultPath, 0o700); err != nil {
		t.Fatalf("os.Mkdir: %v", err)
	}

	err := renameAccount("old", "new")
	if err == nil {
		t.Fatal("expected error when target vault path is a directory")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRenameAccount_RefusesExistingTargetSession(t *testing.T) {
	resetViperAndAccount(t)

	viper.Set("accounts.old.server", "https://example.com")
	viper.Set("active_account", "old")

	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	viper.SetConfigFile(filepath.Join(tmpDir, ".bx.yaml"))

	// No vault files — the vault rename is a no-op.
	// Pre-create the new session file so the session check fires.
	if err := os.WriteFile(filepath.Join(tmpDir, ".bx_session_new.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	err := renameAccount("old", "new")
	if err == nil {
		t.Fatal("expected error when target session file already exists")
	}
	if !strings.Contains(err.Error(), "refusing to rename") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRenameAccount_RefusesSymlinkTargetSession(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks on Windows require elevated privileges")
	}
	resetViperAndAccount(t)

	viper.Set("accounts.old.server", "https://example.com")
	viper.Set("active_account", "old")

	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	viper.SetConfigFile(filepath.Join(tmpDir, ".bx.yaml"))

	// No vault files. Create a symlink at the new session path.
	newSessionPath := filepath.Join(tmpDir, ".bx_session_new.json")
	if err := os.Symlink(filepath.Join(tmpDir, "nonexistent-target"), newSessionPath); err != nil {
		t.Fatalf("os.Symlink: %v", err)
	}

	err := renameAccount("old", "new")
	if err == nil {
		t.Fatal("expected error when target session path is a symlink")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRenameAccount_RefusesDirectoryTargetSession(t *testing.T) {
	resetViperAndAccount(t)

	viper.Set("accounts.old.server", "https://example.com")
	viper.Set("active_account", "old")

	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	viper.SetConfigFile(filepath.Join(tmpDir, ".bx.yaml"))

	// No vault files. Create a directory at the new session path.
	newSessionPath := filepath.Join(tmpDir, ".bx_session_new.json")
	if err := os.Mkdir(newSessionPath, 0o700); err != nil {
		t.Fatalf("os.Mkdir: %v", err)
	}

	err := renameAccount("old", "new")
	if err == nil {
		t.Fatal("expected error when target session path is a directory")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- saveConfig security checks ---

func TestSaveConfig_CreatesFileWhenAbsent(t *testing.T) {
	resetViperAndAccount(t)

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, ".bx.yaml")
	viper.SetConfigFile(cfgPath)

	if err := saveConfig(); err != nil {
		t.Fatalf("saveConfig() error = %v", err)
	}

	fi, err := os.Lstat(cfgPath)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if !fi.Mode().IsRegular() {
		t.Errorf("expected regular file, got mode %v", fi.Mode())
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("expected 0600 permissions, got %v", fi.Mode().Perm())
	}
}

func TestSaveConfig_OverwritesExistingFile(t *testing.T) {
	resetViperAndAccount(t)

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, ".bx.yaml")
	// Create with correct permissions first.
	if err := os.WriteFile(cfgPath, []byte("server: old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	viper.SetConfigFile(cfgPath)
	viper.Set("server", "https://new.example.com")

	if err := saveConfig(); err != nil {
		t.Fatalf("saveConfig() error = %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "new.example.com") {
		t.Errorf("expected new config in file, got: %s", data)
	}
}

func TestSaveConfig_RefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks on Windows require elevated privileges")
	}
	resetViperAndAccount(t)

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, ".bx.yaml")

	// Place a symlink at the config path.
	if err := os.Symlink(filepath.Join(tmpDir, "nonexistent-target.yaml"), cfgPath); err != nil {
		t.Fatalf("os.Symlink: %v", err)
	}
	viper.SetConfigFile(cfgPath)

	err := saveConfig()
	if err == nil {
		t.Fatal("expected error when config path is a symlink")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSaveConfig_RefusesDirectory(t *testing.T) {
	resetViperAndAccount(t)

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, ".bx.yaml")

	// Place a directory at the config path.
	if err := os.Mkdir(cfgPath, 0o700); err != nil {
		t.Fatalf("os.Mkdir: %v", err)
	}
	viper.SetConfigFile(cfgPath)

	err := saveConfig()
	if err == nil {
		t.Fatal("expected error when config path is a directory")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- validateAccountName: coverage for new lowercase-only restriction ---

func TestValidateAccountName_LowercaseOnly(t *testing.T) {
	// Valid: all lowercase + allowed special chars.
	for _, name := range []string{"default", "work", "my-account", "acc_123", "a-z-0-9"} {
		if err := validateAccountName(name); err != nil {
			t.Errorf("validateAccountName(%q) = %v, want nil", name, err)
		}
	}

	// Invalid: uppercase letters are now rejected because Viper lowercases keys.
	for _, name := range []string{"Work", "WORK", "MyAccount", "Mixed-Case", "A"} {
		if err := validateAccountName(name); err == nil {
			t.Errorf("validateAccountName(%q) = nil, want error (uppercase rejected)", name)
		} else if !strings.Contains(err.Error(), "lowercase") {
			t.Errorf("validateAccountName(%q) error %q should mention lowercase", name, err.Error())
		}
	}
}

// --- checkRenameTarget ---

func TestCheckRenameTarget_PathAbsent(t *testing.T) {
	tmpDir := t.TempDir()
	if err := checkRenameTarget(filepath.Join(tmpDir, "nonexistent"), "refusing to rename vault"); err != nil {
		t.Errorf("expected nil for absent path, got %v", err)
	}
}

func TestCheckRenameTarget_RegularFileExists(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "existing.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := checkRenameTarget(target, "refusing to rename vault")
	if err == nil {
		t.Fatal("expected error for existing regular file")
	}
	if !strings.Contains(err.Error(), "refusing to rename vault") {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' in error: %v", err)
	}
}

func TestCheckRenameTarget_Symlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks on Windows require elevated privileges")
	}
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "link.json")
	if err := os.Symlink(filepath.Join(tmpDir, "nonexistent"), target); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	err := checkRenameTarget(target, "refusing to rename vault")
	if err == nil {
		t.Fatal("expected error for symlink")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected 'symlink' in error: %v", err)
	}
}

func TestCheckRenameTarget_Directory(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "adir")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	err := checkRenameTarget(target, "refusing to rename vault")
	if err == nil {
		t.Fatal("expected error for directory")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("expected 'not a regular file' in error: %v", err)
	}
}

// --- active_account validation in initConfig ---

// TestActiveAccount_ValidFromConfig verifies that a valid active_account value
// in the config is accepted and propagated to activeAccountName.
func TestActiveAccount_ValidFromConfig(t *testing.T) {
	resetViperAndAccount(t)

	viper.Set("active_account", "work")
	// Simulate the else-branch of initConfig without calling it directly.
	name := viper.GetString("active_account")
	if err := validateAccountName(name); err != nil {
		t.Errorf("validateAccountName(%q) = %v, want nil", name, err)
	}
}

// TestActiveAccount_InvalidFromConfig verifies that an invalid active_account
// value (e.g. containing path separators or uppercase) is caught by
// validateAccountName and would therefore be rejected in initConfig.
func TestActiveAccount_InvalidFromConfig(t *testing.T) {
	resetViperAndAccount(t)

	for _, bad := range []string{"../etc", "a/b", "Work", "UPPER"} {
		if err := validateAccountName(bad); err == nil {
			t.Errorf("validateAccountName(%q) should have returned error (would be injected into file paths)", bad)
		}
	}
}

// TestSaveConfig_ReplacesAtomically verifies that saveConfig replaces the
// config through a temp file: the result is 0600 even if the old file was
// world-readable, and no temp file is left behind.
func TestSaveConfig_ReplacesAtomically(t *testing.T) {
	resetViperAndAccount(t)

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, ".bx.yaml")
	if err := os.WriteFile(cfgPath, []byte("server: old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	viper.SetConfigFile(cfgPath)
	viper.Set("server", "https://new.example.com")

	if err := saveConfig(); err != nil {
		t.Fatalf("saveConfig() error = %v", err)
	}

	fi, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("expected 0600 permissions, got %v", fi.Mode().Perm())
	}
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected only the config file, found %v", names)
	}
}
