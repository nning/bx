package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nning/bx/internal/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// validAccountName matches names consisting only of lowercase letters, digits,
// underscores, and hyphens.  Uppercase is excluded because Viper normalises all
// config keys to lowercase, which would make an account added as "Work" appear
// as "work" on the next invocation, causing vault-path mismatches.  This
// restriction prevents that class of confusion and also prevents path-traversal
// attacks when the name is used in file paths (e.g. ~/.bx_vault_<name>.json).
var validAccountName = regexp.MustCompile(`^[a-z0-9_-]+$`)

// validateAccountName checks that name is a safe, non-empty account name.
func validateAccountName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("account name must not be empty")
	}
	if !validAccountName.MatchString(name) {
		return fmt.Errorf("account name %q is invalid: only lowercase letters, digits, underscores, and hyphens are allowed", name)
	}
	return nil
}

// checkRenameTarget returns an error if path already exists and must not be
// clobbered.  It uses os.Lstat (does not follow symlinks) so that symlinks are
// detected and rejected rather than silently followed.  prefix is prepended to
// the returned "refusing to …" error message so callers can give context (e.g.
// "refusing to rename vault" or "refusing to rename session").
func checkRenameTarget(path, prefix string) error {
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to lstat target file %q: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: target file %q is a symlink", prefix, path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: target path %q is not a regular file (mode: %v)", prefix, path, fi.Mode())
	}
	return fmt.Errorf("%s: target file %q already exists", prefix, path)
}

var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Manage accounts",
	Long:  `Manage multiple Bitwarden/Vaultwarden accounts across different servers.`,
}

var accountListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configured accounts",
	Run: func(_ *cobra.Command, _ []string) {
		accounts := viper.GetStringMap("accounts")
		active := viper.GetString("active_account")

		if len(accounts) == 0 {
			fmt.Println("No accounts configured.")
			fmt.Println("Run 'bx account add <name>' to add your first account.")
			return
		}

		fmt.Println("Configured accounts:")
		for name := range accounts {
			marker := "  "
			if name == active {
				marker = "* "
			}
			server := viper.GetString("accounts." + name + ".server")
			email := viper.GetString("accounts." + name + ".email")
			fmt.Printf("%s%-20s  %s  %s\n", marker, name, server, email)
		}
	},
}

var accountSwitchCmd = &cobra.Command{
	Use:   "switch <name>",
	Short: "Switch the active account",
	Args:  cobra.ExactArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		name := args[0]
		cobra.CheckErr(validateAccountName(name))

		accounts := viper.GetStringMap("accounts")
		if _, ok := accounts[name]; !ok {
			cobra.CheckErr(fmt.Errorf("account %q not found. Run 'bx account list' to see available accounts", name))
		}

		viper.Set("active_account", name)
		if err := saveConfig(); err != nil {
			cobra.CheckErr(err)
		}
		fmt.Printf("Switched to account %q.\n", name)
	},
}

var accountAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add and log in to a new account",
	Long:  `Add a new named account by providing the server URL, email, and master password. The new account becomes the active account after a successful login.`,
	Args:  cobra.ExactArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		name := args[0]
		cobra.CheckErr(validateAccountName(name))

		// Prompt for server URL if not already configured for this account.
		server := viper.GetString("accounts." + name + ".server")
		if server == "" {
			var err error
			server, err = promptLine("Server URL: ")
			cobra.CheckErr(err)
		}
		if server == "" {
			cobra.CheckErr(fmt.Errorf("server URL is required"))
		}
		cobra.CheckErr(checkServerURL(server))

		// Prompt for email if not already configured for this account.
		email := viper.GetString("accounts." + name + ".email")
		if email == "" {
			var err error
			email, err = promptLine("Email: ")
			cobra.CheckErr(err)
		}
		if email == "" {
			cobra.CheckErr(fmt.Errorf("email is required"))
		}

		// Temporarily set activeAccountName so that performLogin and
		// setAccountSetting route all writes to this account's config section.
		prevAccount := activeAccountName
		activeAccountName = name
		vault.ActiveAccount = name
		defer func() {
			activeAccountName = prevAccount
			vault.ActiveAccount = prevAccount
		}()

		// Pre-populate server so performLogin can find it via accountSetting.
		viper.Set("accounts."+name+".server", server)

		if err := performLogin(server, email); err != nil {
			cobra.CheckErr(err)
		}

		// Make the new account the active one.
		viper.Set("active_account", name)
		if err := saveConfig(); err != nil {
			cobra.CheckErr(err)
		}

		fmt.Printf("Account %q added and set as active.\n", name)
		fmt.Printf("Run 'bx fetch' to download the vault for this account.\n")
	},
}

var accountRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a configured account",
	Long:  `Remove a named account and its associated vault and session files.`,
	Args:  cobra.ExactArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		name := args[0]
		cobra.CheckErr(validateAccountName(name))

		accounts := viper.GetStringMap("accounts")
		if _, ok := accounts[name]; !ok {
			cobra.CheckErr(fmt.Errorf("account %q not found. Run 'bx account list' to see available accounts", name))
		}

		// Clear the session for this account.
		prev := vault.ActiveAccount
		vault.ActiveAccount = name
		_ = vault.ClearSession()
		vault.ActiveAccount = prev
		if err := deleteTokens(name); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not remove tokens of %q from the OS keyring: %v\n", name, err)
		}

		// Remove per-account vault file.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)
		vaultFile := filepath.Join(home, ".bx_vault_"+name+".json")
		if rmErr := os.Remove(vaultFile); rmErr != nil && !os.IsNotExist(rmErr) {
			fmt.Fprintf(os.Stderr, "warning: could not remove vault file %s: %v\n", vaultFile, rmErr)
		}

		// Remove the account from config.
		delete(accounts, name)
		viper.Set("accounts", accounts)

		// If this was the active account, clear it.
		if viper.GetString("active_account") == name {
			viper.Set("active_account", "")
		}

		if err := saveConfig(); err != nil {
			cobra.CheckErr(err)
		}

		fmt.Printf("Account %q removed.\n", name)
	},
}

var accountRenameCmd = &cobra.Command{
	Use:   "rename <old-name> <new-name>",
	Short: "Rename a configured account",
	Long:  `Rename a configured account and update its associated vault and session files.`,
	Args:  cobra.ExactArgs(2),
	Run: func(_ *cobra.Command, args []string) {
		oldName := args[0]
		newName := args[1]

		cobra.CheckErr(validateAccountName(oldName))
		cobra.CheckErr(validateAccountName(newName))

		accounts := viper.GetStringMap("accounts")
		if _, ok := accounts[oldName]; !ok {
			cobra.CheckErr(fmt.Errorf("account %q not found. Run 'bx account list' to see available accounts", oldName))
		}
		if _, ok := accounts[newName]; ok {
			cobra.CheckErr(fmt.Errorf("account %q already exists", newName))
		}

		if err := renameAccount(oldName, newName); err != nil {
			cobra.CheckErr(err)
		}

		fmt.Printf("Account %q renamed to %q.\n", oldName, newName)
	},
}

// renameAccount moves an account's config, vault file, and session file from
// oldName to newName.  It also updates active_account if necessary.
func renameAccount(oldName, newName string) error {
	// Copy all settings from old account to new account.
	accounts := viper.GetStringMap("accounts")
	oldSettings := viper.GetStringMap("accounts." + oldName)
	for k, v := range oldSettings {
		viper.Set("accounts."+newName+"."+k, v)
	}

	// Remove old account entry.
	delete(accounts, oldName)
	// Re-read because viper.Set on sub-keys may have re-created the map.
	accounts = viper.GetStringMap("accounts")
	delete(accounts, oldName)
	viper.Set("accounts", accounts)

	// Update active_account if it pointed to the old name.
	if viper.GetString("active_account") == oldName {
		viper.Set("active_account", newName)
	}

	// Rename per-account vault file.
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	oldVault := filepath.Join(home, ".bx_vault_"+oldName+".json")
	newVault := filepath.Join(home, ".bx_vault_"+newName+".json")

	if err := checkRenameTarget(newVault, "refusing to rename vault"); err != nil {
		return err
	}
	if err := os.Rename(oldVault, newVault); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to rename vault file: %w", err)
	}

	// Rename per-account session file.
	oldSession := filepath.Join(home, ".bx_session_"+oldName+".json")
	newSession := filepath.Join(home, ".bx_session_"+newName+".json")

	if err := checkRenameTarget(newSession, "refusing to rename session"); err != nil {
		return err
	}
	if err := os.Rename(oldSession, newSession); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to rename session file: %w", err)
	}

	if err := moveTokens(oldName, newName); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not move tokens of %q in the OS keyring: %v\n", oldName, err)
	}

	// Clear keyring-backed session state for both old and new account names
	// to avoid leaving orphaned entries after the rename.  This invalidates the
	// session, requiring the user to log in again.
	prevActive := vault.ActiveAccount
	vault.ActiveAccount = oldName
	if err := vault.ClearSession(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to clear session for %q: %v\n", oldName, err)
	}
	vault.ActiveAccount = newName
	if err := vault.ClearSession(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to clear session for %q: %v\n", newName, err)
	}
	vault.ActiveAccount = prevActive

	return saveConfig()
}

func init() {
	rootCmd.AddCommand(accountCmd)
	accountCmd.AddCommand(accountListCmd)
	accountCmd.AddCommand(accountSwitchCmd)
	accountCmd.AddCommand(accountAddCmd)
	accountCmd.AddCommand(accountRemoveCmd)
	accountCmd.AddCommand(accountRenameCmd)
}

// configFilePath returns the path of the config file in use, defaulting to
// ~/.bx.yaml when none has been loaded yet.
func configFilePath() (string, error) {
	if configFile := viper.ConfigFileUsed(); configFile != "" {
		return configFile, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".bx.yaml"), nil
}

// saveConfig writes the current viper state to the config file securely.
//
// The config holds session and refresh tokens, so it is written to a fresh
// 0600 temp file in the same directory and renamed over the old one.  An
// interrupted write therefore never leaves a truncated config behind, and
// because rename replaces the path itself rather than following it, a
// symlink planted after the checks below cannot redirect the write.
func saveConfig() error {
	configFile, err := configFilePath()
	if err != nil {
		return err
	}

	fi, err := os.Lstat(configFile)
	switch {
	case err == nil:
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("config file %s is a symlink, refusing to write for security", configFile)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("config file %s is not a regular file", configFile)
		}
	case !os.IsNotExist(err):
		return err
	}

	// viper picks the format from the file extension.
	ext := filepath.Ext(configFile)
	if ext == "" {
		ext = ".yaml"
	}
	tmp, err := os.CreateTemp(filepath.Dir(configFile), ".bx_config_*"+ext)
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := viper.WriteConfigAs(tmpPath); err != nil {
		return err
	}
	return replaceFile(tmpPath, configFile)
}
