package cmd

import (
	"encoding/json"

	"github.com/spf13/viper"
	keyring "github.com/zalando/go-keyring"
)

// The session and refresh tokens let anyone who holds them sync the vault
// from the server, so they are kept in the OS keyring when one is available,
// like the session keys (see vault.SaveSession).  On systems without a
// keyring daemon they fall back to the 0600 config file, as before.

const tokensKeyringService = "bx"

// accountTokens are the OAuth tokens of one account.
type accountTokens struct {
	Session string `json:"session_token"`
	Refresh string `json:"refresh_token"`
}

// tokensKeyringUser returns the OS-keyring user key for account's tokens.
func tokensKeyringUser(account string) string {
	if account != "" {
		return "tokens_" + account
	}
	return "tokens"
}

// loadTokens returns the active account's tokens, from the OS keyring if it
// holds them and from the config file otherwise.
func loadTokens() accountTokens {
	if raw, err := keyring.Get(tokensKeyringService, tokensKeyringUser(activeAccountName)); err == nil {
		var t accountTokens
		if json.Unmarshal([]byte(raw), &t) == nil {
			return t
		}
	}
	return accountTokens{
		Session: accountSetting("session_token"),
		Refresh: accountSetting("refresh_token"),
	}
}

// storeTokens records t for the active account.  If the OS keyring accepts
// them, any plaintext copy is removed from the config; otherwise they are
// written to the config.  Either way the caller must still call saveConfig.
func storeTokens(t accountTokens) {
	if b, err := json.Marshal(t); err == nil {
		if err := keyring.Set(tokensKeyringService, tokensKeyringUser(activeAccountName), string(b)); err == nil {
			setAccountSetting("session_token", "")
			setAccountSetting("refresh_token", "")
			return
		}
	}
	setAccountSetting("session_token", t.Session)
	setAccountSetting("refresh_token", t.Refresh)
}

// migrateTokensToKeyring moves tokens that an older bx, or a run without a
// keyring, left in the active account's config section into the OS keyring.
// Such a copy is always the newest one, because storeTokens removes it
// whenever the keyring accepts the tokens, so it overwrites the keyring.
// It is best-effort: without a keyring the config is left as it is.
func migrateTokensToKeyring() {
	prefix := ""
	if activeAccountName != "" {
		prefix = "accounts." + activeAccountName + "."
	}
	plain := accountTokens{
		Session: viper.GetString(prefix + "session_token"),
		Refresh: viper.GetString(prefix + "refresh_token"),
	}
	if plain.Session == "" && plain.Refresh == "" {
		return
	}
	b, err := json.Marshal(plain)
	if err != nil {
		return
	}
	if err := keyring.Set(tokensKeyringService, tokensKeyringUser(activeAccountName), string(b)); err != nil {
		return
	}
	viper.Set(prefix+"session_token", "")
	viper.Set(prefix+"refresh_token", "")
	_ = saveConfig()
}

// deleteTokens removes account's tokens from the OS keyring.
func deleteTokens(account string) error {
	err := keyring.Delete(tokensKeyringService, tokensKeyringUser(account))
	if err == keyring.ErrNotFound {
		return nil
	}
	return err
}

// moveTokens moves the keyring tokens of oldName to newName, so that renaming
// an account keeps it logged in.
func moveTokens(oldName, newName string) error {
	raw, err := keyring.Get(tokensKeyringService, tokensKeyringUser(oldName))
	if err == keyring.ErrNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if err := keyring.Set(tokensKeyringService, tokensKeyringUser(newName), raw); err != nil {
		return err
	}
	return deleteTokens(oldName)
}
