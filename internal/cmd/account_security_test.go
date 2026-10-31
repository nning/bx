package cmd

import (
	"testing"

	"github.com/spf13/viper"
)

func TestNamedAccountNeverInheritsIdentityOrTokens(t *testing.T) {
	resetViperAndAccount(t)
	t.Cleanup(func() { resetViperAndAccount(t) })
	for _, key := range []string{"server", "email", "device_id", "session_token", "refresh_token", "protected_key"} {
		viper.Set(key, "legacy-account-value")
	}
	viper.Set("accounts.other.server", "https://other.example.com")
	activeAccountName = "other"
	for _, key := range []string{"email", "device_id", "session_token", "refresh_token", "protected_key"} {
		if got := accountSetting(key); got != "" {
			t.Errorf("named account inherited %s", key)
		}
	}
	if tokens := loadTokens(); tokens.Session != "" || tokens.Refresh != "" {
		t.Fatal("named account inherited legacy tokens")
	}
	if err := validateConfiguredAccount("other"); err != nil {
		t.Fatal(err)
	}
	if err := validateConfiguredAccount("missing"); err == nil {
		t.Fatal("unknown account was accepted")
	}
	if err := performLogin("http://192.0.2.1", "alice@example.com"); err == nil {
		t.Fatal("insecure login reached the password prompt")
	}
}
