package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/nning/bx/internal/client"
)

// tryAutoLoginFn holds the re-authentication logic used by withAutoLogin.
// It is a package-level variable so it can be injected in tests to verify
// withAutoLogin's retry behaviour without making real network calls.
var tryAutoLoginFn = tryAutoLogin

// tryRefreshTokenFn attempts to obtain a new access token using the stored
// refresh token.  It is a package-level variable so it can be injected in
// tests without making real network calls.
var tryRefreshTokenFn = tryRefreshToken

// tryRefreshToken exchanges the stored refresh token for a new access token.
// On success it updates apiClient.Token and persists the new tokens to config.
// It returns nil on success and a non-nil error if the refresh fails.
func tryRefreshToken() error {
	tokens := loadTokens()
	refreshToken := tokens.Refresh
	if refreshToken == "" {
		return fmt.Errorf("no refresh token stored")
	}

	server := accountSetting("server")
	if server == "" {
		return fmt.Errorf("server URL not configured")
	}

	if err := checkServerURL(server); err != nil {
		return err
	}

	deviceID := accountSetting("device_id")
	if deviceID == "" {
		return fmt.Errorf("no device ID stored")
	}

	c := client.New(server)
	tokenResp, err := c.RefreshToken(refreshToken, deviceID)
	if err != nil {
		return err
	}

	tokens.Session = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		tokens.Refresh = tokenResp.RefreshToken
	}
	storeTokens(tokens)
	if tokenResp.Key != "" {
		setAccountSetting("protected_key", tokenResp.Key)
	}

	if err := saveConfig(); err != nil {
		return err
	}

	if apiClient != nil {
		apiClient.Token = tokenResp.AccessToken
	}
	return nil
}

// tryAutoLogin re-authenticates using the server and email stored in the
// active account's configuration.  It first attempts a refresh-token exchange;
// if that fails it falls back to a full password login.  On success it updates
// apiClient.Token so that subsequent API calls in the same invocation use the
// fresh session.
func tryAutoLogin() error {
	if err := tryRefreshTokenFn(); err == nil {
		return nil
	}

	server := accountSetting("server")
	email := accountSetting("email")
	if server == "" {
		return fmt.Errorf("server URL not configured, cannot auto-login. Run 'bx setup' or 'bx account add <name>'")
	}
	if email == "" {
		return fmt.Errorf("email not configured, cannot auto-login. Run 'bx login <email>'")
	}

	fmt.Fprintln(os.Stderr, "Session expired, re-authenticating with password...")
	if err := performLogin(server, email); err != nil {
		return err
	}

	if apiClient != nil {
		apiClient.Token = loadTokens().Session
	}
	return nil
}

// withAutoLogin calls fn. If fn returns ErrUnauthorized it automatically
// re-authenticates via tryAutoLoginFn and retries fn once.  Any other error is
// returned as-is without retrying.
func withAutoLogin(fn func() error) error {
	err := fn()
	if !errors.Is(err, client.ErrUnauthorized) {
		return err
	}
	if loginErr := tryAutoLoginFn(); loginErr != nil {
		return loginErr
	}
	return fn()
}
