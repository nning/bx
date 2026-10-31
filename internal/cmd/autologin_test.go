package cmd

import (
	"errors"
	"fmt"
	"testing"

	"github.com/nning/bx/internal/client"
	"github.com/spf13/viper"
)

// ---- withAutoLogin -------------------------------------------------------

// TestWithAutoLogin_NoError verifies that a nil-returning fn is returned
// immediately without calling tryAutoLoginFn.
func TestWithAutoLogin_NoError(t *testing.T) {
	calls := 0
	loginCalled := false
	orig := tryAutoLoginFn
	defer func() { tryAutoLoginFn = orig }()
	tryAutoLoginFn = func() error { loginCalled = true; return nil }

	err := withAutoLogin(func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if calls != 1 {
		t.Errorf("fn called %d times, want 1", calls)
	}
	if loginCalled {
		t.Error("tryAutoLoginFn should not be called when fn succeeds")
	}
}

// TestWithAutoLogin_NonAuthError verifies that a non-401 error is returned
// immediately without calling tryAutoLoginFn or retrying fn.
func TestWithAutoLogin_NonAuthError(t *testing.T) {
	calls := 0
	loginCalled := false
	orig := tryAutoLoginFn
	defer func() { tryAutoLoginFn = orig }()
	tryAutoLoginFn = func() error { loginCalled = true; return nil }

	want := fmt.Errorf("some unrelated error")
	err := withAutoLogin(func() error {
		calls++
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("expected the original error, got %v", err)
	}
	if calls != 1 {
		t.Errorf("fn called %d times, want 1", calls)
	}
	if loginCalled {
		t.Error("tryAutoLoginFn should not be called for non-401 errors")
	}
}

// TestWithAutoLogin_UnauthorizedRetrySuccess verifies that when fn returns
// ErrUnauthorized, tryAutoLoginFn is called once and fn is retried exactly
// once more.
func TestWithAutoLogin_UnauthorizedRetrySuccess(t *testing.T) {
	calls := 0
	loginCalls := 0
	orig := tryAutoLoginFn
	defer func() { tryAutoLoginFn = orig }()
	tryAutoLoginFn = func() error { loginCalls++; return nil }

	err := withAutoLogin(func() error {
		calls++
		if calls == 1 {
			return client.ErrUnauthorized
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil on retry, got %v", err)
	}
	if calls != 2 {
		t.Errorf("fn called %d times, want 2", calls)
	}
	if loginCalls != 1 {
		t.Errorf("tryAutoLoginFn called %d times, want 1", loginCalls)
	}
}

// TestWithAutoLogin_UnauthorizedRetryAlsoUnauthorized verifies that when fn
// returns ErrUnauthorized on the second attempt the error is surfaced.
func TestWithAutoLogin_UnauthorizedRetryAlsoUnauthorized(t *testing.T) {
	calls := 0
	orig := tryAutoLoginFn
	defer func() { tryAutoLoginFn = orig }()
	tryAutoLoginFn = func() error { return nil }

	err := withAutoLogin(func() error {
		calls++
		return client.ErrUnauthorized
	})
	if !errors.Is(err, client.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized on second attempt, got %v", err)
	}
	if calls != 2 {
		t.Errorf("fn called %d times, want 2", calls)
	}
}

// TestWithAutoLogin_LoginFails verifies that when tryAutoLoginFn fails the
// login error is returned and fn is not retried.
func TestWithAutoLogin_LoginFails(t *testing.T) {
	calls := 0
	loginErr := fmt.Errorf("login failed: invalid credentials")
	orig := tryAutoLoginFn
	defer func() { tryAutoLoginFn = orig }()
	tryAutoLoginFn = func() error { return loginErr }

	err := withAutoLogin(func() error {
		calls++
		return client.ErrUnauthorized
	})
	if !errors.Is(err, loginErr) {
		t.Fatalf("expected login error, got %v", err)
	}
	if calls != 1 {
		t.Errorf("fn called %d times, want 1 (no retry when login fails)", calls)
	}
}

// ---- tryAutoLogin --------------------------------------------------------

// TestTryAutoLogin_NoServer verifies that tryAutoLogin returns an error when
// the server URL is not configured.
func TestTryAutoLogin_NoServer(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	origRefresh := tryRefreshTokenFn
	defer func() { tryRefreshTokenFn = origRefresh }()
	tryRefreshTokenFn = func() error { return fmt.Errorf("no refresh token") }

	err := tryAutoLogin()
	if err == nil {
		t.Fatal("expected error when server URL is not configured")
	}
}

// TestTryAutoLogin_NoEmail verifies that tryAutoLogin returns an error when
// the email is not configured.
func TestTryAutoLogin_NoEmail(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.Set("server", "https://vault.example.com")

	origRefresh := tryRefreshTokenFn
	defer func() { tryRefreshTokenFn = origRefresh }()
	tryRefreshTokenFn = func() error { return fmt.Errorf("no refresh token") }

	err := tryAutoLogin()
	if err == nil {
		t.Fatal("expected error when email is not configured")
	}
}

// ---- tryRefreshToken -----------------------------------------------------

// TestTryRefreshToken_NoToken verifies that tryRefreshToken returns an error
// when no refresh token is stored.
func TestTryRefreshToken_NoToken(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	err := tryRefreshToken()
	if err == nil {
		t.Fatal("expected error when no refresh token is stored")
	}
}

// TestTryRefreshToken_NoServer verifies that tryRefreshToken returns an error
// when the server URL is not configured.
func TestTryRefreshToken_NoServer(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.Set("refresh_token", "some-token")

	err := tryRefreshToken()
	if err == nil {
		t.Fatal("expected error when server URL is not configured")
	}
}

// TestTryRefreshToken_NoDeviceID verifies that tryRefreshToken returns an
// error when no device ID is stored.
func TestTryRefreshToken_NoDeviceID(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.Set("refresh_token", "some-token")
	viper.Set("server", "https://vault.example.com")

	err := tryRefreshToken()
	if err == nil {
		t.Fatal("expected error when no device ID is stored")
	}
}

// ---- tryAutoLogin with refresh success -----------------------------------

// TestTryAutoLogin_RefreshSucceeds verifies that tryAutoLogin returns nil
// when the refresh token exchange succeeds, without falling back to password
// login.
func TestTryAutoLogin_RefreshSucceeds(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	origRefresh := tryRefreshTokenFn
	defer func() { tryRefreshTokenFn = origRefresh }()
	tryRefreshTokenFn = func() error { return nil }

	err := tryAutoLogin()
	if err != nil {
		t.Fatalf("expected nil when refresh succeeds, got %v", err)
	}
}
