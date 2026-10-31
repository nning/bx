package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nning/bx/internal/crypto"
)

// errCloser is an io.ReadCloser whose Close always returns an error.
type errCloser struct{ io.Reader }

func (e errCloser) Close() error { return fmt.Errorf("close error") }

// ---- New ----------------------------------------------------------------

func TestNew_TrimsTrailingSlash(t *testing.T) {
	c := New("https://vault.example.com/")
	if c.ServerURL != "https://vault.example.com" {
		t.Fatalf("expected trimmed URL, got %q", c.ServerURL)
	}
}

func TestNew_NoTrailingSlash(t *testing.T) {
	c := New("https://vault.example.com")
	if c.ServerURL != "https://vault.example.com" {
		t.Fatalf("expected unchanged URL, got %q", c.ServerURL)
	}
}

func TestNew_TokenEmpty(t *testing.T) {
	c := New("https://vault.example.com")
	if c.Token != "" {
		t.Fatal("expected empty Token on new client")
	}
}

// ---- closeResponseBody --------------------------------------------------

func TestCloseResponseBody_NilBody(t *testing.T) {
	// should not panic
	closeResponseBody(nil, nil)
}

func TestCloseResponseBody_NilErrPtr(t *testing.T) {
	rec := httptest.NewRecorder()
	resp := rec.Result()
	// should not panic and should close the body
	closeResponseBody(resp.Body, nil)
}

func TestCloseResponseBody_PropagatesCloseError(t *testing.T) {
	var err error
	closeResponseBody(errCloser{strings.NewReader("")}, &err)
	if err == nil || err.Error() != "close error" {
		t.Fatalf("expected close error to propagate, got %v", err)
	}
}

func TestCloseResponseBody_DoesNotOverwriteExistingError(t *testing.T) {
	existing := fmt.Errorf("original error")
	err := existing
	closeResponseBody(errCloser{strings.NewReader("")}, &err)
	if err != existing {
		t.Fatalf("expected existing error to be preserved, got %v", err)
	}
}

func TestCloseResponseBody_NoCloseError(t *testing.T) {
	rec := httptest.NewRecorder()
	resp := rec.Result()
	var err error
	closeResponseBody(resp.Body, &err)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

// ---- helpers for Login / Sync tests ------------------------------------

// setupLoginServer creates a test HTTP server that handles prelogin and token
// endpoints.  The callers can override the handlers via the mux.
func setupLoginServer(
	t *testing.T,
	preloginHandler http.HandlerFunc,
	tokenHandler http.HandlerFunc,
) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/identity/accounts/prelogin", preloginHandler)
	mux.HandleFunc("/identity/connect/token", tokenHandler)
	return httptest.NewServer(mux)
}

func defaultPreloginHandler(w http.ResponseWriter, _ *http.Request) {
	resp := PreloginResponse{Kdf: 0, KdfIterations: 600000}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func defaultTokenHandler(w http.ResponseWriter, _ *http.Request) {
	resp := TokenResponse{
		AccessToken:  "access-token",
		ExpiresIn:    3600,
		TokenType:    "Bearer",
		RefreshToken: "refresh-token",
		Key:          "vault-key",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ---- Login tests --------------------------------------------------------

func TestLogin_Success(t *testing.T) {
	srv := setupLoginServer(t, defaultPreloginHandler, defaultTokenHandler)
	defer srv.Close()

	c := New(srv.URL)
	resp, err := c.Login("user@example.com", "password", "device-id", "", "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.AccessToken != "access-token" {
		t.Fatalf("expected 'access-token', got %q", resp.AccessToken)
	}
	if c.Token != "access-token" {
		t.Fatal("expected client Token to be set after login")
	}
}

func TestLogin_WithTwoFactorToken(t *testing.T) {
	var gotTwoFactorToken string
	tokenHandler := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil {
			gotTwoFactorToken = r.FormValue("twoFactorToken")
		}
		defaultTokenHandler(w, r)
	}
	srv := setupLoginServer(t, defaultPreloginHandler, tokenHandler)
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Login("user@example.com", "password", "device-id", "123456", "0")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if gotTwoFactorToken != "123456" {
		t.Fatalf("expected twoFactorToken=123456, got %q", gotTwoFactorToken)
	}
}

func TestLogin_PreloginNonOKStatus(t *testing.T) {
	preloginHandler := func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}
	srv := setupLoginServer(t, preloginHandler, defaultTokenHandler)
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Login("user@example.com", "password", "device-id", "", "")
	if err == nil {
		t.Fatal("expected error for non-OK prelogin status")
	}
	if !strings.Contains(err.Error(), "prelogin failed with status 404") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLogin_PreloginInvalidJSON(t *testing.T) {
	preloginHandler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not valid json"))
	}
	srv := setupLoginServer(t, preloginHandler, defaultTokenHandler)
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Login("user@example.com", "password", "device-id", "", "")
	if err == nil {
		t.Fatal("expected error for invalid prelogin JSON")
	}
	if !strings.Contains(err.Error(), "failed to decode prelogin response") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLogin_UnknownKdfType(t *testing.T) {
	preloginHandler := func(w http.ResponseWriter, _ *http.Request) {
		resp := PreloginResponse{Kdf: 99, KdfIterations: 1}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
	srv := setupLoginServer(t, preloginHandler, defaultTokenHandler)
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Login("user@example.com", "password", "device-id", "", "")
	if err == nil {
		t.Fatal("expected error for unknown KDF type")
	}
	if !strings.Contains(err.Error(), "key derivation failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLogin_PBKDF2ZeroIterations(t *testing.T) {
	preloginHandler := func(w http.ResponseWriter, _ *http.Request) {
		resp := PreloginResponse{Kdf: 0, KdfIterations: 0}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
	srv := setupLoginServer(t, preloginHandler, defaultTokenHandler)
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Login("user@example.com", "password", "device-id", "", "")
	if err == nil {
		t.Fatal("expected error for PBKDF2 with zero iterations")
	}
	if !strings.Contains(err.Error(), "key derivation failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLogin_Argon2idZeroParallelism(t *testing.T) {
	preloginHandler := func(w http.ResponseWriter, _ *http.Request) {
		resp := PreloginResponse{Kdf: 1, KdfIterations: 3, KdfMemory: 64, KdfParallelism: 0}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
	srv := setupLoginServer(t, preloginHandler, defaultTokenHandler)
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Login("user@example.com", "password", "device-id", "", "")
	if err == nil {
		t.Fatal("expected error for Argon2id with zero parallelism")
	}
	if !strings.Contains(err.Error(), "key derivation failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLogin_Argon2idSuccess(t *testing.T) {
	email := "user@example.com"
	password := "password"

	// Compute the expected master password hash independently.
	kdfConfig := crypto.KdfConfig{
		Type:        crypto.KdfTypeArgon2id,
		Iterations:  3,
		Memory:      64,
		Parallelism: 4,
	}
	masterKey, err := crypto.DeriveMasterKey(password, email, kdfConfig)
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	wantHash := crypto.HashMasterPassword(masterKey, password)

	preloginHandler := func(w http.ResponseWriter, _ *http.Request) {
		resp := PreloginResponse{Kdf: 1, KdfIterations: 3, KdfMemory: 64, KdfParallelism: 4}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}

	var gotHash string
	tokenHandler := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil {
			gotHash = r.FormValue("password")
		}
		defaultTokenHandler(w, r)
	}

	srv := setupLoginServer(t, preloginHandler, tokenHandler)
	defer srv.Close()

	c := New(srv.URL)
	resp, err := c.Login(email, password, "device-id", "", "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.AccessToken != "access-token" {
		t.Fatalf("expected 'access-token', got %q", resp.AccessToken)
	}
	if gotHash != wantHash {
		t.Fatalf("master password hash mismatch: got %q, want %q", gotHash, wantHash)
	}
}

func TestLogin_TwoFactorRequired(t *testing.T) {
	tokenHandler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		resp := TwoFactorResponse{
			TwoFactorProviders: []string{"0"},
			Error:              "invalid_grant",
			ErrorDescription:   "Two factor required.",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
	srv := setupLoginServer(t, defaultPreloginHandler, tokenHandler)
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Login("user@example.com", "password", "device-id", "", "")
	if err == nil {
		t.Fatal("expected 2FA error")
	}
	tfErr, ok := err.(*ErrTwoFactorRequired)
	if !ok {
		t.Fatalf("expected *ErrTwoFactorRequired, got %T: %v", err, err)
	}
	if tfErr.Response.Error != "invalid_grant" {
		t.Fatalf("unexpected TwoFactorResponse: %+v", tfErr.Response)
	}
}

func TestLogin_InvalidCredentials(t *testing.T) {
	tokenHandler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Username or password is incorrect."}`))
	}
	srv := setupLoginServer(t, defaultPreloginHandler, tokenHandler)
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Login("user@example.com", "wrongpassword", "device-id", "", "")
	if err == nil {
		t.Fatal("expected error for invalid credentials")
	}
	if !strings.Contains(err.Error(), "invalid credentials") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLogin_TokenNonOKStatus(t *testing.T) {
	tokenHandler := func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}
	srv := setupLoginServer(t, defaultPreloginHandler, tokenHandler)
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Login("user@example.com", "password", "device-id", "", "")
	if err == nil {
		t.Fatal("expected error for non-OK token status")
	}
	if !strings.Contains(err.Error(), "login failed with status 500") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLogin_TokenInvalidJSON(t *testing.T) {
	tokenHandler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not valid json"))
	}
	srv := setupLoginServer(t, defaultPreloginHandler, tokenHandler)
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Login("user@example.com", "password", "device-id", "", "")
	if err == nil {
		t.Fatal("expected error for invalid token JSON")
	}
	if !strings.Contains(err.Error(), "failed to decode token response") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLogin_PreloginNetworkError(t *testing.T) {
	c := New("http://127.0.0.1:0") // nothing listening on port 0
	_, err := c.Login("user@example.com", "password", "device-id", "", "")
	if err == nil {
		t.Fatal("expected network error")
	}
	if !strings.Contains(err.Error(), "prelogin request failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLogin_TokenNetworkError(t *testing.T) {
	// Prelogin succeeds, but the token endpoint abruptly closes the connection
	// to simulate a network error.
	preloginCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/identity/accounts/prelogin", func(w http.ResponseWriter, r *http.Request) {
		preloginCalls++
		defaultPreloginHandler(w, r)
	})
	mux.HandleFunc("/identity/connect/token", func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Login("user@example.com", "password", "device-id", "", "")
	if err == nil {
		t.Fatal("expected network error for token request")
	}
	if !strings.Contains(err.Error(), "login request failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if preloginCalls != 1 {
		t.Fatalf("expected prelogin to be called once, got %d", preloginCalls)
	}
}

// ---- RefreshToken tests -------------------------------------------------

func TestRefreshToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identity/connect/token" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.FormValue("grant_type") != "refresh_token" {
			http.Error(w, "wrong grant_type", http.StatusBadRequest)
			return
		}
		if r.FormValue("refresh_token") != "old-refresh-token" {
			http.Error(w, "wrong refresh_token", http.StatusBadRequest)
			return
		}
		resp := TokenResponse{
			AccessToken:  "new-access-token",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
			RefreshToken: "new-refresh-token",
			Key:          "new-vault-key",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := New(srv.URL)
	resp, err := c.RefreshToken("old-refresh-token", "device-id")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.AccessToken != "new-access-token" {
		t.Fatalf("expected 'new-access-token', got %q", resp.AccessToken)
	}
	if resp.RefreshToken != "new-refresh-token" {
		t.Fatalf("expected 'new-refresh-token', got %q", resp.RefreshToken)
	}
	if resp.Key != "new-vault-key" {
		t.Fatalf("expected 'new-vault-key', got %q", resp.Key)
	}
	if c.Token != "new-access-token" {
		t.Fatal("expected client Token to be updated after refresh")
	}
}

func TestRefreshToken_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "invalid refresh token", http.StatusBadRequest)
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.RefreshToken("bad-token", "device-id")
	if err == nil {
		t.Fatal("expected error for non-OK refresh status")
	}
	if !strings.Contains(err.Error(), "token refresh failed with status 400") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRefreshToken_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not valid json"))
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.RefreshToken("some-token", "device-id")
	if err == nil {
		t.Fatal("expected error for invalid refresh JSON")
	}
	if !strings.Contains(err.Error(), "failed to decode token response") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRefreshToken_NetworkError(t *testing.T) {
	c := New("http://127.0.0.1:0")
	_, err := c.RefreshToken("some-token", "device-id")
	if err == nil {
		t.Fatal("expected network error")
	}
	if !strings.Contains(err.Error(), "token refresh request failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---- Sync tests ---------------------------------------------------------

func TestSync_NotAuthenticated(t *testing.T) {
	c := New("https://vault.example.com")
	_, _, err := c.Sync()
	if err == nil {
		t.Fatal("expected error for unauthenticated sync")
	}
	if !strings.Contains(err.Error(), "client not authenticated") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSync_Success(t *testing.T) {
	syncResp := SyncResponse{
		Profile: Profile{
			ID:    "user-id",
			Email: "user@example.com",
			Key:   "encrypted-key",
		},
		Folders: []Folder{{ID: "f1", Name: "Personal"}},
		Ciphers: []Cipher{
			{ID: "c1", Type: 1, Data: CipherData{Name: "My Login"}},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sync" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(syncResp)
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	resp, raw, err := c.Sync()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Profile.Email != "user@example.com" {
		t.Fatalf("expected profile email 'user@example.com', got %q", resp.Profile.Email)
	}
	if len(raw) == 0 {
		t.Fatal("expected non-empty raw bytes")
	}
	if len(resp.Folders) != 1 || resp.Folders[0].Name != "Personal" {
		t.Fatal("unexpected folders in sync response")
	}
}

func TestSync_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "bad-token"

	_, _, err := c.Sync()
	if err == nil || !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for 401 sync status, got %v", err)
	}
}

func TestSync_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	_, _, err := c.Sync()
	if err == nil {
		t.Fatal("expected error for non-OK sync status")
	}
	if !strings.Contains(err.Error(), "sync failed with status 500") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSync_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not valid json"))
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	_, _, err := c.Sync()
	if err == nil {
		t.Fatal("expected error for invalid sync JSON")
	}
	if !strings.Contains(err.Error(), "failed to decode sync response") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSync_NetworkError(t *testing.T) {
	c := New("http://127.0.0.1:0") // nothing listening on port 0
	c.Token = "test-token"

	_, _, err := c.Sync()
	if err == nil {
		t.Fatal("expected network error")
	}
	if !strings.Contains(err.Error(), "sync request failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---- Write method tests --------------------------------------------------

// setupWriteServer creates a test server with handlers for the write endpoints.
func setupWriteServer(t *testing.T, mux *http.ServeMux) *httptest.Server {
	t.Helper()
	return httptest.NewServer(mux)
}

func writeMux(t *testing.T) (*http.ServeMux, func() map[string]any) {
	t.Helper()
	mux := http.NewServeMux()
	var lastBody map[string]any
	softDeleted := false

	respond := func(w http.ResponseWriter, r *http.Request, status int, body any) {
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&lastBody)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}

	sampleCipher := Cipher{
		ID:           "cipher-id",
		Type:         1,
		RevisionDate: "2000-01-01T00:00:00Z",
		Data:         CipherData{Name: "2.abc|def|ghi"},
	}
	sampleFolder := Folder{ID: "folder-id", Name: "2.abc|def|ghi"}

	mux.HandleFunc("/api/ciphers/cipher-id", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			c := sampleCipher
			if softDeleted {
				deletedDate := "2000-03-01T00:00:00Z"
				c.DeletedDate = &deletedDate
			}
			respond(w, r, http.StatusOK, c)
		case "PUT":
			updated := sampleCipher
			updated.RevisionDate = "2000-02-01T00:00:00Z"
			respond(w, r, http.StatusOK, updated)
		case "DELETE":
			respond(w, r, http.StatusOK, nil)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	// Vaultwarden returns HTTP 200 with an empty body for soft delete.
	mux.HandleFunc("/api/ciphers/cipher-id/delete", func(w http.ResponseWriter, r *http.Request) {
		softDeleted = true
		respond(w, r, http.StatusOK, nil)
	})
	mux.HandleFunc("/api/ciphers/cipher-id/restore", func(w http.ResponseWriter, r *http.Request) {
		respond(w, r, http.StatusOK, sampleCipher)
	})
	mux.HandleFunc("/api/ciphers", func(w http.ResponseWriter, r *http.Request) {
		respond(w, r, http.StatusOK, sampleCipher)
	})
	mux.HandleFunc("/api/folders/folder-id", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			respond(w, r, http.StatusOK, sampleFolder)
		case "DELETE":
			respond(w, r, http.StatusOK, nil)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/folders", func(w http.ResponseWriter, r *http.Request) {
		respond(w, r, http.StatusOK, sampleFolder)
	})

	return mux, func() map[string]any { return lastBody }
}

func TestGetCipher_Success(t *testing.T) {
	mux, _ := writeMux(t)
	srv := setupWriteServer(t, mux)
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	cipher, err := c.GetCipher("cipher-id")
	if err != nil {
		t.Fatalf("GetCipher: %v", err)
	}
	if cipher.ID != "cipher-id" {
		t.Errorf("expected cipher-id, got %q", cipher.ID)
	}
}

func TestGetCipher_NotAuthenticated(t *testing.T) {
	c := New("https://vault.example.com")
	_, err := c.GetCipher("cipher-id")
	if err == nil || !strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("expected auth error, got %v", err)
	}
}

func TestGetCipher_NetworkError(t *testing.T) {
	c := New("http://127.0.0.1:0")
	c.Token = "test-token"
	_, err := c.GetCipher("cipher-id")
	if err == nil {
		t.Fatal("expected network error")
	}
}

func TestCreateCipher_Success(t *testing.T) {
	mux, lastBody := writeMux(t)
	srv := setupWriteServer(t, mux)
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	req := CipherRequest{Type: 1, Name: "encrypted-name"}
	cipher, err := c.CreateCipher(req)
	if err != nil {
		t.Fatalf("CreateCipher: %v", err)
	}
	if cipher.ID != "cipher-id" {
		t.Errorf("expected cipher-id, got %q", cipher.ID)
	}
	body := lastBody()
	if body["name"] != "encrypted-name" {
		t.Errorf("request body name: %v", body["name"])
	}
}

func TestUpdateCipherRaw_SendsBodyVerbatim(t *testing.T) {
	mux, lastBody := writeMux(t)
	srv := setupWriteServer(t, mux)
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	// Keys bx does not model must reach the server unchanged, since the server
	// replaces the item with whatever the request contains.
	body := json.RawMessage(`{"type":1,"name":"updated-name","reprompt":1,` +
		`"login":{"fido2Credentials":[{"credentialId":"cred"}]},"passwordHistory":[{"password":"old"}]}`)
	raw, err := c.UpdateCipherRaw("cipher-id", body)
	if err != nil {
		t.Fatalf("UpdateCipherRaw: %v", err)
	}

	var cipher Cipher
	if err := json.Unmarshal(raw, &cipher); err != nil {
		t.Fatalf("response is not a cipher: %v", err)
	}
	if cipher.RevisionDate != "2000-02-01T00:00:00Z" {
		t.Errorf("unexpected revision date: %q", cipher.RevisionDate)
	}

	sent := lastBody()
	if sent["reprompt"] != float64(1) || sent["passwordHistory"] == nil {
		t.Errorf("request body lost unmodeled keys: %v", sent)
	}
	login, _ := sent["login"].(map[string]any)
	if login == nil || login["fido2Credentials"] == nil {
		t.Errorf("request body lost passkeys: %v", sent["login"])
	}
}

func TestCipherField_UnmarshalKeepsTypeAndLinkedID(t *testing.T) {
	raw := `{"fields":[{"type":1,"name":"2.n|c|m","value":"2.v|c|m","linkedId":null},` +
		`{"type":3,"name":"2.n|c|m","value":null,"linkedId":101}]}`
	var c Cipher
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(c.Fields) != 2 {
		t.Fatalf("got %d fields, want 2", len(c.Fields))
	}
	if c.Fields[0].Type != FieldTypeHidden || c.Fields[0].LinkedID != nil {
		t.Errorf("hidden field: %+v", c.Fields[0])
	}
	if c.Fields[1].Type != FieldTypeLinked || c.Fields[1].LinkedID == nil || *c.Fields[1].LinkedID != 101 {
		t.Errorf("linked field: %+v", c.Fields[1])
	}
}

func TestSoftDeleteCipher_Success(t *testing.T) {
	mux, _ := writeMux(t)
	srv := setupWriteServer(t, mux)
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	cipher, err := c.SoftDeleteCipher("cipher-id")
	if err != nil {
		t.Fatalf("SoftDeleteCipher: %v", err)
	}
	if cipher.DeletedDate == nil {
		t.Error("expected DeletedDate to be set after soft delete")
	}
}

func TestHardDeleteCipher_Success(t *testing.T) {
	mux, _ := writeMux(t)
	srv := setupWriteServer(t, mux)
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	if err := c.HardDeleteCipher("cipher-id"); err != nil {
		t.Fatalf("HardDeleteCipher: %v", err)
	}
}

func TestRestoreCipher_Success(t *testing.T) {
	mux, _ := writeMux(t)
	srv := setupWriteServer(t, mux)
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	cipher, err := c.RestoreCipher("cipher-id")
	if err != nil {
		t.Fatalf("RestoreCipher: %v", err)
	}
	if cipher.DeletedDate != nil {
		t.Error("expected DeletedDate to be nil after restore")
	}
}

func TestCreateFolder_Success(t *testing.T) {
	mux, lastBody := writeMux(t)
	srv := setupWriteServer(t, mux)
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	req := FolderRequest{Name: "encrypted-folder-name"}
	folder, err := c.CreateFolder(req)
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	if folder.ID != "folder-id" {
		t.Errorf("expected folder-id, got %q", folder.ID)
	}
	body := lastBody()
	if body["name"] != "encrypted-folder-name" {
		t.Errorf("request body name: %v", body["name"])
	}
}

func TestUpdateFolder_Success(t *testing.T) {
	mux, _ := writeMux(t)
	srv := setupWriteServer(t, mux)
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	req := FolderRequest{Name: "new-name"}
	folder, err := c.UpdateFolder("folder-id", req)
	if err != nil {
		t.Fatalf("UpdateFolder: %v", err)
	}
	if folder.ID != "folder-id" {
		t.Errorf("expected folder-id, got %q", folder.ID)
	}
}

func TestDeleteFolder_Success(t *testing.T) {
	mux, _ := writeMux(t)
	srv := setupWriteServer(t, mux)
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	if err := c.DeleteFolder("folder-id"); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
}

func TestDoJSONRequest_Conflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	err := c.doJSONRequest("GET", srv.URL+"/api/ciphers/x", nil, http.StatusOK, nil)
	if err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func TestDoJSONRequest_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	err := c.doJSONRequest("GET", srv.URL+"/api/ciphers/x", nil, http.StatusOK, nil)
	if err == nil || !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

// TestSync_ResponseBodyTruncated verifies that the client enforces
// maxResponseBytes.  The server streams a JSON object that is syntactically
// valid when read in full but becomes invalid when truncated at maxResponseBytes.
// If io.LimitReader were removed, json.Unmarshal would succeed and Sync() would
// return no error, causing the test to fail.
func TestSync_ResponseBodyTruncated(t *testing.T) {
	// JSON prefix: a complete, valid SyncResponse that ends with an open string
	// field ("pad").  If fully read the closing `"}` completes it; if truncated
	// by LimitReader the string is never closed → parse error.
	const prefix = `{"profile":{"id":"uid","email":"e@e","key":"k"},"folders":[],"ciphers":[],"pad":"`
	chunk := bytes.Repeat([]byte{'A'}, 4096)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, prefix)
		// Stream 'A' bytes until total exceeds maxResponseBytes (no large allocation).
		written := len(prefix)
		for written <= maxResponseBytes {
			n, err := w.Write(chunk)
			written += n
			if err != nil {
				return
			}
		}
		// Closing characters; only reachable without LimitReader.
		_, _ = io.WriteString(w, `"}`)
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	_, _, err := c.Sync()
	// With LimitReader: JSON is truncated → decode error.
	// Without LimitReader: JSON is complete → no error → this assertion fails,
	// catching any future removal of the cap.
	if err == nil {
		t.Fatal("expected JSON decode error: LimitReader should truncate the response before the closing delimiter")
	}
	if !strings.Contains(err.Error(), "failed to decode sync response") {
		t.Fatalf("unexpected error (expected JSON decode): %v", err)
	}
}

// TestLogin_OversizedErrorBody verifies that the client enforces maxResponseBytes
// when reading a token-endpoint error body.  The server writes maxResponseBytes
// of filler followed by a valid `{"error":"invalid_grant"}` payload.  If
// io.LimitReader is working correctly the client never reaches the
// "invalid_grant" string and returns a generic HTTP 400 error.  If LimitReader
// were removed, "invalid_grant" would be found and Login() would return
// "invalid credentials" instead, causing the assertion below to fail.
func TestLogin_OversizedErrorBody(t *testing.T) {
	chunk := bytes.Repeat([]byte{'x'}, 4096)

	tokenHandler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		// Stream filler bytes in chunks (no large allocation).
		written := 0
		for written < maxResponseBytes {
			n, err := w.Write(chunk)
			written += n
			if err != nil {
				return
			}
		}
		// "invalid_grant" appears only past the cap; a capped client must not see it.
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
	}
	srv := setupLoginServer(t, defaultPreloginHandler, tokenHandler)
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Login("user@example.com", "password", "device-id", "", "")
	if err == nil {
		t.Fatal("expected error for non-OK token status")
	}
	// The "invalid_grant" payload was beyond the cap, so it must NOT have been
	// read; if it were, Login() would return "invalid credentials" instead.
	if strings.Contains(err.Error(), "invalid credentials") {
		t.Fatal("body cap not enforced: LimitReader should have prevented reading the invalid_grant payload")
	}
	if !strings.Contains(err.Error(), "login failed with status 400") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestClient_ReusesConnections verifies that consecutive API calls (such as
// the conflict check and the update in bx edit) share one TCP connection
// instead of setting up a new connection, and TLS session, for each.
func TestClient_ReusesConnections(t *testing.T) {
	var newConns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "c1", "type": 1, "name": "2.x|y|z"})
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "token"
	for i := 0; i < 3; i++ {
		if _, err := c.GetCipher("c1"); err != nil {
			t.Fatalf("GetCipher #%d: %v", i, err)
		}
	}
	if got := newConns.Load(); got != 1 {
		t.Errorf("opened %d connections for 3 requests, want 1", got)
	}
}
