package client

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRequestsRejectInsecureServer(t *testing.T) {
	for _, operation := range []string{"login", "refresh", "sync", "upload"} {
		t.Run(operation, func(t *testing.T) {
			c := New("http://192.0.2.1")
			c.Token = "synthetic-token"
			var err error
			switch operation {
			case "login":
				_, err = c.Login("alice@example.com", "synthetic-password", "device", "", "")
			case "refresh":
				_, err = c.RefreshToken("synthetic-refresh", "device")
			case "sync":
				_, _, err = c.Sync()
			case "upload":
				err = c.UploadAttachmentFile(&AttachmentFileUploadResponse{URL: "/ciphers/a/attachment/b"}, nil)
			}
			if err == nil || !strings.Contains(err.Error(), "https://") {
				t.Fatalf("insecure request was not rejected: %v", err)
			}
		})
	}
}

func TestRedirectDoesNotForwardCredentials(t *testing.T) {
	called := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	c := New(origin.URL)
	if _, err := c.RefreshToken("synthetic-refresh", "device"); err == nil {
		t.Fatal("cross-origin redirect accepted")
	}
	if called {
		t.Fatal("redirect target was contacted")
	}
}

func TestRedirectRejectsDowngrade(t *testing.T) {
	u, _ := url.Parse("https://localhost/path")
	r, _ := http.NewRequest(http.MethodPost, "http://localhost/path", nil)
	if err := checkRedirect(r, []*http.Request{{URL: u}}); err == nil {
		t.Fatal("HTTPS downgrade accepted")
	}
}

func TestUploadRejectsForeignOriginsAndUnknownTypes(t *testing.T) {
	called := false
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer foreign.Close()
	c := New("https://vault.example.com")
	c.Token = "synthetic-token"
	for _, upload := range []*AttachmentFileUploadResponse{
		{URL: foreign.URL, FileUploadType: 0},
		{URL: "https://foreign.example.com", FileUploadType: 0},
		{URL: "https://vault.example.com/upload", FileUploadType: 2},
		{URL: "//foreign.example.com/upload", FileUploadType: 0},
		{URL: foreign.URL, FileUploadType: 1},
		nil,
	} {
		if err := c.UploadAttachmentFile(upload, []byte("ciphertext")); err == nil {
			t.Errorf("unsafe upload accepted: %+v", upload)
		}
	}
	if called {
		t.Fatal("unsafe upload URL was contacted")
	}
}

func TestDirectUploadPreservesServerPath(t *testing.T) {
	c := New("https://vault.example.com/prefix")
	for _, raw := range []string{"/ciphers/a/attachment/b", "/api/ciphers/a/attachment/b"} {
		u, err := c.attachmentURL(raw, true)
		if err != nil || u.String() != "https://vault.example.com/prefix/api/ciphers/a/attachment/b" {
			t.Fatalf("resolved upload %q: %v, %v", raw, u, err)
		}
	}
}

func TestLoginFallsBackToLegacyPreloginRoute(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/accounts/prelogin", defaultPreloginHandler)
	mux.HandleFunc("/identity/connect/token", defaultTokenHandler)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := New(srv.URL)
	response, err := c.Login("alice@example.com", "synthetic-password", "device", "", "")
	if err != nil || response.AccessToken != "access-token" {
		t.Fatalf("legacy prelogin: %v", err)
	}
}
