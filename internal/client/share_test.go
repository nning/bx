package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// shareMux serves the endpoints used by ShareCipher and
// UpdateCipherCollections.  It records the request method, path, and body of the
// last write so tests can assert what was sent, and answers the follow-up GET
// with an organization-owned cipher.
func shareMux(t *testing.T) (*http.ServeMux, func() (string, string, map[string]any)) {
	t.Helper()

	var lastMethod, lastPath string
	var lastBody map[string]any

	mux := http.NewServeMux()

	record := func(w http.ResponseWriter, r *http.Request, body any) {
		lastMethod, lastPath = r.Method, r.URL.Path
		lastBody = nil
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&lastBody)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}

	orgID := "org-1"
	shared := Cipher{
		ID:             "cipher-id",
		Type:           1,
		OrganizationID: &orgID,
		RevisionDate:   "2000-07-31T20:05:00Z",
	}

	mux.HandleFunc("/api/ciphers/cipher-id", func(w http.ResponseWriter, r *http.Request) {
		// The GET after a write must not overwrite the recorded request.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(shared)
	})
	// Vaultwarden answers with an empty body on both endpoints below.
	mux.HandleFunc("/api/ciphers/cipher-id/share", func(w http.ResponseWriter, r *http.Request) {
		record(w, r, nil)
	})
	mux.HandleFunc("/api/ciphers/cipher-id/collections", func(w http.ResponseWriter, r *http.Request) {
		record(w, r, nil)
	})

	return mux, func() (string, string, map[string]any) { return lastMethod, lastPath, lastBody }
}

func TestShareCipher_Success(t *testing.T) {
	mux, lastRequest := shareMux(t)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	raw, err := c.ShareCipher("cipher-id", ShareCipherRequest{
		Cipher:        json.RawMessage(`{"id":"cipher-id","organizationId":"org-1","name":"2.a|b|c"}`),
		CollectionIDs: []string{"col-1", "col-2"},
	})
	if err != nil {
		t.Fatalf("ShareCipher: %v", err)
	}

	method, path, body := lastRequest()
	if method != "PUT" {
		t.Errorf("method: got %q, want PUT", method)
	}
	if path != "/api/ciphers/cipher-id/share" {
		t.Errorf("path: got %q", path)
	}
	ids, ok := body["collectionIds"].([]any)
	if !ok || len(ids) != 2 || ids[0] != "col-1" || ids[1] != "col-2" {
		t.Errorf("collectionIds: got %v", body["collectionIds"])
	}
	sentCipher, ok := body["cipher"].(map[string]any)
	if !ok || sentCipher["organizationId"] != "org-1" {
		t.Errorf("cipher: got %v", body["cipher"])
	}

	// The updated cipher is fetched afterwards — as raw JSON, since the write
	// response body differs between server implementations.
	var fetched map[string]any
	if err := json.Unmarshal(raw, &fetched); err != nil {
		t.Fatalf("Unmarshal returned cipher: %v", err)
	}
	if fetched["organizationId"] != "org-1" {
		t.Errorf("expected the organization-owned cipher, got %v", fetched)
	}
}

func TestShareCipher_NotAuthenticated(t *testing.T) {
	c := New("https://vault.example.com")
	_, err := c.ShareCipher("cipher-id", ShareCipherRequest{})
	if err == nil || !strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("expected an auth error, got %v", err)
	}
}

func TestShareCipher_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Invalid collection ID provided", http.StatusBadRequest)
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	if _, err := c.ShareCipher("cipher-id", ShareCipherRequest{}); err == nil {
		t.Fatal("expected an error for HTTP 400")
	} else if !strings.Contains(err.Error(), "Invalid collection ID") {
		t.Errorf("expected the server message to be surfaced, got %v", err)
	}
}

func TestUpdateCipherCollections_Success(t *testing.T) {
	mux, lastRequest := shareMux(t)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	raw, err := c.UpdateCipherCollections("cipher-id", CipherCollectionsRequest{
		CollectionIDs: []string{"col-3"},
	})
	if err != nil {
		t.Fatalf("UpdateCipherCollections: %v", err)
	}

	method, path, body := lastRequest()
	if method != "PUT" {
		t.Errorf("method: got %q, want PUT", method)
	}
	if path != "/api/ciphers/cipher-id/collections" {
		t.Errorf("path: got %q", path)
	}
	ids, ok := body["collectionIds"].([]any)
	if !ok || len(ids) != 1 || ids[0] != "col-3" {
		t.Errorf("collectionIds: got %v", body["collectionIds"])
	}
	var fetched map[string]any
	if err := json.Unmarshal(raw, &fetched); err != nil {
		t.Fatalf("Unmarshal returned cipher: %v", err)
	}
	if fetched["id"] != "cipher-id" {
		t.Errorf("expected the updated cipher, got %v", fetched)
	}
}

func TestUpdateCipherCollections_NotAuthenticated(t *testing.T) {
	c := New("https://vault.example.com")
	_, err := c.UpdateCipherCollections("cipher-id", CipherCollectionsRequest{})
	if err == nil || !strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("expected an auth error, got %v", err)
	}
}

func TestGetCipherRaw_PreservesUnknownFields(t *testing.T) {
	const raw = `{"id":"cipher-id","sshKey":{"privateKey":"2.a|b|c"},"futureField":42}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(raw))
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	got, err := c.GetCipherRaw("cipher-id")
	if err != nil {
		t.Fatalf("GetCipherRaw: %v", err)
	}

	var obj map[string]any
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if obj["futureField"] != float64(42) {
		t.Errorf("fields bx does not model must survive: %v", obj)
	}
	if _, ok := obj["sshKey"].(map[string]any); !ok {
		t.Errorf("sshKey: got %v", obj["sshKey"])
	}
}

func TestGetCipherRaw_NotAuthenticated(t *testing.T) {
	c := New("https://vault.example.com")
	if _, err := c.GetCipherRaw("cipher-id"); err == nil || !strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("expected an auth error, got %v", err)
	}
}
