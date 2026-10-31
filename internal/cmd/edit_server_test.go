package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/vault"
)

// testUserID is the ID of the user the edit tests act as.
const testUserID = "user-id"

// fakeCipherServer imitates how Vaultwarden and Bitwarden store an item on
// PUT /api/ciphers/{id}: the item is *replaced* by the request, so any key the
// request leaves out is gone afterwards.  It also enforces
// lastKnownRevisionDate like the real servers do, and, like Vaultwarden 1.37.4
// and later, rejects a write that does not say which user encrypted it.
type fakeCipherServer struct {
	t     *testing.T
	mu    sync.Mutex
	state map[string]json.RawMessage
	rev   int
}

func (s *fakeCipherServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if r.URL.Path != "/api/ciphers/cipher-id" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
	case http.MethodPut:
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if string(body["encryptedFor"]) != `"`+testUserID+`"` {
			http.Error(w, "missing field `encryptedFor`", http.StatusUnprocessableEntity)
			return
		}
		if string(body["lastKnownRevisionDate"]) != string(s.state["revisionDate"]) {
			http.Error(w, `{"message":"The client copy of this cipher is out of date."}`, http.StatusBadRequest)
			return
		}
		next := map[string]json.RawMessage{}
		for k, v := range body {
			if cipherRequestKeys[k] || k == "organizationId" {
				next[k] = v
			}
		}
		next["id"] = s.state["id"]
		s.state = next
		s.bump()
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(s.state); err != nil {
		s.t.Errorf("encode: %v", err)
	}
}

// bump gives the stored item a new revision, as any write on the server does.
func (s *fakeCipherServer) bump() {
	s.rev++
	s.state["revisionDate"] = json.RawMessage(`"2000-09-25T00:00:0` + string(rune('0'+s.rev)) + `.000000Z"`)
}

// setupEditServer starts a fake server holding the item from serverCipher,
// points apiClient at it, and seeds a local vault cache with the same item.
// It returns the server and the cached (local) copy of the item.
func setupEditServer(t *testing.T) (*fakeCipherServer, *client.Cipher) {
	t.Helper()
	key := testKey()
	raw, _ := serverCipher(t, key)

	fake := &fakeCipherServer{t: t, state: decodeObject(t, raw)}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	oldClient := apiClient
	apiClient = client.New(srv.URL)
	apiClient.Token = "test-token"
	t.Cleanup(func() { apiClient = oldClient })

	t.Setenv("HOME", t.TempDir())
	oldAccount := vault.ActiveAccount
	vault.ActiveAccount = ""
	t.Cleanup(func() { vault.ActiveAccount = oldAccount })
	path, err := vault.VaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"ciphers":[`+string(raw)+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var local client.Cipher
	if err := json.Unmarshal(raw, &local); err != nil {
		t.Fatal(err)
	}
	return fake, &local
}

// assertNothingLost checks that everything bx does not edit survived a write.
func assertNothingLost(t *testing.T, before, after map[string]json.RawMessage) {
	t.Helper()
	for _, k := range []string{"reprompt", "favorite", "folderId", "notes"} {
		if compactJSON(t, after[k]) != compactJSON(t, before[k]) {
			t.Errorf("%s changed:\n got %s\nwant %s", k, after[k], before[k])
		}
	}
	loginBefore, loginAfter := decodeObject(t, before["login"]), decodeObject(t, after["login"])
	for _, k := range []string{"fido2Credentials", "uris", "autofillOnPageLoad"} {
		if compactJSON(t, loginAfter[k]) != compactJSON(t, loginBefore[k]) {
			t.Errorf("login.%s changed:\n got %s\nwant %s", k, loginAfter[k], loginBefore[k])
		}
	}
}

func TestEdit_AgainstServer_PasswordChange(t *testing.T) {
	fake, local := setupEditServer(t)
	key := testKey()
	before := fake.state

	raw, _, editKey, err := fetchEditBase("GitHub", local, false, key, nil)
	if err != nil {
		t.Fatalf("fetchEditBase: %v", err)
	}
	if err := sendEdit(local, raw, cipherUpdate{Password: strPtr("new-pass")}, testUserID, editKey); err != nil {
		t.Fatalf("sendEdit: %v", err)
	}

	after := fake.state
	assertNothingLost(t, before, after)
	if compactJSON(t, after["fields"]) != compactJSON(t, before["fields"]) {
		t.Errorf("custom fields changed: %s", after["fields"])
	}
	if got := decryptJSONString(t, key, decodeObject(t, after["login"])["password"]); got != "new-pass" {
		t.Errorf("password: got %q", got)
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(after["passwordHistory"], &entries); err != nil || len(entries) != 2 {
		t.Fatalf("passwordHistory: %s", after["passwordHistory"])
	}
	if got := decryptJSONString(t, key, entries[0]["password"]); got != "old-pass" {
		t.Errorf("previous password not in history: got %q", got)
	}

	// The local cache holds the server's copy, passkeys included.
	path, _ := vault.VaultPath()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "fido2Credentials") || !strings.Contains(string(data), string(after["revisionDate"])) {
		t.Errorf("local cache not updated from server copy:\n%s", data)
	}
}

func TestEdit_AgainstServer_Interactive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script as editor")
	}
	fake, local := setupEditServer(t)
	key := testKey()
	before := fake.state

	// The "editor" changes the hidden field and adds a new one using the
	// keyword syntax, and leaves everything else alone.
	script := filepath.Join(t.TempDir(), "editor.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"+
		"sed -i 's/^hidden PIN: 1234$/hidden PIN: 5678/; s/^notes:$/field Recovery: abc-def\\nnotes:/' \"$1\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", script)

	if err := runEditInteractive(editCmd, "GitHub", testUserID, local, key, nil); err != nil {
		t.Fatalf("runEditInteractive: %v", err)
	}

	after := fake.state
	assertNothingLost(t, before, after)
	for _, k := range []string{"name", "passwordHistory"} {
		if compactJSON(t, after[k]) != compactJSON(t, before[k]) {
			t.Errorf("%s changed:\n got %s\nwant %s", k, after[k], before[k])
		}
	}
	if a, b := decodeObject(t, after["login"])["password"], decodeObject(t, before["login"])["password"]; string(a) != string(b) {
		t.Errorf("password re-encrypted although unchanged")
	}

	var fields []client.CipherField
	if err := json.Unmarshal(after["fields"], &fields); err != nil || len(fields) != 2 {
		t.Fatalf("fields: %s", after["fields"])
	}
	want := []cipherCustomField{
		{Type: client.FieldTypeHidden, Name: "PIN", Value: "5678"},
		{Type: client.FieldTypeText, Name: "Recovery", Value: "abc-def"},
	}
	for i, f := range fields {
		got, err := decodeCustomField(f, key)
		if err != nil || got != want[i] {
			t.Errorf("field %d: got %+v, %v; want %+v", i, got, err, want[i])
		}
	}
}

func TestEdit_AgainstServer_RefusesStaleCache(t *testing.T) {
	fake, local := setupEditServer(t)
	fake.bump() // changed elsewhere after the last bx fetch

	_, _, _, err := fetchEditBase("GitHub", local, false, testKey(), nil)
	if err == nil || !strings.Contains(err.Error(), "conflict detected") {
		t.Errorf("expected conflict error, got %v", err)
	}
}

func TestEdit_AgainstServer_ServerRejectsConcurrentChange(t *testing.T) {
	fake, local := setupEditServer(t)
	before := fake.state

	raw, _, key, err := fetchEditBase("GitHub", local, false, testKey(), nil)
	if err != nil {
		t.Fatalf("fetchEditBase: %v", err)
	}
	fake.mu.Lock()
	fake.bump() // changed elsewhere while the editor was open
	fake.mu.Unlock()

	if err := sendEdit(local, raw, cipherUpdate{Name: strPtr("x")}, testUserID, key); err == nil {
		t.Fatal("expected the server to reject the stale write")
	}
	if compactJSON(t, fake.state["name"]) != compactJSON(t, before["name"]) {
		t.Error("stale write was applied")
	}
}
