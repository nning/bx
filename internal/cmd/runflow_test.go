package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
	"github.com/spf13/cobra"
)

// ---------------------------------------------------------------------------
// runGet with a seeded vault (no server interaction)
// ---------------------------------------------------------------------------

func TestRunGet_JSON(t *testing.T) {
	key := testKey()
	c := makeLoginCipher(t, key)
	dir := writeVaultCache(t, key, c)
	t.Chdir(dir)

	cmd := newGetTestCmd(t)
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() { runGet(cmd, []string{"GitHub"}) })
	var record jsonCipher
	if err := json.Unmarshal([]byte(out), &record); err != nil {
		t.Fatalf("output is not JSON: %q", out)
	}
	if record.ID != "item-1" || record.Type != "login" || record.Name != "GitHub" {
		t.Errorf("record: %+v", record)
	}
	if record.TOTP != "JBSWY3DPEHPK3PXP" {
		t.Errorf("totp: %q", record.TOTP)
	}
}

func TestRunGet_PasswordOnly(t *testing.T) {
	key := testKey()
	c := makeCipherWithUsername(t, "item-1", "GitHub", "user", "", key)
	c.Type = client.CipherTypeLogin
	c.Login = &client.CipherLogin{Password: encryptStr(t, key, "s3cret")}
	dir := writeVaultCache(t, key, c)
	t.Chdir(dir)

	cmd := newGetTestCmd(t)
	if err := cmd.Flags().Set("password-only", "true"); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() { runGet(cmd, []string{"GitHub"}) })
	if out != "s3cret\n" {
		t.Errorf("got %q, want %q", out, "s3cret\n")
	}
}

func TestRunGet_History(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "GitHub", "", key)
	c.Type = client.CipherTypeLogin
	c.PasswordHistory = []client.CipherPasswordHistory{
		{Password: encryptStr(t, key, "old-pass"), LastUsedDate: "2000-09-25T00:00:00.000Z"},
	}
	dir := writeVaultCache(t, key, c)
	t.Chdir(dir)

	cmd := newGetTestCmd(t)
	if err := cmd.Flags().Set("history", "true"); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() { runGet(cmd, []string{"GitHub"}) })
	if !strings.Contains(out, "old-pass") || !strings.Contains(out, "Password history for GitHub") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestRunGet_HistoryJSON(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "GitHub", "", key)
	c.Type = client.CipherTypeLogin
	c.PasswordHistory = []client.CipherPasswordHistory{
		{Password: encryptStr(t, key, "old-pass"), LastUsedDate: "2000-09-25T00:00:00.000Z"},
	}
	dir := writeVaultCache(t, key, c)
	t.Chdir(dir)

	cmd := newGetTestCmd(t)
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("history", "true"); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() { runGet(cmd, []string{"GitHub"}) })
	var entries []jsonHistoryEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("output is not JSON: %q", out)
	}
	if len(entries) != 1 || entries[0].Password != "old-pass" {
		t.Errorf("entries: %+v", entries)
	}
}

// newGetTestCmd builds a fresh get command with its flags registered.
func newGetTestCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "get", Run: runGet}
	addGetFlags(cmd)
	return cmd
}

// ---------------------------------------------------------------------------
// runCreate for a card item against a fake server
// ---------------------------------------------------------------------------

// fakeWriteServer handles POST /api/ciphers and PUT /api/ciphers/{id}: the
// item is replaced by the request, as Vaultwarden and Bitwarden do.
type fakeWriteServer struct {
	t     *testing.T
	state map[string]json.RawMessage
}

func (s *fakeWriteServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.t.Helper()
	switch {
	case r.URL.Path == "/api/ciphers" && r.Method == http.MethodPost:
		var req client.CipherRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body, err := json.Marshal(map[string]any{
			"id":             "new-id",
			"organizationId": nil,
			"folderId":       nil,
			"type":           req.Type,
			"name":           req.Name,
			"card":           req.Card,
			"identity":       req.Identity,
			"sshKey":         req.SshKey,
			"revisionDate":   "2000-10-02T00:00:00Z",
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)

	default:
		http.NotFound(w, r)
	}
}

func TestRunCreate_CardAgainstServer(t *testing.T) {
	key := testKey()
	dir := writeVaultCache(t, key)

	fake := &fakeWriteServer{t: t, state: nil}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	oldClient := apiClient
	apiClient = client.New(srv.URL)
	apiClient.Token = "test-token"
	t.Cleanup(func() { apiClient = oldClient })

	cmd := newCreateTestCmd(t)
	for flag, value := range map[string]string{
		"name":       "My card",
		"cardholder": "John Doe",
		"brand":      "Visa",
		"number":     "4111111111111111",
		"exp-month":  "12",
		"exp-year":   "2027",
		"code":       "123",
		"type":       "card",
	} {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatal(err)
		}
	}

	out := captureStdout(t, func() {
		if err := runCreate(cmd, nil); err != nil {
			t.Errorf("runCreate: %v", err)
		}
	})
	if !strings.Contains(out, "Created: My card") {
		t.Errorf("unexpected output: %q", out)
	}

	// The local cache holds the new item.
	data, err := readVaultFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(data, `"type":3`) {
		t.Errorf("local cache missing the card item:\n%s", data)
	}
}

func TestRunCreate_LoginFlagOnCardIsRejected(t *testing.T) {
	key := testKey()
	writeVaultCache(t, key)

	oldClient := apiClient
	apiClient = client.New("http://localhost")
	apiClient.Token = "test-token"
	t.Cleanup(func() { apiClient = oldClient })

	cmd := newCreateTestCmd(t)
	for flag, value := range map[string]string{"name": "My card", "type": "card", "password": "x"} {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := runCreate(cmd, nil); err == nil {
		t.Error("expected --password to be rejected for a card item")
	}
}

// readVaultFile reads the default account's vault cache in dir.
func readVaultFile(dir string) (string, error) {
	path, err := vaultPathForTest()
	if err != nil {
		return "", err
	}
	// VaultPath uses the real home; the test set HOME to dir.
	data, err := os.ReadFile(filepath.Join(dir, filepath.Base(path)))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ---------------------------------------------------------------------------
// runEdit for a card item against a fake server
// ---------------------------------------------------------------------------

func TestRunEdit_CardAgainstServer(t *testing.T) {
	key := testKey()
	cardRaw := serverCardCipher(t, key)

	fake := &fakeCipherServer{t: t, state: decodeObject(t, cardRaw)}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	oldClient := apiClient
	apiClient = client.New(srv.URL)
	apiClient.Token = "test-token"
	t.Cleanup(func() { apiClient = oldClient })

	c := makeCipher(t, "cipher-id", "My card", "", key)
	c.Type = client.CipherTypeCard
	if err := json.Unmarshal(cardRaw, &c); err != nil {
		t.Fatal(err)
	}
	dir := writeVaultCache(t, key, c)
	t.Chdir(dir)

	cmd := newEditTestCmd(t)
	if err := cmd.Flags().Set("number", "5555"); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runEdit(cmd, []string{"My card"}); err != nil {
			t.Errorf("runEdit: %v", err)
		}
	})
	if !strings.Contains(out, "Updated: My card") {
		t.Errorf("unexpected output: %q", out)
	}
	if got := decryptJSONString(t, key, decodeObject(t, fake.state["card"])["number"]); got != "5555" {
		t.Errorf("number on server: got %q", got)
	}
}

func TestRunEdit_RejectsLoginFlagOnCard(t *testing.T) {
	key := testKey()
	cardRaw := serverCardCipher(t, key)

	fake := &fakeCipherServer{t: t, state: decodeObject(t, cardRaw)}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	oldClient := apiClient
	apiClient = client.New(srv.URL)
	apiClient.Token = "test-token"
	t.Cleanup(func() { apiClient = oldClient })

	c := makeCipher(t, "cipher-id", "My card", "", key)
	c.Type = client.CipherTypeCard
	if err := json.Unmarshal(cardRaw, &c); err != nil {
		t.Fatal(err)
	}
	dir := writeVaultCache(t, key, c)
	t.Chdir(dir)

	cmd := newEditTestCmd(t)
	if err := cmd.Flags().Set("password", "x"); err != nil {
		t.Fatal(err)
	}
	if err := runEdit(cmd, []string{"My card"}); err == nil {
		t.Error("expected --password to be rejected for a card item")
	}
}

// ---------------------------------------------------------------------------
// runAttachmentList
// ---------------------------------------------------------------------------

func TestRunAttachmentList(t *testing.T) {
	key := testKey()
	c, _ := makeAttachmentCipher(t, key)
	dir := writeVaultCache(t, key, c)
	t.Chdir(dir)

	out := captureStdout(t, func() {
		if err := runAttachmentList(nil, []string{"item-1"}); err != nil {
			t.Errorf("runAttachmentList: %v", err)
		}
	})
	if !strings.Contains(out, "report.pdf") || !strings.Contains(out, "511 B") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestRunAttachmentList_NoAttachments(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "Plain", "", key)
	dir := writeVaultCache(t, key, c)
	t.Chdir(dir)

	if err := runAttachmentList(nil, []string{"item-1"}); err == nil {
		t.Error("expected an error for an item without attachments")
	}
}

// ---------------------------------------------------------------------------
// Review fixes
// ---------------------------------------------------------------------------

func TestRunCreate_SshKeyRequiresPrivateKey(t *testing.T) {
	key := testKey()
	writeVaultCache(t, key)

	oldClient := apiClient
	apiClient = client.New("http://localhost")
	apiClient.Token = "test-token"
	t.Cleanup(func() { apiClient = oldClient })

	cmd := newCreateTestCmd(t)
	for flag, value := range map[string]string{"name": "My key", "type": "ssh-key", "public-key": "ssh-ed25519 AAAA"} {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := runCreate(cmd, nil); err == nil {
		t.Error("expected an error for an SSH key item without a private key")
	}
}

func TestWriteAttachmentFile_SymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Symlink("/tmp/never-created-target", "link"); err != nil {
		t.Skip("symlinks not supported")
	}
	if err := writeAttachmentFile([]byte("x"), "link", true); err == nil {
		t.Error("expected an error writing through a symlink with --force")
	}
	// Without --force the O_EXCL create must also refuse (the link exists).
	if err := writeAttachmentFile([]byte("x"), "link", false); err == nil {
		t.Error("expected an error creating over an existing symlink")
	}
}

func TestWriteAttachmentFile_AtomicOverwrite(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := writeAttachmentFile([]byte("one"), "f.txt", false); err != nil {
		t.Fatalf("writeAttachmentFile: %v", err)
	}
	// Overwriting without --force must fail and keep the original.
	if err := writeAttachmentFile([]byte("two"), "f.txt", false); err == nil {
		t.Error("expected an error for an existing file without --force")
	}
	data, err := os.ReadFile("f.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "one" {
		t.Errorf("file changed: %q", data)
	}
	// With --force the file is replaced.
	if err := writeAttachmentFile([]byte("two"), "f.txt", true); err != nil {
		t.Fatalf("writeAttachmentFile with force: %v", err)
	}
	data, err = os.ReadFile("f.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "two" {
		t.Errorf("file not replaced: %q", data)
	}
}

func TestRunAttachmentGet_OutputDash(t *testing.T) {
	key := testKey()
	c, attKey := makeAttachmentCipher(t, key)

	encData, err := crypto.EncryptAttachment([]byte("stdout content"), attKey)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeAttachmentServer{data: encData}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	oldClient := apiClient
	apiClient = client.New(srv.URL)
	apiClient.Token = "test-token"
	t.Cleanup(func() { apiClient = oldClient })

	dir := seedAttachmentVault(t, c, key)
	t.Chdir(dir)

	cmd := newAttachmentTestCmd(t)
	if err := cmd.Flags().Set("output", "-"); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := runAttachmentGet(cmd, []string{"item-1", "report.pdf"}); err != nil {
			t.Errorf("runAttachmentGet: %v", err)
		}
	})
	if out != "stdout content" {
		t.Errorf("got %q, want the decrypted content on stdout", out)
	}
}

// ---------------------------------------------------------------------------
// Review round 2 fixes
// ---------------------------------------------------------------------------

func TestHumanSize_ClampsHugeValues(t *testing.T) {
	// A size from a tampered vault cache must not index past the unit lookup.
	if got := humanSize(int64(^uint64(0) >> 1)); got == "" {
		t.Error("humanSize(MaxInt64) returned empty")
	}
	if got := humanSize(int64(1) << 62); got == "" {
		t.Error("humanSize(1<<62) returned empty")
	}
}

func TestRunEdit_InteractiveRejectsFieldFlags(t *testing.T) {
	key := testKey()
	cardRaw := serverCardCipher(t, key)

	fake := &fakeCipherServer{t: t, state: decodeObject(t, cardRaw)}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	oldClient := apiClient
	apiClient = client.New(srv.URL)
	apiClient.Token = "test-token"
	t.Cleanup(func() { apiClient = oldClient })

	c := makeCipher(t, "cipher-id", "My card", "", key)
	c.Type = client.CipherTypeCard
	if err := json.Unmarshal(cardRaw, &c); err != nil {
		t.Fatal(err)
	}
	dir := writeVaultCache(t, key, c)
	t.Chdir(dir)

	cmd := newEditTestCmd(t)
	if err := cmd.Flags().Set("interactive", "true"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("number", "5555"); err != nil {
		t.Fatal(err)
	}
	if err := runEdit(cmd, []string{"My card"}); err == nil {
		t.Error("expected --interactive with a field flag to be rejected")
	}
}

func TestRunEdit_InteractiveRejectsMutableFlags(t *testing.T) {
	key := testKey()
	c := makeLoginCipher(t, key)
	dir := writeVaultCache(t, key, c)
	t.Chdir(dir)

	oldClient := apiClient
	apiClient = client.New("http://localhost")
	apiClient.Token = "test-token"
	t.Cleanup(func() { apiClient = oldClient })

	cmd := newEditTestCmd(t)
	if err := cmd.Flags().Set("interactive", "true"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("name", "x"); err != nil {
		t.Fatal(err)
	}
	if err := runEdit(cmd, []string{"GitHub"}); err == nil {
		t.Error("expected --interactive with --name to be rejected")
	}
}
