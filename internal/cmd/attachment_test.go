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
	"github.com/nning/bx/internal/vault"
	"github.com/spf13/cobra"
)

// vaultPathForTest returns the vault cache path for the default account.
func vaultPathForTest() (string, error) {
	return vault.VaultPath()
}

// ---------------------------------------------------------------------------
// findAttachment / safeAttachmentName / humanSize / attachmentKey
// ---------------------------------------------------------------------------

// makeAttachmentCipher builds a cipher with one attachment whose name and key
// are encrypted with itemKey.
func makeAttachmentCipher(t *testing.T, key []byte) (client.Cipher, []byte) {
	t.Helper()
	c := makeCipher(t, "item-1", "With attachment", "", key)
	c.Type = client.CipherTypeLogin

	attKey := make([]byte, 64)
	for i := range attKey {
		attKey[i] = byte(200 - i)
	}
	att := client.CipherAttachment{
		ID:       "att-1",
		FileName: encryptStr(t, key, "report.pdf"),
		Key:      encryptStr(t, key, string(attKey)),
		Size:     "511",
	}
	c.Attachments = []client.CipherAttachment{att}
	return c, attKey
}

func TestFindAttachment_ByNameAndID(t *testing.T) {
	key := testKey()
	c, _ := makeAttachmentCipher(t, key)

	got, err := findAttachment(&c, key, "report.pdf")
	if err != nil || got == nil {
		t.Fatalf("findAttachment by name: %v, %v", got, err)
	}
	if got.ID != "att-1" {
		t.Errorf("ID: %q", got.ID)
	}

	got, err = findAttachment(&c, key, "ATT-1")
	if err != nil || got == nil {
		t.Fatalf("findAttachment by ID: %v, %v", got, err)
	}
	if got.ID != "att-1" {
		t.Errorf("ID: %q", got.ID)
	}

	got, err = findAttachment(&c, key, "missing.pdf")
	if err != nil || got != nil {
		t.Errorf("missing attachment: %v, %v", got, err)
	}
}

func TestSafeAttachmentName(t *testing.T) {
	tests := []struct {
		in    string
		want  string
		fails bool
	}{
		{"report.pdf", "report.pdf", false},
		{"../report.pdf", "report.pdf", false},
		{"/etc/passwd", "passwd", false},
		{"..", "", true},
		{".", "", true},
		{"", "", true},
		{"/", "", true},
	}
	for _, tc := range tests {
		got, err := safeAttachmentName(tc.in)
		if tc.fails {
			if err == nil {
				t.Errorf("safeAttachmentName(%q) = %q, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("safeAttachmentName(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("safeAttachmentName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHumanSize(t *testing.T) {
	tests := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{511, "511 B"},
		{2048, "2.0 KiB"},
		{1536 * 1024, "1.5 MiB"},
		{3 * 1024 * 1024 * 1024, "3.0 GiB"},
	}
	for _, tc := range tests {
		if got := humanSize(tc.in); got != tc.want {
			t.Errorf("humanSize(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAttachmentKey(t *testing.T) {
	key := testKey()
	c, attKey := makeAttachmentCipher(t, key)

	got, err := attachmentKey(&c.Attachments[0], key)
	if err != nil {
		t.Fatalf("attachmentKey: %v", err)
	}
	if string(got) != string(attKey) {
		t.Error("attachment key mismatch")
	}

	broken := c
	broken.Attachments = []client.CipherAttachment{{ID: "att-1", Key: "not-a-cipher-string"}}
	if _, err := attachmentKey(&broken.Attachments[0], key); err == nil {
		t.Error("expected an error for an undecryptable attachment key")
	}
}

// ---------------------------------------------------------------------------
// attachment get against a fake server
// ---------------------------------------------------------------------------

// fakeAttachmentServer serves the encrypted attachment bytes for
// GET /api/ciphers/item-1/attachment/att-1.
type fakeAttachmentServer struct {
	data []byte
}

func (s *fakeAttachmentServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/api/ciphers/item-1/attachment/att-1" {
		_ = json.NewEncoder(w).Encode(map[string]string{"url": "http://" + r.Host + "/file"})
		return
	}
	if r.URL.Path != "/file" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(s.data)
}

// seedAttachmentVault writes a local vault cache with the given cipher and
// seeds an unlocked session with the test key.
func seedAttachmentVault(t *testing.T, c client.Cipher, key []byte) string {
	t.Helper()
	return writeVaultCache(t, key, c)
}

// newAttachmentTestCmd builds a fresh attachment get command with its flags
// registered.
func newAttachmentTestCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "get", RunE: runAttachmentGet}
	cmd.Flags().StringP("output", "o", "", "")
	cmd.Flags().BoolP("force", "f", false, "")
	return cmd
}

func TestAttachmentGet_ToFile(t *testing.T) {
	key := testKey()
	c, attKey := makeAttachmentCipher(t, key)

	encData, err := crypto.EncryptAttachment([]byte("attachment content"), attKey)
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
	if err := cmd.Flags().Set("output", filepath.Join(dir, "report.pdf")); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := runAttachmentGet(cmd, []string{"item-1", "report.pdf"}); err != nil {
			t.Errorf("runAttachmentGet: %v", err)
		}
	})
	if !strings.Contains(out, "Saved attachment: ") || !strings.Contains(out, "report.pdf") {
		t.Errorf("unexpected output: %q", out)
	}
	got, err := os.ReadFile(filepath.Join(dir, "report.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "attachment content" {
		t.Errorf("decrypted file: %q", got)
	}
}

func TestAttachmentGet_RefusesOverwrite(t *testing.T) {
	key := testKey()
	c, attKey := makeAttachmentCipher(t, key)

	encData, err := crypto.EncryptAttachment([]byte("content"), attKey)
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

	// A pre-existing file must not be overwritten without --force.
	if err := os.WriteFile(filepath.Join(dir, "existing.txt"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newAttachmentTestCmd(t)
	if err := cmd.Flags().Set("output", "existing.txt"); err != nil {
		t.Fatal(err)
	}
	if err := runAttachmentGet(cmd, []string{"item-1", "att-1"}); err == nil {
		t.Fatal("expected an error for an existing output file without --force")
	}
	got, err := os.ReadFile(filepath.Join(dir, "existing.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Error("the existing file was overwritten without --force")
	}
}

func TestAttachmentGet_UnknownAttachment(t *testing.T) {
	key := testKey()
	c, _ := makeAttachmentCipher(t, key)

	seedAttachmentVault(t, c, key)

	cmd := newAttachmentTestCmd(t)
	if err := runAttachmentGet(cmd, []string{"item-1", "missing.pdf"}); err == nil {
		t.Fatal("expected an error for an unknown attachment")
	}
}
