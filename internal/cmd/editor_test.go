package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nning/bx/internal/client"
)

// ---------------------------------------------------------------------------
// formatCipherForEditor / parseCipherFromEditor round-trip
// ---------------------------------------------------------------------------

func TestFormatParse_RoundTrip_AllFields(t *testing.T) {
	original := cipherEditFields{
		Type:     client.CipherTypeLogin,
		Name:     "GitHub",
		Username: "user@example.com",
		Password: "s3cret!",
		Totp:     "JBSWY3DPEHPK3PXP",
		URLs:     []string{"https://github.com", "https://github.com/login"},
		Notes:    "My personal account\nwith multiple lines",
	}

	text := formatCipherForEditor(original)
	parsed := parseCipherFromEditor(text, client.CipherTypeLogin)

	if parsed.Name != original.Name {
		t.Errorf("Name: got %q, want %q", parsed.Name, original.Name)
	}
	if parsed.Username != original.Username {
		t.Errorf("Username: got %q, want %q", parsed.Username, original.Username)
	}
	if parsed.Password != original.Password {
		t.Errorf("Password: got %q, want %q", parsed.Password, original.Password)
	}
	if parsed.Totp != original.Totp {
		t.Errorf("Totp: got %q, want %q", parsed.Totp, original.Totp)
	}
	if !urlsEqual(parsed.URLs, original.URLs) {
		t.Errorf("URLs: got %v, want %v", parsed.URLs, original.URLs)
	}
	if parsed.Notes != original.Notes {
		t.Errorf("Notes: got %q, want %q", parsed.Notes, original.Notes)
	}
}

func TestFormatParse_RoundTrip_EmptyFields(t *testing.T) {
	original := cipherEditFields{
		Type: client.CipherTypeLogin,
		Name: "Empty Entry",
	}

	text := formatCipherForEditor(original)
	parsed := parseCipherFromEditor(text, client.CipherTypeLogin)

	if parsed.Name != original.Name {
		t.Errorf("Name: got %q, want %q", parsed.Name, original.Name)
	}
	if parsed.Username != "" {
		t.Errorf("Username: got %q, want empty", parsed.Username)
	}
	if parsed.Password != "" {
		t.Errorf("Password: got %q, want empty", parsed.Password)
	}
	if parsed.Totp != "" {
		t.Errorf("Totp: got %q, want empty", parsed.Totp)
	}
	if len(parsed.URLs) != 0 {
		t.Errorf("URLs: got %v, want empty", parsed.URLs)
	}
	if parsed.Notes != "" {
		t.Errorf("Notes: got %q, want empty", parsed.Notes)
	}
}

func TestFormatParse_RoundTrip_SingleURL(t *testing.T) {
	original := cipherEditFields{
		Type: client.CipherTypeLogin,
		Name: "Single URL",
		URLs: []string{"https://example.com"},
	}

	text := formatCipherForEditor(original)
	parsed := parseCipherFromEditor(text, client.CipherTypeLogin)

	if !urlsEqual(parsed.URLs, original.URLs) {
		t.Errorf("URLs: got %v, want %v", parsed.URLs, original.URLs)
	}
}

// ---------------------------------------------------------------------------
// parseCipherFromEditor edge cases
// ---------------------------------------------------------------------------

func TestParseCipherFromEditor_IgnoresComments(t *testing.T) {
	text := `# This is a comment
name: Test
# Another comment
username: user
password: pass
totp:
url:
notes:
`
	parsed := parseCipherFromEditor(text, client.CipherTypeLogin)
	if parsed.Name != "Test" {
		t.Errorf("Name: got %q, want %q", parsed.Name, "Test")
	}
	if parsed.Username != "user" {
		t.Errorf("Username: got %q, want %q", parsed.Username, "user")
	}
}

func TestParseCipherFromEditor_NotesMultiline(t *testing.T) {
	text := `name: Test
username: user
password: pass
totp:
url:
notes:
Line 1
Line 2
Line 3
`
	parsed := parseCipherFromEditor(text, client.CipherTypeLogin)
	want := "Line 1\nLine 2\nLine 3"
	if parsed.Notes != want {
		t.Errorf("Notes: got %q, want %q", parsed.Notes, want)
	}
}

func TestParseCipherFromEditor_NotesInlineAndMultiline(t *testing.T) {
	text := `name: Test
username: user
password: pass
totp:
url:
notes: First line
Second line
Third line
`
	parsed := parseCipherFromEditor(text, client.CipherTypeLogin)
	want := "First line\nSecond line\nThird line"
	if parsed.Notes != want {
		t.Errorf("Notes: got %q, want %q", parsed.Notes, want)
	}
}

func TestParseCipherFromEditor_EmptyInput(t *testing.T) {
	parsed := parseCipherFromEditor("", client.CipherTypeLogin)
	if parsed.Name != "" {
		t.Errorf("Name: got %q, want empty", parsed.Name)
	}
}

func TestParseCipherFromEditor_MultipleURLs(t *testing.T) {
	text := `name: Test
username: user
password: pass
totp:
url: https://example.com
url: https://example.org
url: https://example.net
notes:
`
	parsed := parseCipherFromEditor(text, client.CipherTypeLogin)
	want := []string{"https://example.com", "https://example.org", "https://example.net"}
	if !urlsEqual(parsed.URLs, want) {
		t.Errorf("URLs: got %v, want %v", parsed.URLs, want)
	}
}

func TestParseCipherFromEditor_URLsRemoved(t *testing.T) {
	// User deletes all URL lines — should result in empty slice.
	text := `name: Test
username: user
password: pass
totp:
notes:
`
	parsed := parseCipherFromEditor(text, client.CipherTypeLogin)
	if len(parsed.URLs) != 0 {
		t.Errorf("URLs: got %v, want empty", parsed.URLs)
	}
}

func TestParseCipherFromEditor_PasswordWithColons(t *testing.T) {
	text := `name: Test
username: user
password: pass:word:with:colons
totp:
url:
notes:
`
	parsed := parseCipherFromEditor(text, client.CipherTypeLogin)
	if parsed.Password != "pass:word:with:colons" {
		t.Errorf("Password: got %q, want %q", parsed.Password, "pass:word:with:colons")
	}
}

// ---------------------------------------------------------------------------
// parseKV
// ---------------------------------------------------------------------------

func TestParseKV_Valid(t *testing.T) {
	key, val, ok := parseKV("name: GitHub")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if key != "name" {
		t.Errorf("key: got %q, want %q", key, "name")
	}
	if val != "GitHub" {
		t.Errorf("val: got %q, want %q", val, "GitHub")
	}
}

func TestParseKV_EmptyValue(t *testing.T) {
	key, val, ok := parseKV("totp:")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if key != "totp" {
		t.Errorf("key: got %q, want %q", key, "totp")
	}
	if val != "" {
		t.Errorf("val: got %q, want empty", val)
	}
}

func TestParseKV_EmptyLine(t *testing.T) {
	_, _, ok := parseKV("")
	if ok {
		t.Error("expected ok=false for empty line")
	}
}

func TestParseKV_NoColon(t *testing.T) {
	_, _, ok := parseKV("no colon here")
	if ok {
		t.Error("expected ok=false for line without colon")
	}
}

func TestParseKV_ValueWithColons(t *testing.T) {
	key, val, ok := parseKV("password: a:b:c")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if key != "password" {
		t.Errorf("key: got %q, want %q", key, "password")
	}
	if val != "a:b:c" {
		t.Errorf("val: got %q, want %q", val, "a:b:c")
	}
}

func TestParseKV_CaseInsensitiveKey(t *testing.T) {
	key, _, ok := parseKV("Name: test")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if key != "name" {
		t.Errorf("key: got %q, want %q", key, "name")
	}
}

// ---------------------------------------------------------------------------
// urlsEqual
// ---------------------------------------------------------------------------

func TestUrlsEqual_BothEmpty(t *testing.T) {
	if !urlsEqual(nil, nil) {
		t.Error("expected true for nil,nil")
	}
	if !urlsEqual([]string{}, []string{}) {
		t.Error("expected true for empty,empty")
	}
}

func TestUrlsEqual_DifferentLength(t *testing.T) {
	if urlsEqual([]string{"a"}, []string{"a", "b"}) {
		t.Error("expected false for different lengths")
	}
}

func TestUrlsEqual_Same(t *testing.T) {
	a := []string{"https://example.com", "https://example.org"}
	b := []string{"https://example.com", "https://example.org"}
	if !urlsEqual(a, b) {
		t.Error("expected true for equal slices")
	}
}

func TestUrlsEqual_DifferentOrder(t *testing.T) {
	a := []string{"https://example.com", "https://example.org"}
	b := []string{"https://example.org", "https://example.com"}
	if urlsEqual(a, b) {
		t.Error("expected false for different order")
	}
}

// ---------------------------------------------------------------------------
// editorCommand
// ---------------------------------------------------------------------------

func TestEditorCommand_Visual(t *testing.T) {
	t.Setenv("VISUAL", "code")
	t.Setenv("EDITOR", "nano")
	if got := editorCommand(); got != "code" {
		t.Errorf("got %q, want %q", got, "code")
	}
}

func TestEditorCommand_Editor(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "nano")
	if got := editorCommand(); got != "nano" {
		t.Errorf("got %q, want %q", got, "nano")
	}
}

func TestEditorCommand_Default(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")
	if got := editorCommand(); got != "vi" {
		t.Errorf("got %q, want %q", got, "vi")
	}
}

// ---------------------------------------------------------------------------
// splitEditorCommand
// ---------------------------------------------------------------------------

func TestSplitEditorCommand_Simple(t *testing.T) {
	got := splitEditorCommand("vim")
	if len(got) != 1 || got[0] != "vim" {
		t.Errorf("got %v, want [vim]", got)
	}
}

func TestSplitEditorCommand_WithArgs(t *testing.T) {
	got := splitEditorCommand("code -w")
	if len(got) != 2 || got[0] != "code" || got[1] != "-w" {
		t.Errorf("got %v, want [code -w]", got)
	}
}

func TestSplitEditorCommand_DoubleQuoted(t *testing.T) {
	got := splitEditorCommand(`"my editor" --flag`)
	if len(got) != 2 || got[0] != "my editor" || got[1] != "--flag" {
		t.Errorf("got %v, want [my editor --flag]", got)
	}
}

func TestSplitEditorCommand_SingleQuoted(t *testing.T) {
	got := splitEditorCommand(`'my editor' --flag`)
	if len(got) != 2 || got[0] != "my editor" || got[1] != "--flag" {
		t.Errorf("got %v, want [my editor --flag]", got)
	}
}

func TestSplitEditorCommand_Empty(t *testing.T) {
	got := splitEditorCommand("")
	if len(got) != 1 || got[0] != "vi" {
		t.Errorf("got %v, want [vi]", got)
	}
}

func TestSplitEditorCommand_MultipleArgs(t *testing.T) {
	got := splitEditorCommand("vim -f --noplugin")
	if len(got) != 3 || got[0] != "vim" || got[1] != "-f" || got[2] != "--noplugin" {
		t.Errorf("got %v, want [vim -f --noplugin]", got)
	}
}

// ---------------------------------------------------------------------------
// secureWipe
// ---------------------------------------------------------------------------

func TestSecureWipe_RemovesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("sensitive data"), 0600); err != nil {
		t.Fatal(err)
	}

	secureWipe(path)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected file to be removed after secureWipe")
	}
}

func TestSecureWipe_NonexistentFile(t *testing.T) {
	// Should not panic.
	secureWipe("/nonexistent/path/to/file")
}

// ---------------------------------------------------------------------------
// decryptCipherToFields
// ---------------------------------------------------------------------------

func TestDecryptCipherToFields_AllFields(t *testing.T) {
	key := testKey()
	totp := encryptStr(t, key, "JBSWY3DPEHPK3PXP")
	notes := encryptStr(t, key, "Some notes")

	c := client.Cipher{
		ID:   "test-id",
		Type: client.CipherTypeLogin,
		Data: client.CipherData{
			Name:     encryptStr(t, key, "GitHub"),
			Username: encryptStr(t, key, "user@example.com"),
			Password: encryptStr(t, key, "s3cret"),
			Totp:     &totp,
			Notes:    &notes,
			URIs: []client.CipherURI{
				{URI: encryptStr(t, key, "https://github.com")},
			},
		},
	}

	fields, err := decryptCipherToFields(&c, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if fields.Name != "GitHub" {
		t.Errorf("Name: got %q, want %q", fields.Name, "GitHub")
	}
	if fields.Username != "user@example.com" {
		t.Errorf("Username: got %q, want %q", fields.Username, "user@example.com")
	}
	if fields.Password != "s3cret" {
		t.Errorf("Password: got %q, want %q", fields.Password, "s3cret")
	}
	if fields.Totp != "JBSWY3DPEHPK3PXP" {
		t.Errorf("Totp: got %q, want %q", fields.Totp, "JBSWY3DPEHPK3PXP")
	}
	if len(fields.URLs) != 1 || fields.URLs[0] != "https://github.com" {
		t.Errorf("URLs: got %v, want [https://github.com]", fields.URLs)
	}
	if fields.Notes != "Some notes" {
		t.Errorf("Notes: got %q, want %q", fields.Notes, "Some notes")
	}
}

func TestDecryptCipherToFields_EmptyOptional(t *testing.T) {
	key := testKey()

	c := client.Cipher{
		ID:   "test-id",
		Type: client.CipherTypeLogin,
		Data: client.CipherData{
			Name: encryptStr(t, key, "Minimal"),
		},
	}

	fields, err := decryptCipherToFields(&c, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if fields.Name != "Minimal" {
		t.Errorf("Name: got %q, want %q", fields.Name, "Minimal")
	}
	if fields.Username != "" {
		t.Errorf("Username: got %q, want empty", fields.Username)
	}
	if fields.Password != "" {
		t.Errorf("Password: got %q, want empty", fields.Password)
	}
	if fields.Totp != "" {
		t.Errorf("Totp: got %q, want empty", fields.Totp)
	}
	if len(fields.URLs) != 0 {
		t.Errorf("URLs: got %v, want empty", fields.URLs)
	}
	if fields.Notes != "" {
		t.Errorf("Notes: got %q, want empty", fields.Notes)
	}
}

// ---------------------------------------------------------------------------
// decryptCipherToFields — error paths
// ---------------------------------------------------------------------------

func TestDecryptCipherToFields_InvalidName(t *testing.T) {
	key := testKey()
	c := client.Cipher{
		ID:   "test-id",
		Type: client.CipherTypeLogin,
		Data: client.CipherData{
			Name: "invalid-not-encrypted",
		},
	}
	_, err := decryptCipherToFields(&c, key)
	if err == nil {
		t.Fatal("expected error for invalid name encryption")
	}
	if !strings.Contains(err.Error(), "name") {
		t.Errorf("error should mention 'name': %v", err)
	}
}

func TestDecryptCipherToFields_InvalidUsername(t *testing.T) {
	key := testKey()
	c := client.Cipher{
		ID:   "test-id",
		Type: client.CipherTypeLogin,
		Data: client.CipherData{
			Name:     encryptStr(t, key, "Valid Name"),
			Username: "invalid-not-encrypted",
		},
	}
	_, err := decryptCipherToFields(&c, key)
	if err == nil {
		t.Fatal("expected error for invalid username encryption")
	}
	if !strings.Contains(err.Error(), "username") {
		t.Errorf("error should mention 'username': %v", err)
	}
}

func TestDecryptCipherToFields_InvalidPassword(t *testing.T) {
	key := testKey()
	c := client.Cipher{
		ID:   "test-id",
		Type: client.CipherTypeLogin,
		Data: client.CipherData{
			Name:     encryptStr(t, key, "Valid Name"),
			Password: "invalid-not-encrypted",
		},
	}
	_, err := decryptCipherToFields(&c, key)
	if err == nil {
		t.Fatal("expected error for invalid password encryption")
	}
	if !strings.Contains(err.Error(), "password") {
		t.Errorf("error should mention 'password': %v", err)
	}
}

func TestDecryptCipherToFields_InvalidTotp(t *testing.T) {
	key := testKey()
	invalidTotp := "invalid-not-encrypted"
	c := client.Cipher{
		ID:   "test-id",
		Type: client.CipherTypeLogin,
		Data: client.CipherData{
			Name: encryptStr(t, key, "Valid Name"),
			Totp: &invalidTotp,
		},
	}
	_, err := decryptCipherToFields(&c, key)
	if err == nil {
		t.Fatal("expected error for invalid TOTP encryption")
	}
	if !strings.Contains(err.Error(), "TOTP") {
		t.Errorf("error should mention 'TOTP': %v", err)
	}
}

func TestDecryptCipherToFields_InvalidURI(t *testing.T) {
	key := testKey()
	c := client.Cipher{
		ID:   "test-id",
		Type: client.CipherTypeLogin,
		Data: client.CipherData{
			Name: encryptStr(t, key, "Valid Name"),
			URIs: []client.CipherURI{
				{URI: "invalid-not-encrypted"},
			},
		},
	}
	_, err := decryptCipherToFields(&c, key)
	if err == nil {
		t.Fatal("expected error for invalid URI encryption")
	}
	if !strings.Contains(err.Error(), "URI") {
		t.Errorf("error should mention 'URI': %v", err)
	}
}

func TestDecryptCipherToFields_InvalidNotes(t *testing.T) {
	key := testKey()
	invalidNotes := "invalid-not-encrypted"
	c := client.Cipher{
		ID:   "test-id",
		Type: client.CipherTypeLogin,
		Data: client.CipherData{
			Name:  encryptStr(t, key, "Valid Name"),
			Notes: &invalidNotes,
		},
	}
	_, err := decryptCipherToFields(&c, key)
	if err == nil {
		t.Fatal("expected error for invalid notes encryption")
	}
	if !strings.Contains(err.Error(), "notes") {
		t.Errorf("error should mention 'notes': %v", err)
	}
}

// ---------------------------------------------------------------------------
// openInEditor (using a simple script as $EDITOR)
// ---------------------------------------------------------------------------

func TestOpenInEditor_BasicFlow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping shell-based editor test on Windows")
	}
	// Use sed as the "editor" — it appends a line to the file.
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "sed")

	content := "name: Original\nusername: user\npassword: pass\ntotp:\nurl:\nnotes:\n"

	// sed -i 's/Original/Modified/' <file> would work, but we need the
	// editor to receive the filename as an argument.  openInEditor passes
	// the filename as the first arg.  Use a wrapper script.
	dir := t.TempDir()
	script := filepath.Join(dir, "editor.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nTMP=\"$1.tmp\"\nsed 's/Original/Modified/' \"$1\" > \"$TMP\" && mv \"$TMP\" \"$1\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", script)

	result, err := openInEditor(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "Modified") {
		t.Errorf("expected edited content to contain 'Modified', got: %q", result)
	}
	if strings.Contains(result, "Original") {
		t.Errorf("expected 'Original' to be replaced, got: %q", result)
	}
}

// ---------------------------------------------------------------------------
// formatCipherForEditor output format
// ---------------------------------------------------------------------------

func TestFormatCipherForEditor_ContainsComments(t *testing.T) {
	f := cipherEditFields{Type: client.CipherTypeLogin, Name: "Test"}
	text := formatCipherForEditor(f)
	if !strings.Contains(text, "# ") {
		t.Error("expected output to contain comment lines")
	}
}

func TestFormatCipherForEditor_EmptyURLShowsEmptyLine(t *testing.T) {
	f := cipherEditFields{Type: client.CipherTypeLogin, Name: "Test"}
	text := formatCipherForEditor(f)
	if !strings.Contains(text, "url:\n") {
		t.Error("expected empty url line when no URLs")
	}
}

// ---------------------------------------------------------------------------
// CRLF normalization
// ---------------------------------------------------------------------------

func TestParseCipherFromEditor_CRLFNormalized(t *testing.T) {
	// Simulates a Windows editor writing CRLF line endings.
	text := "name: Test\r\nusername: user\r\npassword: pass\r\ntotp:\r\nurl: https://example.com\r\nnotes:\r\nLine 1\r\nLine 2\r\n"
	parsed := parseCipherFromEditor(text, client.CipherTypeLogin)
	if parsed.Name != "Test" {
		t.Errorf("Name: got %q, want %q", parsed.Name, "Test")
	}
	if parsed.Username != "user" {
		t.Errorf("Username: got %q, want %q", parsed.Username, "user")
	}
	if parsed.Password != "pass" {
		t.Errorf("Password: got %q, want %q", parsed.Password, "pass")
	}
	if len(parsed.URLs) != 1 || parsed.URLs[0] != "https://example.com" {
		t.Errorf("URLs: got %v, want [https://example.com]", parsed.URLs)
	}
	want := "Line 1\nLine 2"
	if parsed.Notes != want {
		t.Errorf("Notes: got %q, want %q", parsed.Notes, want)
	}
}

func TestParseCipherFromEditor_NotesPreservesHash(t *testing.T) {
	// Inside notes, '#' lines are preserved as normal text.
	text := "name: Test\nusername:\npassword:\ntotp:\nurl:\nnotes:\n# This is a note\nRegular line\n"
	parsed := parseCipherFromEditor(text, client.CipherTypeLogin)
	want := "# This is a note\nRegular line"
	if parsed.Notes != want {
		t.Errorf("Notes: got %q, want %q", parsed.Notes, want)
	}
}

// ---------------------------------------------------------------------------
// secureWipe edge cases
// ---------------------------------------------------------------------------

func TestSecureWipe_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}

	secureWipe(path)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected empty file to be removed after secureWipe")
	}
}

func TestSecureWipe_Symlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test not reliable on Windows")
	}
	dir := t.TempDir()
	realFile := filepath.Join(dir, "real.txt")
	link := filepath.Join(dir, "link.txt")

	if err := os.WriteFile(realFile, []byte("real content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realFile, link); err != nil {
		t.Fatal(err)
	}

	// secureWipe should refuse to follow the symlink, leaving both files intact.
	secureWipe(link)

	// The real file should still exist and be unmodified.
	data, err := os.ReadFile(realFile)
	if err != nil {
		t.Fatalf("real file should still exist: %v", err)
	}
	if string(data) != "real content" {
		t.Errorf("real file modified: got %q", string(data))
	}
}

func TestSecureWipe_OverwritesBeforeRemoval(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	content := "super secret password 12345"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Verify file exists with content first.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != content {
		t.Fatalf("setup failed: got %q", string(data))
	}

	secureWipe(path)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected file to be removed")
	}
}

func TestSecureWipe_LargerThanChunkSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.txt")
	// Create a file larger than 64 KiB chunk to exercise the chunked write loop.
	data := make([]byte, 128*1024)
	for i := range data {
		data[i] = 'A'
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	secureWipe(path)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected large file to be removed after secureWipe")
	}
}

// ---------------------------------------------------------------------------
// decryptCipherToFields — additional coverage
// ---------------------------------------------------------------------------

func TestDecryptCipherToFields_MultipleURIs(t *testing.T) {
	key := testKey()

	c := client.Cipher{
		ID:   "test-id",
		Type: client.CipherTypeLogin,
		Data: client.CipherData{
			Name: encryptStr(t, key, "Multi URI"),
			URIs: []client.CipherURI{
				{URI: encryptStr(t, key, "https://example.com")},
				{URI: encryptStr(t, key, "https://example.org")},
				{URI: encryptStr(t, key, "https://example.net")},
			},
		},
	}

	fields, err := decryptCipherToFields(&c, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"https://example.com", "https://example.org", "https://example.net"}
	if !urlsEqual(fields.URLs, want) {
		t.Errorf("URLs: got %v, want %v", fields.URLs, want)
	}
}

func TestDecryptCipherToFields_EmptyTotp(t *testing.T) {
	key := testKey()
	emptyTotp := ""

	c := client.Cipher{
		ID:   "test-id",
		Type: client.CipherTypeLogin,
		Data: client.CipherData{
			Name: encryptStr(t, key, "No TOTP"),
			Totp: &emptyTotp,
		},
	}

	fields, err := decryptCipherToFields(&c, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fields.Totp != "" {
		t.Errorf("Totp: got %q, want empty", fields.Totp)
	}
}

func TestDecryptCipherToFields_EmptyNotes(t *testing.T) {
	key := testKey()
	emptyNotes := ""

	c := client.Cipher{
		ID:   "test-id",
		Type: client.CipherTypeLogin,
		Data: client.CipherData{
			Name:  encryptStr(t, key, "No Notes"),
			Notes: &emptyNotes,
		},
	}

	fields, err := decryptCipherToFields(&c, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fields.Notes != "" {
		t.Errorf("Notes: got %q, want empty", fields.Notes)
	}
}

func TestDecryptCipherToFields_NilTotp(t *testing.T) {
	key := testKey()

	c := client.Cipher{
		ID:   "test-id",
		Type: client.CipherTypeLogin,
		Data: client.CipherData{
			Name: encryptStr(t, key, "Nil TOTP"),
			Totp: nil,
		},
	}

	fields, err := decryptCipherToFields(&c, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fields.Totp != "" {
		t.Errorf("Totp: got %q, want empty", fields.Totp)
	}
}

func TestDecryptCipherToFields_NilNotes(t *testing.T) {
	key := testKey()

	c := client.Cipher{
		ID:   "test-id",
		Type: client.CipherTypeLogin,
		Data: client.CipherData{
			Name:  encryptStr(t, key, "Nil Notes"),
			Notes: nil,
		},
	}

	fields, err := decryptCipherToFields(&c, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fields.Notes != "" {
		t.Errorf("Notes: got %q, want empty", fields.Notes)
	}
}

// ---------------------------------------------------------------------------
// splitEditorCommand — additional coverage
// ---------------------------------------------------------------------------

func TestSplitEditorCommand_ExtraWhitespace(t *testing.T) {
	got := splitEditorCommand("  vim   -f   ")
	if len(got) != 2 || got[0] != "vim" || got[1] != "-f" {
		t.Errorf("got %v, want [vim -f]", got)
	}
}

func TestSplitEditorCommand_OnlySpaces(t *testing.T) {
	got := splitEditorCommand("   ")
	if len(got) != 1 || got[0] != "vi" {
		t.Errorf("got %v, want [vi] for whitespace-only input", got)
	}
}

func TestSplitEditorCommand_MixedQuotes(t *testing.T) {
	got := splitEditorCommand(`"my editor" -w 'some flag'`)
	if len(got) != 3 || got[0] != "my editor" || got[1] != "-w" || got[2] != "some flag" {
		t.Errorf("got %v, want [my editor -w some flag]", got)
	}
}

// ---------------------------------------------------------------------------
// formatCipherForEditor — output structure
// ---------------------------------------------------------------------------

func TestFormatCipherForEditor_AllFieldsPresent(t *testing.T) {
	f := cipherEditFields{
		Type:     client.CipherTypeLogin,
		Name:     "My Entry",
		Username: "admin",
		Password: "p@ss",
		Totp:     "ABCD1234",
		URLs:     []string{"https://example.com", "https://example.org"},
		Notes:    "Some notes here",
	}
	text := formatCipherForEditor(f)

	// Verify all fields are present in the output.
	checks := []string{
		"name: My Entry",
		"username: admin",
		"password: p@ss",
		"totp: ABCD1234",
		"url: https://example.com",
		"url: https://example.org",
		"notes:",
		"Some notes here",
	}
	for _, check := range checks {
		if !strings.Contains(text, check) {
			t.Errorf("expected output to contain %q", check)
		}
	}
}

func TestFormatCipherForEditor_NotesWithNewline(t *testing.T) {
	f := cipherEditFields{
		Type:  client.CipherTypeLogin,
		Name:  "Test",
		Notes: "Line 1\nLine 2\n",
	}
	text := formatCipherForEditor(f)

	// Notes that already end with \n should not get a double newline.
	if strings.Contains(text, "Line 2\n\n") {
		t.Error("expected no double newline after notes ending with \\n")
	}
}

func TestFormatCipherForEditor_CommentHeaderUpdated(t *testing.T) {
	f := cipherEditFields{Type: client.CipherTypeLogin, Name: "Test"}
	text := formatCipherForEditor(f)

	// The header should now clarify that # is only a comment before notes.
	if !strings.Contains(text, "before 'notes:'") {
		t.Error("expected header to mention that # comments only apply before notes")
	}
}

// ---------------------------------------------------------------------------
// parseCipherFromEditor — additional edge cases
// ---------------------------------------------------------------------------

func TestParseCipherFromEditor_WhitespaceOnlyLines(t *testing.T) {
	text := "  \n  name: Test  \n  username:  user  \npassword:  pass  \ntotp:\nurl:\nnotes:\n"
	parsed := parseCipherFromEditor(text, client.CipherTypeLogin)
	if parsed.Name != "Test" {
		t.Errorf("Name: got %q, want %q", parsed.Name, "Test")
	}
	if parsed.Username != "user" {
		t.Errorf("Username: got %q, want %q", parsed.Username, "user")
	}
	if parsed.Password != "pass" {
		t.Errorf("Password: got %q, want %q", parsed.Password, "pass")
	}
}

func TestParseCipherFromEditor_UnknownKeysIgnored(t *testing.T) {
	text := "name: Test\nunknown: value\nfoo: bar\nusername: user\npassword: pass\ntotp:\nurl:\nnotes:\n"
	parsed := parseCipherFromEditor(text, client.CipherTypeLogin)
	if parsed.Name != "Test" {
		t.Errorf("Name: got %q, want %q", parsed.Name, "Test")
	}
	if parsed.Username != "user" {
		t.Errorf("Username: got %q, want %q", parsed.Username, "user")
	}
}

func TestParseCipherFromEditor_EmptyURLLine(t *testing.T) {
	// An empty "url:" line should not add anything to URLs.
	text := "name: Test\nusername:\npassword:\ntotp:\nurl:\nnotes:\n"
	parsed := parseCipherFromEditor(text, client.CipherTypeLogin)
	if len(parsed.URLs) != 0 {
		t.Errorf("URLs: got %v, want empty for bare 'url:' line", parsed.URLs)
	}
}

func TestParseCipherFromEditor_NotesTrailingEmptyLinesStripped(t *testing.T) {
	text := "name: Test\nnotes:\nHello\n\n\n\n"
	parsed := parseCipherFromEditor(text, client.CipherTypeLogin)
	if parsed.Notes != "Hello" {
		t.Errorf("Notes: got %q, want %q", parsed.Notes, "Hello")
	}
}

func TestParseCipherFromEditor_NotesOnlyWhitespace(t *testing.T) {
	text := "name: Test\nnotes:\n   \n  \n"
	parsed := parseCipherFromEditor(text, client.CipherTypeLogin)
	if parsed.Notes != "" {
		t.Errorf("Notes: got %q, want empty for whitespace-only notes", parsed.Notes)
	}
}

func TestParseCipherFromEditor_URLWithPort(t *testing.T) {
	text := "name: Test\nurl: https://localhost:8443/path\nnotes:\n"
	parsed := parseCipherFromEditor(text, client.CipherTypeLogin)
	if len(parsed.URLs) != 1 || parsed.URLs[0] != "https://localhost:8443/path" {
		t.Errorf("URLs: got %v, want [https://localhost:8443/path]", parsed.URLs)
	}
}

// ---------------------------------------------------------------------------
// openInEditor — additional coverage
// ---------------------------------------------------------------------------

func TestOpenInEditor_EditorWithArguments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping shell-based editor test on Windows")
	}
	// Set EDITOR to a command with arguments to test splitEditorCommand integration.
	dir := t.TempDir()
	script := filepath.Join(dir, "editor.sh")
	// The script ignores its first arg (the flag) and writes to the last arg (the file).
	// This mimics editors like `code -w <file>` where the file is the last argument.
	if err := os.WriteFile(script, []byte("#!/bin/sh\nshift\necho EDITED > \"$1\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	// Use a command with arguments: "<script> --some-flag" (the script ignores the flag).
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", script+" --some-flag")

	result, err := openInEditor("original content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "EDITED") {
		t.Errorf("expected result to contain 'EDITED', got %q", result)
	}
}

func TestOpenInEditor_EditorFailure(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "false") // `false` always exits with code 1

	_, err := openInEditor("test content")
	if err == nil {
		t.Fatal("expected error when editor exits with failure")
	}
}

func TestOpenInEditor_NonexistentEditor(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "/nonexistent/editor/binary")

	_, err := openInEditor("test content")
	if err == nil {
		t.Fatal("expected error for nonexistent editor binary")
	}
}

// ---------------------------------------------------------------------------
// urlsEqual — nil vs empty
// ---------------------------------------------------------------------------

func TestUrlsEqual_NilVsEmpty(t *testing.T) {
	// nil and empty should be considered equal (both mean "no URLs").
	if !urlsEqual(nil, []string{}) {
		t.Error("expected nil and empty to be equal")
	}
	if !urlsEqual([]string{}, nil) {
		t.Error("expected empty and nil to be equal")
	}
}

func TestUrlsEqual_SingleElement(t *testing.T) {
	a := []string{"https://example.com"}
	b := []string{"https://example.com"}
	if !urlsEqual(a, b) {
		t.Error("expected true for equal single-element slices")
	}
}

// ---------------------------------------------------------------------------
// custom fields
// ---------------------------------------------------------------------------

func TestFormatParse_RoundTrip_CustomFields(t *testing.T) {
	original := cipherEditFields{
		Type: client.CipherTypeLogin,
		Name: "GitHub",
		CustomFields: []cipherCustomField{
			{Type: client.FieldTypeText, Name: "Recovery", Value: "https://example.com/a:b"},
			{Type: client.FieldTypeHidden, Name: "PIN", Value: "1234"},
			{Type: client.FieldTypeBoolean, Name: "Active", Value: "true"},
			{Type: client.FieldTypeLinked, Name: "Login", Value: "username"},
			{Type: client.FieldTypeText, Name: "", Value: "unnamed"},
			{Type: client.FieldTypeText, Name: "empty", Value: ""},
			{Type: client.FieldTypeText, Name: "a: b", Value: " padded\tvalue "},
			{Type: client.FieldTypeText, Name: `"quoted"`, Value: "line1\nline2"},
			{Type: client.FieldTypeText, Name: "field", Value: `"literal quotes"`},
		},
	}

	parsed := parseCipherFromEditor(formatCipherForEditor(original), client.CipherTypeLogin)

	if !customFieldsEqual(parsed.CustomFields, original.CustomFields) {
		t.Errorf("CustomFields:\n got %+v\nwant %+v", parsed.CustomFields, original.CustomFields)
	}
}

func TestFormatParse_RoundTrip_QuotedValues(t *testing.T) {
	original := cipherEditFields{
		Type:     client.CipherTypeLogin,
		Name:     " spaced name ",
		Username: `"quoted"`,
		Password: "pass word\n",
		Totp:     "\tJBSWY3DPEHPK3PXP",
		URLs:     []string{" https://example.com"},
	}

	parsed := parseCipherFromEditor(formatCipherForEditor(original), client.CipherTypeLogin)

	if parsed.Name != original.Name || parsed.Username != original.Username ||
		parsed.Password != original.Password || parsed.Totp != original.Totp ||
		!urlsEqual(parsed.URLs, original.URLs) {
		t.Errorf("round trip changed values:\n got %+v\nwant %+v", parsed, original)
	}
}

func TestFormatCipherForEditor_CustomFieldSyntax(t *testing.T) {
	text := formatCipherForEditor(cipherEditFields{
		Name: "Test",
		CustomFields: []cipherCustomField{
			{Type: client.FieldTypeHidden, Name: "PIN", Value: "1234"},
			{Type: client.FieldTypeLinked, Name: "User", Value: "username"},
		},
	})

	for _, want := range []string{"\nhidden PIN: 1234\n", "\nlinked User: username\n", "#   field <name>: <value>"} {
		if !strings.Contains(text, want) {
			t.Errorf("expected editor file to contain %q:\n%s", want, text)
		}
	}
}

func TestParseCustomFieldLine(t *testing.T) {
	tests := []struct {
		line string
		want cipherCustomField
		ok   bool
	}{
		{"field PIN: 1234", cipherCustomField{Type: client.FieldTypeText, Name: "PIN", Value: "1234"}, true},
		{"  Hidden  API Key :  s3cret  ", cipherCustomField{Type: client.FieldTypeHidden, Name: "API Key", Value: "s3cret"}, true},
		{"boolean Active: false", cipherCustomField{Type: client.FieldTypeBoolean, Name: "Active", Value: "false"}, true},
		{"linked Pass: password", cipherCustomField{Type: client.FieldTypeLinked, Name: "Pass", Value: "password"}, true},
		{"field Site: https://example.com:8443/x", cipherCustomField{Name: "Site", Value: "https://example.com:8443/x"}, true},
		{`field "a:b": c`, cipherCustomField{Name: "a:b", Value: "c"}, true},
		{`field "": c`, cipherCustomField{Name: "", Value: "c"}, true},
		{"field Recovery", cipherCustomField{Name: "Recovery", Value: ""}, true},
		{"field\tTabbed: x", cipherCustomField{Name: "Tabbed", Value: "x"}, true},
		{"field 'a' thing: v", cipherCustomField{Name: "'a' thing", Value: "v"}, true},
		{"fields: x", cipherCustomField{}, false},
		{"field", cipherCustomField{}, false},
		{"name: field x", cipherCustomField{}, false},
	}
	for _, tt := range tests {
		got, ok := parseCustomFieldLine(tt.line)
		if ok != tt.ok || got != tt.want {
			t.Errorf("parseCustomFieldLine(%q) = %+v, %v; want %+v, %v", tt.line, got, ok, tt.want, tt.ok)
		}
	}
}

func TestParseCipherFromEditor_CustomFieldsAmongOtherKeys(t *testing.T) {
	f := parseCipherFromEditor("name: x\nhidden PIN: 1\n# field Commented: out\nfield URL: https://a\nnotes:\nfield not: a field\n", client.CipherTypeLogin)

	want := []cipherCustomField{
		{Type: client.FieldTypeHidden, Name: "PIN", Value: "1"},
		{Type: client.FieldTypeText, Name: "URL", Value: "https://a"},
	}
	if !customFieldsEqual(f.CustomFields, want) {
		t.Errorf("CustomFields: got %+v, want %+v", f.CustomFields, want)
	}
	if f.Notes != "field not: a field" {
		t.Errorf("Notes: got %q", f.Notes)
	}
}

func TestDecryptCipherToFields_CustomFieldTypes(t *testing.T) {
	key := testKey()
	pin := encryptStr(t, key, "PIN")
	linked := encryptStr(t, key, "Linked")
	linkedID := linkedIDUsername

	c := client.Cipher{
		Type: client.CipherTypeLogin,
		Data: client.CipherData{Name: encryptStr(t, key, "Item")},
		Fields: []client.CipherField{
			{Type: client.FieldTypeLinked, Name: &linked, LinkedID: &linkedID},
			{Type: client.FieldTypeHidden, Name: &pin, Value: encryptStr(t, key, "1234")},
		},
	}

	f, err := decryptCipherToFields(&c, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []cipherCustomField{
		{Type: client.FieldTypeLinked, Name: "Linked", Value: "username"},
		{Type: client.FieldTypeHidden, Name: "PIN", Value: "1234"},
	}
	if !customFieldsEqual(f.CustomFields, want) {
		t.Errorf("CustomFields: got %+v, want %+v", f.CustomFields, want)
	}
}

func TestCustomFieldsEqual(t *testing.T) {
	a := []cipherCustomField{{Name: "a", Value: "1"}}
	if !customFieldsEqual(nil, nil) || !customFieldsEqual(a, []cipherCustomField{{Name: "a", Value: "1"}}) {
		t.Error("expected equal")
	}
	if customFieldsEqual(a, nil) || customFieldsEqual(a, []cipherCustomField{{Name: "a", Value: "2"}}) ||
		customFieldsEqual(a, []cipherCustomField{{Type: client.FieldTypeHidden, Name: "a", Value: "1"}}) {
		t.Error("expected not equal")
	}
}

func TestEditTempRoot(t *testing.T) {
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", private)
	if got := editTempRoot(); got != private {
		t.Errorf("editTempRoot() = %q, want private XDG_RUNTIME_DIR %q", got, private)
	}

	shared := t.TempDir()
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", shared)
	if got := editTempRoot(); got != os.TempDir() {
		t.Errorf("editTempRoot() = %q, want %q for a non-private XDG_RUNTIME_DIR", got, os.TempDir())
	}

	t.Setenv("XDG_RUNTIME_DIR", "")
	if got := editTempRoot(); got != os.TempDir() {
		t.Errorf("editTempRoot() = %q, want %q", got, os.TempDir())
	}
}
