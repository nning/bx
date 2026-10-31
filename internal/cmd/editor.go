package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
)

// editorCommand returns the editor command string for interactive editing.
// It checks $VISUAL, then $EDITOR, then falls back to "vi".
func editorCommand() string {
	if v := os.Getenv("VISUAL"); v != "" {
		return v
	}
	if v := os.Getenv("EDITOR"); v != "" {
		return v
	}
	return "vi"
}

// splitEditorCommand splits an editor command string into argv, handling
// simple quoting so that settings like `code -w` or `"my editor" --flag`
// work correctly.  It does not support escape sequences; for complex cases
// the user can wrap their editor in a script.
func splitEditorCommand(cmd string) []string {
	var args []string
	var current strings.Builder
	inSingle := false
	inDouble := false

	for _, r := range cmd {
		switch {
		case r == '\'' && !inDouble:
			inSingle = !inSingle
		case r == '"' && !inSingle:
			inDouble = !inDouble
		case r == ' ' && !inSingle && !inDouble:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}

	if len(args) == 0 {
		return []string{"vi"}
	}
	return args
}

// cipherEditFields holds the decrypted, human-readable fields of a cipher
// that are presented to the user in the interactive editor.  Type is the
// cipher's item type: it selects which fields are shown and parsed.  For
// non-login types with their own object (card, identity, sshKey), TypeFields
// holds the decrypted fields keyed by their JSON field name.
type cipherEditFields struct {
	Type         int
	Name         string
	Username     string
	Password     string
	Totp         string
	URLs         []string
	Notes        string
	CustomFields []cipherCustomField
	TypeFields   map[string]string
}

// cipherCustomField is a decrypted custom field.  Type is one of the
// client.FieldType* constants; for linked fields Value names the login field
// the custom field points to ("username" or "password").
type cipherCustomField struct {
	Type  int
	Name  string
	Value string
}

// customFieldKeywords maps the editor keyword that starts a custom field line
// to the field type, in the order they are documented.
var customFieldKeywords = []struct {
	keyword string
	typ     int
}{
	{"field", client.FieldTypeText},
	{"hidden", client.FieldTypeHidden},
	{"boolean", client.FieldTypeBoolean},
	{"linked", client.FieldTypeLinked},
}

// customFieldKeyword returns the editor keyword for a field type.  Types bx
// does not know are shown as text fields.
func customFieldKeyword(typ int) string {
	for _, k := range customFieldKeywords {
		if k.typ == typ {
			return k.keyword
		}
	}
	return "field"
}

// quoteEditorValue returns s as it is written to the editor file.  Values that
// would not survive the line-based format unchanged — leading or trailing
// whitespace, line breaks, or a leading '"' — are written as a Go-syntax
// quoted string.
func quoteEditorValue(s string) string {
	if s != strings.TrimSpace(s) || strings.HasPrefix(s, `"`) || strings.ContainsAny(s, "\r\n") {
		return strconv.Quote(s)
	}
	return s
}

// quoteEditorName is quoteEditorValue for custom field names, which are also
// quoted when empty or when they contain the ':' that ends them.
func quoteEditorName(s string) string {
	if s == "" || strings.Contains(s, ":") {
		return strconv.Quote(s)
	}
	return quoteEditorValue(s)
}

// unquoteEditorValue reverses quoteEditorValue.  A value that starts with '"'
// but is not a valid quoted string is taken literally.
func unquoteEditorValue(s string) string {
	if strings.HasPrefix(s, `"`) {
		if u, err := strconv.Unquote(s); err == nil {
			return u
		}
	}
	return s
}

// formatCipherForEditor renders a cipherEditFields into the text format that
// is written to the temporary file.  Lines starting with "# " are comments
// and are ignored when the file is parsed back.  Login items show their login
// fields; other item types show the fields of their type object.
func formatCipherForEditor(f cipherEditFields) string {
	var b strings.Builder
	b.WriteString("# Edit this file and save to update the vault item.\n")
	b.WriteString("# Lines starting with '#' before 'notes:' are comments and will be ignored;\n")
	b.WriteString("# inside notes, '#' is treated as normal text.\n")
	b.WriteString("# To clear a field, delete its value (leave just the key and colon).\n")
	b.WriteString("# The 'notes' field starts after 'notes:' and extends to the end of the file.\n")
	b.WriteString("#\n")
	b.WriteString("# Custom fields, one per line; add or delete lines to add or remove fields:\n")
	b.WriteString("#   field <name>: <value>          text field\n")
	b.WriteString("#   hidden <name>: <value>         hidden field\n")
	b.WriteString("#   boolean <name>: true|false     checkbox\n")
	b.WriteString("#   linked <name>: username|password\n")
	b.WriteString("# Values with leading or trailing spaces, line breaks, or a leading '\"' are\n")
	b.WriteString("# written as \"quoted\" strings with \\n, \\t, and \\\" escapes; so are field names\n")
	b.WriteString("# that are empty or contain ':'.\n")
	b.WriteString("#\n")

	b.WriteString("name: " + quoteEditorValue(f.Name) + "\n")

	if f.Type == client.CipherTypeLogin {
		b.WriteString("username: " + quoteEditorValue(f.Username) + "\n")
		b.WriteString("password: " + quoteEditorValue(f.Password) + "\n")
		b.WriteString("totp: " + quoteEditorValue(f.Totp) + "\n")
		for _, u := range f.URLs {
			b.WriteString("url: " + quoteEditorValue(u) + "\n")
		}
		if len(f.URLs) == 0 {
			b.WriteString("url:\n")
		}
	} else if spec, ok := typeSpecs[f.Type]; ok {
		b.WriteString("# Fields of this " + spec.obj + " item:\n")
		for _, fs := range spec.fields {
			key := editorTypeKey(fs)
			b.WriteString(key + ": " + quoteEditorValue(f.TypeFields[fs.json]) + "\n")
		}
	}

	for _, cf := range f.CustomFields {
		b.WriteString(customFieldKeyword(cf.Type) + " " + quoteEditorName(cf.Name) + ": " + quoteEditorValue(cf.Value) + "\n")
	}
	b.WriteString("notes:\n")
	if f.Notes != "" {
		b.WriteString(f.Notes)
		if !strings.HasSuffix(f.Notes, "\n") {
			b.WriteString("\n")
		}
	}
	return b.String()
}

// parseCipherFromEditor parses the text produced by the interactive editor
// back into a cipherEditFields for an item of the given type.  Comment lines
// (starting with '#') are stripped. Everything after the first "notes:" line
// is treated as the notes field.
func parseCipherFromEditor(text string, cipherType int) cipherEditFields {
	f := cipherEditFields{Type: cipherType}
	if spec, ok := typeSpecs[cipherType]; ok {
		f.TypeFields = map[string]string{}
		for _, fs := range spec.fields {
			f.TypeFields[fs.json] = ""
		}
	}
	lines := strings.Split(text, "\n")

	inNotes := false
	var notesLines []string
	for _, line := range lines {
		// Normalize CRLF: strip trailing \r that Windows editors may add.
		line = strings.TrimRight(line, "\r")

		if inNotes {
			notesLines = append(notesLines, line)
			continue
		}

		// Skip comment lines.
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		if cf, ok := parseCustomFieldLine(line); ok {
			f.CustomFields = append(f.CustomFields, cf)
			continue
		}

		key, val, ok := parseKV(line)
		if !ok {
			continue
		}

		// A key that belongs to the item's type object takes priority over the
		// login keys (identity items carry a username of their own).
		if f.TypeFields != nil {
			if fs, ok := matchTypeFieldSpec(key, cipherType); ok {
				f.TypeFields[fs.json] = unquoteEditorValue(val)
				continue
			}
		}

		switch key {
		case "name":
			f.Name = unquoteEditorValue(val)
		case "username":
			f.Username = unquoteEditorValue(val)
		case "password":
			f.Password = unquoteEditorValue(val)
		case "totp":
			f.Totp = unquoteEditorValue(val)
		case "url":
			if val != "" {
				f.URLs = append(f.URLs, unquoteEditorValue(val))
			}
		case "notes":
			inNotes = true
			// If the notes: line itself has a value, include it as the first line.
			if val != "" {
				notesLines = append(notesLines, val)
			}
		}
	}

	// Trim trailing empty lines from notes, then join.
	for len(notesLines) > 0 && strings.TrimSpace(notesLines[len(notesLines)-1]) == "" {
		notesLines = notesLines[:len(notesLines)-1]
	}
	f.Notes = strings.Join(notesLines, "\n")

	return f
}

// matchTypeFieldSpec matches a lower-cased editor key against the fields of
// the item's type object.
func matchTypeFieldSpec(keyLower string, cipherType int) (typeFieldSpec, bool) {
	spec, ok := typeSpecs[cipherType]
	if !ok {
		return typeFieldSpec{}, false
	}
	for _, f := range spec.fields {
		if matchTypeField(keyLower, f) {
			return f, true
		}
	}
	return typeFieldSpec{}, false
}

// parseCustomFieldLine parses a custom field line such as "hidden PIN: 1234"
// (see customFieldKeywords).  The keyword is case-insensitive; the name runs to
// the first ':' unless it is quoted.  A line without ':' is a field with an
// empty value.  It reports false for lines that are not custom field lines.
func parseCustomFieldLine(line string) (cipherCustomField, bool) {
	line = strings.TrimSpace(line)
	for _, k := range customFieldKeywords {
		if len(line) <= len(k.keyword) || !strings.EqualFold(line[:len(k.keyword)], k.keyword) {
			continue
		}
		rest := line[len(k.keyword):]
		if rest[0] != ' ' && rest[0] != '\t' {
			continue
		}
		rest = strings.TrimSpace(rest)

		var name string
		if q, err := strconv.QuotedPrefix(rest); err == nil && rest[0] == '"' {
			name, _ = strconv.Unquote(q)
			rest = strings.TrimSpace(rest[len(q):])
			rest = strings.TrimPrefix(rest, ":")
		} else {
			var found bool
			name, rest, found = strings.Cut(rest, ":")
			name = strings.TrimSpace(name)
			if !found {
				rest = ""
			}
		}
		return cipherCustomField{Type: k.typ, Name: name, Value: unquoteEditorValue(strings.TrimSpace(rest))}, true
	}
	return cipherCustomField{}, false
}

// parseKV splits "key: value" and returns (key, value, true).
// Returns ("", "", false) if the line is empty or has no colon.
func parseKV(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", false
	}
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:idx])
	val := strings.TrimSpace(line[idx+1:])
	return strings.ToLower(key), val, true
}

// decryptCipherToFields decrypts the relevant fields of a cipher and returns
// them as a cipherEditFields ready for the interactive editor.
func decryptCipherToFields(c *client.Cipher, key []byte) (cipherEditFields, error) {
	f := cipherEditFields{Type: c.Type}

	nameBytes, err := crypto.Decrypt(cipherName(c), key)
	if err != nil {
		return f, fmt.Errorf("failed to decrypt name: %w", err)
	}
	f.Name = string(nameBytes)

	// Non-login types with their own object: decrypt every type field.  Login
	// fields are only decrypted for login items.
	if _, ok := typeSpecs[c.Type]; ok {
		typeFields, err := decryptTypeFields(c, key)
		if err != nil {
			return f, err
		}
		f.TypeFields = typeFields
	} else {
		if u := cipherUsername(c); u != "" {
			userBytes, err := crypto.Decrypt(u, key)
			if err != nil {
				return f, fmt.Errorf("failed to decrypt username: %w", err)
			}
			f.Username = string(userBytes)
		}

		if p := cipherPassword(c); p != "" {
			passBytes, err := crypto.Decrypt(p, key)
			if err != nil {
				return f, fmt.Errorf("failed to decrypt password: %w", err)
			}
			f.Password = string(passBytes)
		}

		if totpField := cipherTotp(c); totpField != nil && *totpField != "" {
			totpBytes, err := crypto.Decrypt(*totpField, key)
			if err != nil {
				return f, fmt.Errorf("failed to decrypt TOTP: %w", err)
			}
			f.Totp = string(totpBytes)
		}

		for _, u := range cipherURIs(c) {
			uriBytes, err := crypto.Decrypt(u.URI, key)
			if err != nil {
				return f, fmt.Errorf("failed to decrypt URI: %w", err)
			}
			if len(uriBytes) > 0 {
				f.URLs = append(f.URLs, string(uriBytes))
			}
		}
	}

	// Every custom field is shown, including ones without a value (e.g.
	// linked fields): a field missing from the editor would be deleted.
	for _, cf := range cipherCustomFields(c) {
		field, err := decodeCustomField(cf, key)
		if err != nil {
			return f, err
		}
		f.CustomFields = append(f.CustomFields, field)
	}

	if notes := cipherNotes(c); notes != nil && *notes != "" {
		notesBytes, err := crypto.Decrypt(*notes, key)
		if err != nil {
			return f, fmt.Errorf("failed to decrypt notes: %w", err)
		}
		f.Notes = string(notesBytes)
	}

	return f, nil
}

// openInEditor creates a secure temporary file with the provided content,
// opens the user's editor, reads the result, and securely wipes and removes
// the temporary file.  It returns the edited content.
func openInEditor(content string) (string, error) {
	// Create a private temp directory (0700) to hold the file.
	tmpDir, err := os.MkdirTemp(editTempRoot(), "bx-edit-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tmpPath := filepath.Join(tmpDir, "entry.txt")
	if err := os.WriteFile(tmpPath, []byte(content), 0600); err != nil {
		return "", fmt.Errorf("failed to write temp file: %w", err)
	}
	defer secureWipe(tmpPath)

	editorArgs := splitEditorCommand(editorCommand())
	editorArgs = append(editorArgs, tmpPath)
	//nolint:gosec // editor is intentionally user-controlled via $VISUAL/$EDITOR
	cmd := exec.Command(editorArgs[0], editorArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("editor exited with error: %w", err)
	}

	result, err := os.ReadFile(tmpPath)
	if err != nil {
		return "", fmt.Errorf("failed to read edited file: %w", err)
	}

	return string(result), nil
}

// editTempRoot returns the directory under which the decrypted item is placed
// for editing.  $XDG_RUNTIME_DIR is preferred: on Linux it is a per-user
// tmpfs, so the plaintext never reaches a disk at all.  Elsewhere the system
// temp directory is used.
func editTempRoot() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() && fi.Mode().Perm()&0o077 == 0 {
			return dir
		}
	}
	return os.TempDir()
}

// secureWipe overwrites the file at path with zeros before removing it, to
// reduce the window during which sensitive data is recoverable on disk.
//
// This is best-effort only.  On SSDs (wear levelling), copy-on-write file
// systems such as Btrfs and ZFS, and journalling or snapshotting storage the
// zeros may land in different blocks than the original data, which then
// stays recoverable.  Editors may also write swap or backup files of their
// own.  editTempRoot avoids the disk entirely where a tmpfs is available.
func secureWipe(path string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	// Refuse to follow symlinks.
	if info.Mode()&os.ModeSymlink != 0 {
		return
	}
	size := info.Size()
	if size <= 0 {
		_ = os.Remove(path)
		return
	}

	// Overwrite the file in fixed-size chunks to avoid large allocations.
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		_ = os.Remove(path)
		return
	}

	const chunkSize = 64 * 1024 // 64 KiB
	zeros := make([]byte, chunkSize)

	remaining := size
	for remaining > 0 {
		toWrite := int64(chunkSize)
		if remaining < toWrite {
			toWrite = remaining
		}
		if _, err := f.Write(zeros[:toWrite]); err != nil {
			break
		}
		remaining -= toWrite
	}
	_ = f.Sync()
	_ = f.Close()
	_ = os.Remove(path)
}
