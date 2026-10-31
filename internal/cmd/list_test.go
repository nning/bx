package cmd

import (
	"testing"

	"github.com/nning/bx/internal/client"
)

// ---------------------------------------------------------------------------
// sortListRows
// ---------------------------------------------------------------------------

// TestSortListRows_CaseInsensitiveOrder verifies that rows are sorted
// alphabetically regardless of the case of each name.
func TestSortListRows_CaseInsensitiveOrder(t *testing.T) {
	rows := []listRow{
		{id: "c", name: "azure", lowerName: "azure"},
		{id: "a", name: "Apple", lowerName: "apple"},
		{id: "b", name: "amazon", lowerName: "amazon"},
	}
	sortListRows(rows)
	want := []string{"amazon", "Apple", "azure"}
	for i, r := range rows {
		if r.name != want[i] {
			t.Errorf("rows[%d].name = %q, want %q", i, r.name, want[i])
		}
	}
}

// TestSortListRows_TieBreakByOriginalName verifies that when two entries have
// the same lowercased name, the one that sorts earlier lexicographically by
// original name comes first.
func TestSortListRows_TieBreakByOriginalName(t *testing.T) {
	rows := []listRow{
		{id: "x", name: "github", lowerName: "github"},
		{id: "y", name: "GitHub", lowerName: "github"},
	}
	sortListRows(rows)
	// "GitHub" < "github" in ASCII (uppercase letters precede lowercase).
	if rows[0].name != "GitHub" {
		t.Errorf("rows[0].name = %q, want %q", rows[0].name, "GitHub")
	}
	if rows[1].name != "github" {
		t.Errorf("rows[1].name = %q, want %q", rows[1].name, "github")
	}
}

// TestSortListRows_TieBreakByID verifies that when both lowerName and name are
// identical the row with the lexicographically smaller id comes first, ensuring
// fully deterministic output.
func TestSortListRows_TieBreakByID(t *testing.T) {
	rows := []listRow{
		{id: "zzz", name: "GitHub", lowerName: "github"},
		{id: "aaa", name: "GitHub", lowerName: "github"},
	}
	sortListRows(rows)
	if rows[0].id != "aaa" {
		t.Errorf("rows[0].id = %q, want %q", rows[0].id, "aaa")
	}
	if rows[1].id != "zzz" {
		t.Errorf("rows[1].id = %q, want %q", rows[1].id, "zzz")
	}
}

// TestSortListRows_StablePreservesRelativeOrder verifies that rows whose sort
// keys are all equal keep their original relative order (stable sort guarantee).
func TestSortListRows_StablePreservesRelativeOrder(t *testing.T) {
	rows := []listRow{
		{id: "same", name: "Same", lowerName: "same", username: "first"},
		{id: "same", name: "Same", lowerName: "same", username: "second"},
	}
	sortListRows(rows)
	if rows[0].username != "first" || rows[1].username != "second" {
		t.Error("stable sort should preserve original order for equal keys")
	}
}

// TestSortListRows_Empty verifies that sorting an empty slice does not panic.
func TestSortListRows_Empty(t *testing.T) {
	sortListRows(nil)
	sortListRows([]listRow{})
}

// TestCipherMatchesPattern_EmptyPatternAlwaysMatches verifies that an empty
// pattern always includes the cipher regardless of its name or URIs.
func TestCipherMatchesPattern_EmptyPatternAlwaysMatches(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "id-1", "GitHub", "https://github.com", key)
	if !cipherMatchesPattern("github", "", &c, key, "") {
		t.Error("expected empty pattern to always match")
	}
}

// TestCipherMatchesPattern_NameMatch verifies that a cipher is included when
// the decrypted name contains the pattern (case-insensitive).
func TestCipherMatchesPattern_NameMatch(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "id-1", "GitHub", "", key)
	if !cipherMatchesPattern("github", "", &c, key, "github") {
		t.Error("expected name match to return true")
	}
}

// TestCipherMatchesPattern_NameNoMatchURIMatch verifies that a cipher is
// included when the name does not match but one of its URIs does.
// This is the core fix: `bx list github.com` should find items whose URI
// contains "github.com" even when the item is named "GitHub".
func TestCipherMatchesPattern_NameNoMatchURIMatch(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "id-1", "GitHub", "https://github.com", key)
	if !cipherMatchesPattern("github", "", &c, key, "github.com") {
		t.Error("expected URI fallback match to return true when name does not match")
	}
}

// TestCipherMatchesPattern_NoMatch verifies that a cipher is excluded when
// neither its name nor its URIs contain the pattern.
func TestCipherMatchesPattern_NoMatch(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "id-1", "Google", "https://google.com", key)
	if cipherMatchesPattern("google", "", &c, key, "github") {
		t.Error("expected no match to return false")
	}
}

// TestCipherMatchesPattern_NoURIs verifies that a cipher with no URIs and a
// non-matching name is excluded.
func TestCipherMatchesPattern_NoURIs(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "id-1", "Google", "", key)
	if cipherMatchesPattern("google", "", &c, key, "github.com") {
		t.Error("expected false for cipher with no URIs and non-matching name")
	}
}

// TestCipherMatchesPattern_LoginURIsTakePriority verifies that Login.URIs are
// preferred over Data.URIs (consistent with cipherURIs helper used elsewhere).
func TestCipherMatchesPattern_LoginURIsTakePriority(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "id-1", "MyAccount", "https://google.com", key) // Data.URIs = google.com
	// Add Login.URIs pointing to github.com; Login.URIs should take priority.
	c.Login = &client.CipherLogin{
		URIs: []client.CipherURI{{URI: encryptStr(t, key, "https://github.com")}},
	}
	// Pattern matches Login.URIs but not Data.URIs or name.
	if !cipherMatchesPattern("myaccount", "", &c, key, "github.com") {
		t.Error("expected Login.URIs to take priority and match github.com")
	}
	// Pattern matches Data.URIs but Login.URIs shadow them.
	if cipherMatchesPattern("myaccount", "", &c, key, "google.com") {
		t.Error("expected Data.URIs to be shadowed by Login.URIs")
	}
}

// TestCipherMatchesPattern_UsernameMatch verifies that a cipher is included
// when the decrypted username contains the pattern.
func TestCipherMatchesPattern_UsernameMatch(t *testing.T) {
	key := testKey()
	c := makeCipherWithUsername(t, "id-1", "GitHub", "alice@example.com", "https://github.com", key)
	if !cipherMatchesPattern("github", "alice@example.com", &c, key, "alice@example.com") {
		t.Error("expected username match to return true")
	}
}

// TestCipherMatchesPattern_UsernameNoMatch verifies that a cipher is excluded
// when neither name, username, nor URIs match the pattern.
func TestCipherMatchesPattern_UsernameNoMatch(t *testing.T) {
	key := testKey()
	c := makeCipherWithUsername(t, "id-1", "GitHub", "alice@example.com", "https://github.com", key)
	if cipherMatchesPattern("github", "alice@example.com", &c, key, "someone@else.com") {
		t.Error("expected no match to return false")
	}
}

// TestCipherMatchesPattern_UsernameSubstringMatch verifies that a cipher is
// included when the pattern is a substring of the decrypted username.
func TestCipherMatchesPattern_UsernameSubstringMatch(t *testing.T) {
	key := testKey()
	c := makeCipherWithUsername(t, "id-1", "Service", "alice@example.com", "", key)
	if !cipherMatchesPattern("service", "alice@example.com", &c, key, "alice@") {
		t.Error("expected username substring match to return true")
	}
}

// TestCipherMatchesPattern_UsernameCaseInsensitive verifies that username
// matching is case-insensitive.
func TestCipherMatchesPattern_UsernameCaseInsensitive(t *testing.T) {
	key := testKey()
	c := makeCipherWithUsername(t, "id-1", "Service", "Admin@Example.COM", "", key)
	if !cipherMatchesPattern("service", "admin@example.com", &c, key, "admin@example.com") {
		t.Error("expected case-insensitive username match to return true")
	}
}

// TestCipherMatchesPattern_UsernameOnlyMatch verifies that a cipher is included
// when only the username matches (not name or URI).
func TestCipherMatchesPattern_UsernameOnlyMatch(t *testing.T) {
	key := testKey()
	c := makeCipherWithUsername(t, "id-1", "My Service", "admin@corp.com", "https://internal.corp.net", key)
	// Pattern matches only the username, not the name ("My Service") or URI.
	if !cipherMatchesPattern("my service", "admin@corp.com", &c, key, "admin@corp") {
		t.Error("expected match when only username matches the pattern")
	}
}

// TestCipherMatchesPattern_EmptyUsername verifies that a cipher with no
// username still matches by name or URI (username check is safely skipped).
func TestCipherMatchesPattern_EmptyUsername(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "id-1", "GitHub", "https://github.com", key)
	// Should match by name even though username is empty.
	if !cipherMatchesPattern("github", "", &c, key, "github") {
		t.Error("expected name match even with empty username")
	}
	// Should match by URI even though username is empty.
	if !cipherMatchesPattern("github", "", &c, key, "github.com") {
		t.Error("expected URI match even with empty username")
	}
}

// TestCipherMatchesPattern_NameMatchTakesPriority verifies that when both
// name and username would match, the function returns true (name is checked
// first, so the result is the same either way).
func TestCipherMatchesPattern_NameMatchTakesPriority(t *testing.T) {
	key := testKey()
	c := makeCipherWithUsername(t, "id-1", "admin portal", "admin@example.com", "", key)
	// Pattern "admin" matches both name and username.
	if !cipherMatchesPattern("admin portal", "admin@example.com", &c, key, "admin") {
		t.Error("expected match when both name and username contain pattern")
	}
}
