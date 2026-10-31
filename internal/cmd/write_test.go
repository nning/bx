package cmd

import (
	"testing"

	"github.com/nning/bx/internal/client"
)

// ---------------------------------------------------------------------------
// cipherTypeFromString
// ---------------------------------------------------------------------------

func TestCipherTypeFromString_Login(t *testing.T) {
	typ, err := cipherTypeFromString("login")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if typ != 1 {
		t.Errorf("got %d, want 1", typ)
	}
}

func TestCipherTypeFromString_Note(t *testing.T) {
	typ, err := cipherTypeFromString("note")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if typ != client.CipherTypeNote {
		t.Errorf("got %d, want %d", typ, client.CipherTypeNote)
	}
}

func TestCipherTypeFromString_Card(t *testing.T) {
	typ, err := cipherTypeFromString("card")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if typ != client.CipherTypeCard {
		t.Errorf("got %d, want %d", typ, client.CipherTypeCard)
	}
}

func TestCipherTypeFromString_Identity(t *testing.T) {
	typ, err := cipherTypeFromString("identity")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if typ != client.CipherTypeIdentity {
		t.Errorf("got %d, want %d", typ, client.CipherTypeIdentity)
	}
}

func TestCipherTypeFromString_SshKey(t *testing.T) {
	typ, err := cipherTypeFromString("ssh-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if typ != client.CipherTypeSshKey {
		t.Errorf("got %d, want %d", typ, client.CipherTypeSshKey)
	}
}

func TestCipherTypeFromString_Unknown(t *testing.T) {
	_, err := cipherTypeFromString("unknown")
	if err == nil {
		t.Error("expected error for unknown type, got nil")
	}
}

func TestCipherTypeFromString_Typo(t *testing.T) {
	// A common typo should return an error, not silently create a login item.
	_, err := cipherTypeFromString("loign")
	if err == nil {
		t.Error("expected error for typo, got nil")
	}
}

// ---------------------------------------------------------------------------
// findFolderID
// ---------------------------------------------------------------------------

// makeFolder builds a test folder with an encrypted name.
func makeFolder(t *testing.T, id, name string, key []byte) client.Folder {
	t.Helper()
	return client.Folder{
		ID:   id,
		Name: encryptStr(t, key, name),
	}
}

func TestFindFolderID_ByID(t *testing.T) {
	key := testKey()
	folders := []client.Folder{
		makeFolder(t, "folder-1", "Personal", key),
		makeFolder(t, "folder-2", "Work", key),
	}
	got, err := findFolderID("folder-1", folders, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "folder-1" {
		t.Errorf("got %q, want %q", got, "folder-1")
	}
}

func TestFindFolderID_ByNameExact(t *testing.T) {
	key := testKey()
	folders := []client.Folder{
		makeFolder(t, "folder-1", "Personal", key),
		makeFolder(t, "folder-2", "Work", key),
	}
	got, err := findFolderID("Work", folders, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "folder-2" {
		t.Errorf("got %q, want %q", got, "folder-2")
	}
}

func TestFindFolderID_ByNameCaseInsensitive(t *testing.T) {
	key := testKey()
	folders := []client.Folder{
		makeFolder(t, "folder-1", "Personal", key),
	}
	got, err := findFolderID("personal", folders, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "folder-1" {
		t.Errorf("got %q, want %q", got, "folder-1")
	}
}

func TestFindFolderID_NotFound(t *testing.T) {
	key := testKey()
	folders := []client.Folder{
		makeFolder(t, "folder-1", "Personal", key),
	}
	got, err := findFolderID("NonExistent", folders, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestFindFolderID_EmptyList(t *testing.T) {
	key := testKey()
	got, err := findFolderID("Personal", nil, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestFindFolderID_SkipsDecryptionError(t *testing.T) {
	key := testKey()
	// A folder with an invalid cipher string should be skipped, not panic.
	folders := []client.Folder{
		{ID: "bad-folder", Name: "not-valid-cipher-string"},
		makeFolder(t, "folder-1", "Personal", key),
	}
	got, err := findFolderID("Personal", folders, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "folder-1" {
		t.Errorf("got %q, want %q", got, "folder-1")
	}
}

func TestFindFolderID_ByShortID(t *testing.T) {
	key := testKey()
	folders := []client.Folder{
		makeFolder(t, "550e8400-e29b-41d4-a716-446655440000", "Personal", key),
		makeFolder(t, "abcdef12-0000-0000-0000-000000000000", "Work", key),
	}
	got, err := findFolderID("550e8400", folders, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("got %q, want full UUID", got)
	}
}

// TestFindFolderID_AmbiguousShortID verifies that an error is returned when
// multiple folders share the same first UUID segment.
func TestFindFolderID_AmbiguousShortID(t *testing.T) {
	key := testKey()
	folders := []client.Folder{
		makeFolder(t, "550e8400-aaaa-0000-0000-000000000000", "Personal", key),
		makeFolder(t, "550e8400-bbbb-0000-0000-000000000000", "Work", key),
	}
	got, err := findFolderID("550e8400", folders, key)
	if err == nil {
		t.Fatal("expected error for ambiguous short ID, got nil")
	}
	if got != "" {
		t.Errorf("expected empty string for ambiguous short ID, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// findFolder
// ---------------------------------------------------------------------------

func TestFindFolder_ByID(t *testing.T) {
	key := testKey()
	folders := []client.Folder{
		makeFolder(t, "folder-1", "Personal", key),
		makeFolder(t, "folder-2", "Work", key),
	}
	got, err := findFolder("folder-2", folders, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected folder, got nil")
	}
	if got.ID != "folder-2" {
		t.Errorf("got ID %q, want %q", got.ID, "folder-2")
	}
}

func TestFindFolder_ByNameExact(t *testing.T) {
	key := testKey()
	folders := []client.Folder{
		makeFolder(t, "folder-1", "Personal", key),
	}
	got, err := findFolder("Personal", folders, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected folder, got nil")
	}
	if got.ID != "folder-1" {
		t.Errorf("got ID %q, want %q", got.ID, "folder-1")
	}
}

func TestFindFolder_ByNameCaseInsensitive(t *testing.T) {
	key := testKey()
	folders := []client.Folder{
		makeFolder(t, "folder-1", "Personal", key),
	}
	got, err := findFolder("personal", folders, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected folder for case-insensitive name match, got nil")
	}
	if got.ID != "folder-1" {
		t.Errorf("got ID %q, want %q", got.ID, "folder-1")
	}
}

func TestFindFolder_NotFound(t *testing.T) {
	key := testKey()
	folders := []client.Folder{
		makeFolder(t, "folder-1", "Personal", key),
	}
	got, err := findFolder("NonExistent", folders, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestFindFolder_EmptyList(t *testing.T) {
	key := testKey()
	got, err := findFolder("anything", nil, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for empty list, got %+v", got)
	}
}

func TestFindFolder_SkipsDecryptionError(t *testing.T) {
	key := testKey()
	// A folder with invalid cipher string should be skipped gracefully.
	folders := []client.Folder{
		{ID: "bad-folder", Name: "not-valid-cipher-string"},
		makeFolder(t, "folder-1", "Personal", key),
	}
	got, err := findFolder("Personal", folders, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected folder, got nil")
	}
	if got.ID != "folder-1" {
		t.Errorf("got ID %q, want %q", got.ID, "folder-1")
	}
}

func TestFindFolder_ByShortID(t *testing.T) {
	key := testKey()
	folders := []client.Folder{
		makeFolder(t, "550e8400-e29b-41d4-a716-446655440000", "Personal", key),
		makeFolder(t, "abcdef12-0000-0000-0000-000000000000", "Work", key),
	}
	got, err := findFolder("550e8400", folders, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected folder via short ID, got nil")
	}
	if got.ID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("got ID %q, want full UUID", got.ID)
	}
}

// TestFindFolder_AmbiguousShortID verifies that an error is returned when
// multiple folders share the same first UUID segment.
func TestFindFolder_AmbiguousShortID(t *testing.T) {
	key := testKey()
	folders := []client.Folder{
		makeFolder(t, "550e8400-aaaa-0000-0000-000000000000", "Personal", key),
		makeFolder(t, "550e8400-bbbb-0000-0000-000000000000", "Work", key),
	}
	got, err := findFolder("550e8400", folders, key)
	if err == nil {
		t.Fatal("expected error for ambiguous short ID, got nil")
	}
	if got != nil {
		t.Errorf("expected nil folder for ambiguous short ID, got %+v", got)
	}
}

// ---------------------------------------------------------------------------
// findDeletedCipher
// ---------------------------------------------------------------------------

// makeDeletedCipher creates a cipher with DeletedDate set.
func makeDeletedCipher(t *testing.T, id, name string, key []byte) client.Cipher {
	t.Helper()
	c := makeCipher(t, id, name, "", key)
	d := "2000-03-01T00:00:00Z"
	c.DeletedDate = &d
	return c
}

func TestFindDeletedCipher_ByID(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeDeletedCipher(t, "trash-1", "OldEntry", key),
		makeDeletedCipher(t, "trash-2", "AnotherOld", key),
	}
	got, err := findDeletedCipher("trash-1", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher, got nil")
	}
	if got.ID != "trash-1" {
		t.Errorf("got ID %q, want %q", got.ID, "trash-1")
	}
}

func TestFindDeletedCipher_ByNameSubstring(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeDeletedCipher(t, "trash-1", "OldGitHub", key),
	}
	got, err := findDeletedCipher("github", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher by substring name match, got nil")
	}
	if got.ID != "trash-1" {
		t.Errorf("got ID %q, want %q", got.ID, "trash-1")
	}
}

func TestFindDeletedCipher_ByNameCaseInsensitive(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeDeletedCipher(t, "trash-1", "OldEntry", key),
	}
	got, err := findDeletedCipher("OLDENTRY", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher by case-insensitive name match, got nil")
	}
}

func TestFindDeletedCipher_SkipsActiveItems(t *testing.T) {
	key := testKey()
	// Active item with matching name should NOT be returned.
	active := makeCipher(t, "active-1", "GitHub", "", key)
	ciphers := []client.Cipher{active}
	got, err := findDeletedCipher("GitHub", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for active item, got %+v", got)
	}
}

func TestFindDeletedCipher_NotFound(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeDeletedCipher(t, "trash-1", "OldEntry", key),
	}
	got, err := findDeletedCipher("NonExistent", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestFindDeletedCipher_EmptyList(t *testing.T) {
	key := testKey()
	got, err := findDeletedCipher("anything", nil, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for empty list, got %+v", got)
	}
}

func TestFindDeletedCipher_SkipsDecryptionError(t *testing.T) {
	key := testKey()
	// A deleted cipher with an unreadable name should be skipped.
	bad := client.Cipher{ID: "bad-cipher", Data: client.CipherData{Name: "not-valid"}}
	d := "2000-03-01T00:00:00Z"
	bad.DeletedDate = &d
	good := makeDeletedCipher(t, "trash-1", "GoodEntry", key)
	ciphers := []client.Cipher{bad, good}
	got, err := findDeletedCipher("GoodEntry", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher, got nil")
	}
	if got.ID != "trash-1" {
		t.Errorf("got ID %q, want %q", got.ID, "trash-1")
	}
}

func TestFindDeletedCipher_MixedActiveAndDeleted(t *testing.T) {
	key := testKey()
	active := makeCipher(t, "active-1", "GitHub Active", "", key)
	deleted := makeDeletedCipher(t, "trash-1", "GitHub Deleted", key)
	ciphers := []client.Cipher{active, deleted}

	// Should find the deleted one.
	got, err := findDeletedCipher("GitHub Deleted", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected deleted cipher, got nil")
	}
	if got.ID != "trash-1" {
		t.Errorf("got ID %q, want %q", got.ID, "trash-1")
	}

	// Should NOT find the active one.
	got2, err2 := findDeletedCipher("GitHub Active", ciphers, key, nil)
	if err2 != nil {
		t.Fatalf("unexpected error: %v", err2)
	}
	if got2 != nil {
		t.Errorf("expected nil for active item lookup in deleted search, got %+v", got2)
	}
}

// TestFindDeletedCipher_ByShortID verifies that the first UUID segment can be
// used to look up a deleted cipher (matching the short form shown by bx list --deleted).
func TestFindDeletedCipher_ByShortID(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeDeletedCipher(t, "550e8400-e29b-41d4-a716-446655440000", "OldGitHub", key),
		makeDeletedCipher(t, "abcdef12-0000-0000-0000-000000000000", "OldGoogle", key),
	}
	got, err := findDeletedCipher("550e8400", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected deleted cipher via short ID, got nil")
	}
	if got.ID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("got ID %q, want full UUID", got.ID)
	}
}

// TestFindDeletedCipher_AmbiguousShortID verifies that an error is returned when
// multiple deleted ciphers share the same first UUID segment.
func TestFindDeletedCipher_AmbiguousShortID(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeDeletedCipher(t, "550e8400-aaaa-0000-0000-000000000000", "OldGitHub", key),
		makeDeletedCipher(t, "550e8400-bbbb-0000-0000-000000000000", "OldGoogle", key),
	}
	got, err := findDeletedCipher("550e8400", ciphers, key, nil)
	if err == nil {
		t.Fatal("expected error for ambiguous short ID, got nil")
	}
	if got != nil {
		t.Errorf("expected nil cipher for ambiguous short ID, got %+v", got)
	}
}

// makeDeletedCipherWithUsername creates a deleted cipher with encrypted username.
func makeDeletedCipherWithUsername(t *testing.T, id, name, username string, key []byte) client.Cipher {
	t.Helper()
	c := makeCipherWithUsername(t, id, name, username, "", key)
	d := "2000-03-01T00:00:00Z"
	c.DeletedDate = &d
	return c
}

// TestFindDeletedCipher_ByUsername verifies that a deleted cipher can be found
// by an exact username match.
func TestFindDeletedCipher_ByUsername(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeDeletedCipherWithUsername(t, "trash-1", "OldService", "admin@old.com", key),
		makeDeletedCipherWithUsername(t, "trash-2", "AnotherOld", "user@another.com", key),
	}
	got, err := findDeletedCipher("admin@old.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected deleted cipher by username, got nil")
	}
	if got.ID != "trash-1" {
		t.Errorf("got ID %q, want %q", got.ID, "trash-1")
	}
}

// TestFindDeletedCipher_ByUsernameSubstring verifies that a deleted cipher can
// be found by a username substring match.
func TestFindDeletedCipher_ByUsernameSubstring(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeDeletedCipherWithUsername(t, "trash-1", "OldService", "admin@old.com", key),
	}
	got, err := findDeletedCipher("admin@", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected deleted cipher by username substring, got nil")
	}
	if got.ID != "trash-1" {
		t.Errorf("got ID %q, want %q", got.ID, "trash-1")
	}
}

// TestFindDeletedCipher_ByUsernameCaseInsensitive verifies that deleted cipher
// username matching is case-insensitive.
func TestFindDeletedCipher_ByUsernameCaseInsensitive(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeDeletedCipherWithUsername(t, "trash-1", "OldService", "Admin@OLD.com", key),
	}
	got, err := findDeletedCipher("admin@old.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected deleted cipher by case-insensitive username, got nil")
	}
}

// TestFindDeletedCipher_NameBeatsUsername verifies that name matching takes
// priority over username matching for deleted ciphers.
func TestFindDeletedCipher_NameBeatsUsername(t *testing.T) {
	key := testKey()
	// First cipher has a name that matches the pattern.
	nameMatch := makeDeletedCipher(t, "trash-name", "admin@corp.com", key)
	// Second cipher has a username that matches the pattern.
	userMatch := makeDeletedCipherWithUsername(t, "trash-user", "Some Service", "admin@corp.com", key)

	ciphers := []client.Cipher{nameMatch, userMatch}
	got, err := findDeletedCipher("admin@corp.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher, got nil")
	}
	if got.ID != "trash-name" {
		t.Errorf("got ID %q, want %q (name should beat username)", got.ID, "trash-name")
	}
}

// TestFindDeletedCipher_UsernameSkipsEmptyUsername verifies that deleted ciphers
// without a username are safely skipped during the username pass.
func TestFindDeletedCipher_UsernameSkipsEmptyUsername(t *testing.T) {
	key := testKey()
	// First cipher has no username.
	noUser := makeDeletedCipher(t, "trash-no-user", "NoUserService", key)
	// Second cipher has a matching username.
	withUser := makeDeletedCipherWithUsername(t, "trash-with-user", "WithUserService", "admin@site.com", key)

	ciphers := []client.Cipher{noUser, withUser}
	got, err := findDeletedCipher("admin@site.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher with username, got nil")
	}
	if got.ID != "trash-with-user" {
		t.Errorf("got ID %q, want %q", got.ID, "trash-with-user")
	}
}

// TestFindDeletedCipher_UsernameNotFound verifies that nil is returned when
// no deleted cipher matches by username.
func TestFindDeletedCipher_UsernameNotFound(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeDeletedCipherWithUsername(t, "trash-1", "Service", "user@known.com", key),
	}
	got, err := findDeletedCipher("unknown@nowhere.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for non-matching username, got %+v", got)
	}
}

// TestFindDeletedCipher_UsernameSkipsActiveItems verifies that active (non-deleted)
// ciphers are ignored when searching by username.
func TestFindDeletedCipher_UsernameSkipsActiveItems(t *testing.T) {
	key := testKey()
	active := makeCipherWithUsername(t, "active-1", "Active Service", "admin@active.com", "", key)
	ciphers := []client.Cipher{active}
	got, err := findDeletedCipher("admin@active.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for active item searched by username, got %+v", got)
	}
}
