package cmd

import (
	"strings"
	"testing"

	"github.com/nning/bx/internal/client"
)

// orgTestKey returns a deterministic 64-byte key distinct from testKey(),
// standing in for an organization's symmetric key.
func orgTestKey() []byte {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i + 101)
	}
	return key
}

// makeCollection builds a test collection with an org-key-encrypted name.
func makeCollection(t *testing.T, id, orgID, name string, orgKey []byte) client.Collection {
	t.Helper()
	return client.Collection{
		ID:             id,
		OrganizationID: orgID,
		Name:           encryptStr(t, orgKey, name),
	}
}

// familyVault builds the organization/collection fixture used by most tests
// here: one "Family" organization with three member collections.
func familyVault(t *testing.T) ([]client.ProfileOrganization, []client.Collection, map[string][]byte) {
	t.Helper()
	orgKey := orgTestKey()
	orgs := []client.ProfileOrganization{
		{ID: "aaaaaaaa-1111-1111-1111-111111111111", Name: "Family"},
		{ID: "bbbbbbbb-2222-2222-2222-222222222222", Name: "Test"},
	}
	cols := []client.Collection{
		makeCollection(t, "cccccccc-1111-1111-1111-111111111111", orgs[0].ID, "Wife", orgKey),
		makeCollection(t, "dddddddd-1111-1111-1111-111111111111", orgs[0].ID, "Kid 1", orgKey),
		makeCollection(t, "eeeeeeee-2222-2222-2222-222222222222", orgs[1].ID, "Wife", orgKey),
	}
	orgKeys := map[string][]byte{orgs[0].ID: orgKey, orgs[1].ID: orgKey}
	return orgs, cols, orgKeys
}

// ---------------------------------------------------------------------------
// orgNameByID
// ---------------------------------------------------------------------------

func TestOrgNameByID(t *testing.T) {
	orgs, _, _ := familyVault(t)

	if got := orgNameByID(orgs, orgs[0].ID); got != "Family" {
		t.Errorf("got %q, want %q", got, "Family")
	}
	if got := orgNameByID(orgs, ""); got != "" {
		t.Errorf("empty ID: got %q, want empty", got)
	}
	// Unknown organization: fall back to the short ID.
	if got := orgNameByID(orgs, "ffffffff-9999-9999-9999-999999999999"); got != "ffffffff" {
		t.Errorf("got %q, want %q", got, "ffffffff")
	}
	// Known organization without a name: fall back to the short ID.
	unnamed := []client.ProfileOrganization{{ID: "12345678-0000-0000-0000-000000000000"}}
	if got := orgNameByID(unnamed, unnamed[0].ID); got != "12345678" {
		t.Errorf("got %q, want %q", got, "12345678")
	}
}

// ---------------------------------------------------------------------------
// findOrganization
// ---------------------------------------------------------------------------

func TestFindOrganization_ByName(t *testing.T) {
	orgs, _, _ := familyVault(t)

	got, err := findOrganization("Family", orgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.ID != orgs[0].ID {
		t.Fatalf("got %+v, want the Family organization", got)
	}
}

func TestFindOrganization_ByNameCaseInsensitive(t *testing.T) {
	orgs, _, _ := familyVault(t)

	got, err := findOrganization("family", orgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.ID != orgs[0].ID {
		t.Fatalf("got %+v, want the Family organization", got)
	}
}

func TestFindOrganization_ByFullAndShortID(t *testing.T) {
	orgs, _, _ := familyVault(t)

	got, err := findOrganization(orgs[1].ID, orgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.ID != orgs[1].ID {
		t.Fatalf("full ID: got %+v", got)
	}

	got, err = findOrganization("bbbbbbbb", orgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.ID != orgs[1].ID {
		t.Fatalf("short ID: got %+v", got)
	}
}

func TestFindOrganization_AmbiguousShortID(t *testing.T) {
	orgs := []client.ProfileOrganization{
		{ID: "aaaaaaaa-1111-1111-1111-111111111111", Name: "One"},
		{ID: "aaaaaaaa-2222-2222-2222-222222222222", Name: "Two"},
	}
	_, err := findOrganization("aaaaaaaa", orgs)
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected an ambiguity error, got %v", err)
	}
}

func TestFindOrganization_NotFound(t *testing.T) {
	orgs, _, _ := familyVault(t)

	got, err := findOrganization("Neighbours", orgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

// ---------------------------------------------------------------------------
// collectionName / collectionNames
// ---------------------------------------------------------------------------

func TestCollectionName(t *testing.T) {
	_, cols, orgKeys := familyVault(t)

	if got := collectionName(cols[0], orgKeys); got != "Wife" {
		t.Errorf("got %q, want %q", got, "Wife")
	}
	// Missing organization key: no name can be decrypted.
	if got := collectionName(cols[0], nil); got != "" {
		t.Errorf("expected empty name without an org key, got %q", got)
	}
	// Wrong key: decryption fails, no name.
	if got := collectionName(cols[0], map[string][]byte{cols[0].OrganizationID: testKey()}); got != "" {
		t.Errorf("expected empty name with the wrong key, got %q", got)
	}
}

func TestCollectionNames(t *testing.T) {
	_, cols, orgKeys := familyVault(t)

	got := collectionNames([]string{cols[1].ID, cols[0].ID}, cols, orgKeys)
	want := []string{"Kid 1", "Wife"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}

	// Unknown IDs fall back to the short ID so output is never empty.
	got = collectionNames([]string{"99999999-0000-0000-0000-000000000000"}, cols, orgKeys)
	if len(got) != 1 || got[0] != "99999999" {
		t.Errorf("got %v, want [99999999]", got)
	}

	if got := collectionNames(nil, cols, orgKeys); len(got) != 0 {
		t.Errorf("expected no names, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// findCollections
// ---------------------------------------------------------------------------

func TestFindCollections_ByName(t *testing.T) {
	orgs, cols, orgKeys := familyVault(t)

	got, err := findCollections([]string{"Wife", "Kid 1"}, cols, orgs[0].ID, orgKeys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 collections, got %d", len(got))
	}
	if got[0].ID != cols[0].ID || got[1].ID != cols[1].ID {
		t.Errorf("unexpected order/ids: %s, %s", got[0].ID, got[1].ID)
	}
}

func TestFindCollections_NameOfAnotherOrgIsNotFound(t *testing.T) {
	orgs, cols, orgKeys := familyVault(t)

	// "Kid 1" only exists in Family, so it must not resolve for Test.
	_, err := findCollections([]string{"Kid 1"}, cols, orgs[1].ID, orgKeys)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected a not-found error, got %v", err)
	}

	// "Wife" exists in both, but only the Test one may be returned.
	got, err := findCollections([]string{"Wife"}, cols, orgs[1].ID, orgKeys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].ID != cols[2].ID {
		t.Fatalf("expected the Test organization's collection, got %+v", got)
	}
}

func TestFindCollections_ByFullAndShortID(t *testing.T) {
	orgs, cols, orgKeys := familyVault(t)

	got, err := findCollections([]string{cols[0].ID, "dddddddd"}, cols, orgs[0].ID, orgKeys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0].ID != cols[0].ID || got[1].ID != cols[1].ID {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestFindCollections_DeduplicatesPreservingOrder(t *testing.T) {
	orgs, cols, orgKeys := familyVault(t)

	got, err := findCollections([]string{"Kid 1", "Wife", cols[1].ID}, cols, orgs[0].ID, orgKeys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected duplicates to collapse, got %d", len(got))
	}
	if got[0].ID != cols[1].ID || got[1].ID != cols[0].ID {
		t.Errorf("expected the order the flags were given in, got %s, %s", got[0].ID, got[1].ID)
	}
}

func TestFindCollections_AmbiguousName(t *testing.T) {
	orgKey := orgTestKey()
	orgID := "aaaaaaaa-1111-1111-1111-111111111111"
	cols := []client.Collection{
		makeCollection(t, "cccccccc-1111-1111-1111-111111111111", orgID, "Shared", orgKey),
		makeCollection(t, "dddddddd-1111-1111-1111-111111111111", orgID, "Shared", orgKey),
	}
	_, err := findCollections([]string{"Shared"}, cols, orgID, map[string][]byte{orgID: orgKey})
	if err == nil || !strings.Contains(err.Error(), "ambiguous collection name") {
		t.Fatalf("expected an ambiguity error, got %v", err)
	}
}

func TestFindCollections_AmbiguousShortID(t *testing.T) {
	orgKey := orgTestKey()
	orgID := "aaaaaaaa-1111-1111-1111-111111111111"
	cols := []client.Collection{
		makeCollection(t, "cccccccc-1111-1111-1111-111111111111", orgID, "One", orgKey),
		makeCollection(t, "cccccccc-2222-2222-2222-222222222222", orgID, "Two", orgKey),
	}
	_, err := findCollections([]string{"cccccccc"}, cols, orgID, map[string][]byte{orgID: orgKey})
	if err == nil || !strings.Contains(err.Error(), "ambiguous short ID") {
		t.Fatalf("expected an ambiguity error, got %v", err)
	}
}

func TestFindCollections_EmptyValue(t *testing.T) {
	orgs, cols, orgKeys := familyVault(t)

	_, err := findCollections([]string{"  "}, cols, orgs[0].ID, orgKeys)
	if err == nil || !strings.Contains(err.Error(), "empty collection name") {
		t.Fatalf("expected an empty-name error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// sortCollectionRows
// ---------------------------------------------------------------------------

func TestSortCollectionRows(t *testing.T) {
	rows := []collectionRow{
		{id: "3", org: "Family", lowerOrg: "family", name: "wife", lowerName: "wife"},
		{id: "1", org: "Test", lowerOrg: "test", name: "Alpha", lowerName: "alpha"},
		{id: "2", org: "Family", lowerOrg: "family", name: "Kid 1", lowerName: "kid 1"},
	}
	sortCollectionRows(rows)

	wantIDs := []string{"2", "3", "1"}
	for i, want := range wantIDs {
		if rows[i].id != want {
			t.Errorf("index %d: got id %q, want %q", i, rows[i].id, want)
		}
	}
}
