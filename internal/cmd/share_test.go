package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
)

const testOrgID = "aaaaaaaa-1111-1111-1111-111111111111"

// decodeShareCipher unmarshals a built share payload into a generic map.
func decodeShareCipher(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("could not parse share cipher: %v", err)
	}
	return obj
}

// mustDecrypt decrypts a cipher string and fails the test if it cannot.
func mustDecrypt(t *testing.T, cipherString string, key []byte) string {
	t.Helper()
	plaintext, err := crypto.Decrypt(cipherString, key)
	if err != nil {
		t.Fatalf("Decrypt(%q): %v", cipherString, err)
	}
	return string(plaintext)
}

// personalCipherJSON builds the server's JSON representation of a personal
// login item whose values are encrypted with accountKey directly (no per-item
// key), including custom fields, a passkey, and password history.
func personalCipherJSON(t *testing.T, accountKey []byte) json.RawMessage {
	t.Helper()
	enc := func(s string) string { return encryptStr(t, accountKey, s) }

	obj := map[string]any{
		"object":         "cipherDetails",
		"id":             "item-1",
		"organizationId": nil,
		"folderId":       nil,
		"type":           1,
		"reprompt":       0,
		"favorite":       true,
		"key":            nil,
		"name":           enc("Example Service"),
		"notes":          enc("family account"),
		"login": map[string]any{
			"username": enc("alice@example.com"),
			"password": enc("s3cret"),
			"totp":     nil,
			"uris": []any{
				map[string]any{"uri": enc("https://service.example.com"), "match": nil},
			},
			"fido2Credentials": []any{
				map[string]any{
					"credentialId": enc("cred-id"),
					"rpId":         enc("disneyplus.com"),
					"counter":      enc("0"),
					"discoverable": enc("true"),
					"creationDate": "2000-01-01T00:00:00.000Z",
				},
			},
		},
		"fields": []any{
			map[string]any{"name": enc("PIN"), "value": enc("1234"), "type": 0},
		},
		"passwordHistory": []any{
			map[string]any{"password": enc("old-password"), "lastUsedDate": "2000-12-01T00:00:00.000Z"},
		},
		"attachments":  nil,
		"permissions":  map[string]any{"delete": true, "restore": true},
		"edit":         true,
		"viewPassword": true,
		"revisionDate": "2000-07-31T20:02:00.000Z",
		"creationDate": "2000-01-01T00:00:00.000Z",
		"deletedDate":  nil,
	}

	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return raw
}

// ---------------------------------------------------------------------------
// buildShareCipher — item without a per-item key
// ---------------------------------------------------------------------------

func TestBuildShareCipher_ReencryptsAllValuesWithOrgKey(t *testing.T) {
	accountKey := testKey()
	orgKey := orgTestKey()

	got, err := buildShareCipher(personalCipherJSON(t, accountKey), testOrgID, testUserID, accountKey, orgKey)
	if err != nil {
		t.Fatalf("buildShareCipher: %v", err)
	}
	obj := decodeShareCipher(t, got)

	if obj["organizationId"] != testOrgID {
		t.Errorf("organizationId: got %v, want %q", obj["organizationId"], testOrgID)
	}
	if obj["lastKnownRevisionDate"] != "2000-07-31T20:02:00.000Z" {
		t.Errorf("lastKnownRevisionDate: got %v", obj["lastKnownRevisionDate"])
	}
	if obj["encryptedFor"] != testUserID {
		t.Errorf("encryptedFor: got %v, want %q", obj["encryptedFor"], testUserID)
	}

	// Top-level values must now decrypt with the organization key.
	if name := mustDecrypt(t, obj["name"].(string), orgKey); name != "Example Service" {
		t.Errorf("name: got %q", name)
	}
	if notes := mustDecrypt(t, obj["notes"].(string), orgKey); notes != "family account" {
		t.Errorf("notes: got %q", notes)
	}

	// Nested values are re-encrypted too, including passkeys and history.
	login := obj["login"].(map[string]any)
	if user := mustDecrypt(t, login["username"].(string), orgKey); user != "alice@example.com" {
		t.Errorf("username: got %q", user)
	}
	if pw := mustDecrypt(t, login["password"].(string), orgKey); pw != "s3cret" {
		t.Errorf("password: got %q", pw)
	}
	uri := login["uris"].([]any)[0].(map[string]any)
	if got := mustDecrypt(t, uri["uri"].(string), orgKey); got != "https://service.example.com" {
		t.Errorf("uri: got %q", got)
	}
	cred := login["fido2Credentials"].([]any)[0].(map[string]any)
	if got := mustDecrypt(t, cred["rpId"].(string), orgKey); got != "disneyplus.com" {
		t.Errorf("passkey rpId: got %q", got)
	}
	if cred["creationDate"] != "2000-01-01T00:00:00.000Z" {
		t.Errorf("plaintext passkey creationDate was modified: %v", cred["creationDate"])
	}
	field := obj["fields"].([]any)[0].(map[string]any)
	if got := mustDecrypt(t, field["name"].(string), orgKey); got != "PIN" {
		t.Errorf("custom field name: got %q", got)
	}
	if got := mustDecrypt(t, field["value"].(string), orgKey); got != "1234" {
		t.Errorf("custom field value: got %q", got)
	}
	history := obj["passwordHistory"].([]any)[0].(map[string]any)
	if got := mustDecrypt(t, history["password"].(string), orgKey); got != "old-password" {
		t.Errorf("password history: got %q", got)
	}
	if history["lastUsedDate"] != "2000-12-01T00:00:00.000Z" {
		t.Errorf("plaintext lastUsedDate was modified: %v", history["lastUsedDate"])
	}

	// Non-encrypted values must survive untouched.
	if obj["favorite"] != true {
		t.Errorf("favorite: got %v", obj["favorite"])
	}
	if obj["type"] != float64(1) {
		t.Errorf("type: got %v", obj["type"])
	}
	if obj["id"] != "item-1" {
		t.Errorf("id: got %v", obj["id"])
	}
}

func TestBuildShareCipher_DropsResponseOnlyFields(t *testing.T) {
	accountKey := testKey()
	orgKey := orgTestKey()

	got, err := buildShareCipher(personalCipherJSON(t, accountKey), testOrgID, testUserID, accountKey, orgKey)
	if err != nil {
		t.Fatalf("buildShareCipher: %v", err)
	}
	obj := decodeShareCipher(t, got)

	for _, key := range []string{
		"object", "attachments", "permissions", "edit", "viewPassword",
		"revisionDate", "creationDate", "deletedDate", "collectionIds",
	} {
		if _, present := obj[key]; present {
			t.Errorf("response-only field %q must not be sent to the server", key)
		}
	}
}

func TestBuildShareCipher_OldKeyNoLongerDecrypts(t *testing.T) {
	accountKey := testKey()
	orgKey := orgTestKey()

	got, err := buildShareCipher(personalCipherJSON(t, accountKey), testOrgID, testUserID, accountKey, orgKey)
	if err != nil {
		t.Fatalf("buildShareCipher: %v", err)
	}
	obj := decodeShareCipher(t, got)

	if _, err := crypto.Decrypt(obj["name"].(string), accountKey); err == nil {
		t.Error("the account key must no longer decrypt a shared item's name")
	}
}

// ---------------------------------------------------------------------------
// buildShareCipher — item with a per-item key
// ---------------------------------------------------------------------------

// itemKeyCipherJSON builds a personal item that carries its own key: keyMaterial
// is wrapped with the account key, and the item's values are encrypted with
// fieldKey — the 64-byte key bx derives from keyMaterial, which for 32-byte key
// material is its HKDF expansion.
func itemKeyCipherJSON(t *testing.T, accountKey, keyMaterial, fieldKey []byte) json.RawMessage {
	t.Helper()
	wrapped, err := crypto.Encrypt(keyMaterial, accountKey)
	if err != nil {
		t.Fatalf("Encrypt item key: %v", err)
	}
	obj := map[string]any{
		"id":           "item-2",
		"type":         1,
		"key":          wrapped,
		"name":         encryptStr(t, fieldKey, "Example Service"),
		"login":        map[string]any{"password": encryptStr(t, fieldKey, "s3cret")},
		"revisionDate": "2000-07-31T20:02:00.000Z",
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return raw
}

func TestBuildShareCipher_RewrapsItemKeyOnly(t *testing.T) {
	accountKey := testKey()
	orgKey := orgTestKey()
	itemKey := make([]byte, 64)
	for i := range itemKey {
		itemKey[i] = byte(i + 7)
	}

	raw := itemKeyCipherJSON(t, accountKey, itemKey, itemKey)
	original := decodeShareCipher(t, raw)

	got, err := buildShareCipher(raw, testOrgID, testUserID, accountKey, orgKey)
	if err != nil {
		t.Fatalf("buildShareCipher: %v", err)
	}
	obj := decodeShareCipher(t, got)

	// The item key is re-wrapped with the organization key and still unwraps to
	// the very same key material.
	unwrapped, err := crypto.Decrypt(obj["key"].(string), orgKey)
	if err != nil {
		t.Fatalf("could not unwrap the item key with the org key: %v", err)
	}
	if string(unwrapped) != string(itemKey) {
		t.Error("the unwrapped item key differs from the original")
	}

	// The field ciphertexts are encrypted with the item key, so they must be
	// forwarded byte for byte.
	if obj["name"] != original["name"] {
		t.Error("name ciphertext must not be touched when the item has its own key")
	}
	gotLogin := obj["login"].(map[string]any)
	wantLogin := original["login"].(map[string]any)
	if gotLogin["password"] != wantLogin["password"] {
		t.Error("password ciphertext must not be touched when the item has its own key")
	}

	// And they still decrypt with the item key.
	if name := mustDecrypt(t, obj["name"].(string), itemKey); name != "Example Service" {
		t.Errorf("name: got %q", name)
	}
}

func TestBuildShareCipher_UndecryptableItemKey(t *testing.T) {
	accountKey := testKey()
	orgKey := orgTestKey()
	itemKey := make([]byte, 64)

	raw := itemKeyCipherJSON(t, accountKey, itemKey, itemKey)
	// Use a key the item was not encrypted with.
	_, err := buildShareCipher(raw, testOrgID, testUserID, orgKey, orgKey)
	if err == nil || !strings.Contains(err.Error(), "item's own key") {
		t.Fatalf("expected an item-key error, got %v", err)
	}
}

func TestBuildShareCipher_UndecryptableValueAborts(t *testing.T) {
	accountKey := testKey()
	orgKey := orgTestKey()

	// A value encrypted with a key we do not have must abort the whole move
	// instead of producing a half-readable item.
	strangerKey := make([]byte, 64)
	for i := range strangerKey {
		strangerKey[i] = byte(i + 200)
	}
	obj := map[string]any{
		"id":           "item-3",
		"type":         1,
		"name":         encryptStr(t, accountKey, "Example Service"),
		"notes":        encryptStr(t, strangerKey, "unreadable"),
		"revisionDate": "2000-07-31T20:02:00.000Z",
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if _, err := buildShareCipher(raw, testOrgID, testUserID, accountKey, orgKey); err == nil {
		t.Fatal("expected an error for a value that cannot be decrypted")
	} else if !strings.Contains(err.Error(), "notes") {
		t.Errorf("expected the failing field to be named, got %v", err)
	}
}

func TestBuildShareCipher_InvalidJSON(t *testing.T) {
	if _, err := buildShareCipher(json.RawMessage("not json"), testOrgID, testUserID, testKey(), orgTestKey()); err == nil {
		t.Fatal("expected an error for malformed cipher JSON")
	}
}

// ---------------------------------------------------------------------------
// reencryptJSONValue
// ---------------------------------------------------------------------------

func TestReencryptJSONValue_LeavesNonCipherValuesAlone(t *testing.T) {
	accountKey := testKey()
	orgKey := orgTestKey()

	raw := json.RawMessage(`{"n":1,"b":true,"nil":null,"s":"plain","uuid":"aaaaaaaa-1111-1111-1111-111111111111","when":"2000-07-31T20:02:00.000Z"}`)
	got, err := reencryptJSONValue(raw, accountKey, orgKey)
	if err != nil {
		t.Fatalf("reencryptJSONValue: %v", err)
	}

	var before, after map[string]any
	if err := json.Unmarshal(raw, &before); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := json.Unmarshal(got, &after); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for key, want := range before {
		if after[key] != want {
			t.Errorf("%s: got %v, want %v", key, after[key], want)
		}
	}
}

func TestReencryptJSONValue_NestedArrays(t *testing.T) {
	accountKey := testKey()
	orgKey := orgTestKey()

	raw, err := json.Marshal([]any{[]any{encryptStr(t, accountKey, "deep")}})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := reencryptJSONValue(raw, accountKey, orgKey)
	if err != nil {
		t.Fatalf("reencryptJSONValue: %v", err)
	}

	var nested [][]string
	if err := json.Unmarshal(got, &nested); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got := mustDecrypt(t, nested[0][0], orgKey); got != "deep" {
		t.Errorf("got %q, want %q", got, "deep")
	}
}

// ---------------------------------------------------------------------------
// cipherRawString / rawCipherHasAttachments
// ---------------------------------------------------------------------------

func TestCipherRawString(t *testing.T) {
	raw := json.RawMessage(`{"revisionDate":"2000-07-31T20:02:00.000Z","key":null,"type":1}`)

	if got := cipherRawString(raw, "revisionDate"); got != "2000-07-31T20:02:00.000Z" {
		t.Errorf("got %q", got)
	}
	if got := cipherRawString(raw, "key"); got != "" {
		t.Errorf("null field: got %q, want empty", got)
	}
	if got := cipherRawString(raw, "type"); got != "" {
		t.Errorf("non-string field: got %q, want empty", got)
	}
	if got := cipherRawString(raw, "missing"); got != "" {
		t.Errorf("missing field: got %q, want empty", got)
	}
	if got := cipherRawString(json.RawMessage("nope"), "key"); got != "" {
		t.Errorf("invalid JSON: got %q, want empty", got)
	}
}

func TestRawCipherHasAttachments(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{"null", `{"attachments":null}`, false},
		{"empty array", `{"attachments":[]}`, false},
		{"absent", `{"id":"item-1"}`, false},
		{"one attachment", `{"attachments":[{"id":"att-1","fileName":"2.a|b|c"}]}`, true},
		{"invalid JSON", `nope`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rawCipherHasAttachments(json.RawMessage(tt.raw)); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// resolveOwnershipTarget
// ---------------------------------------------------------------------------

func TestResolveOwnershipTarget_MovePersonalItemToOrganization(t *testing.T) {
	orgs, _, _ := familyVault(t)

	got, err := resolveOwnershipTarget("Example Service", "Family", true, "", orgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.orgID != orgs[0].ID || got.orgName != "Family" {
		t.Errorf("got %+v, want the Family organization", got)
	}
	if !got.move {
		t.Error("a personal item joining an organization must be flagged as a move")
	}
}

func TestResolveOwnershipTarget_CollectionsOnlyWithoutOrgFlag(t *testing.T) {
	orgs, _, _ := familyVault(t)

	got, err := resolveOwnershipTarget("Example Service", "", false, orgs[0].ID, orgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.orgID != orgs[0].ID || got.orgName != "Family" {
		t.Errorf("got %+v", got)
	}
	if got.move {
		t.Error("an item already in the organization must not be moved")
	}
}

func TestResolveOwnershipTarget_CollectionsOnlyWithSameOrgFlag(t *testing.T) {
	orgs, _, _ := familyVault(t)

	got, err := resolveOwnershipTarget("Example Service", "Family", true, orgs[0].ID, orgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.move {
		t.Error("re-stating the current organization must not trigger a move")
	}
}

func TestResolveOwnershipTarget_PersonalItemWithoutOrgFlag(t *testing.T) {
	orgs, _, _ := familyVault(t)

	_, err := resolveOwnershipTarget("Example Service", "", false, "", orgs)
	if err == nil || !strings.Contains(err.Error(), "--organization") {
		t.Fatalf("expected a hint to pass --organization, got %v", err)
	}
}

func TestResolveOwnershipTarget_EmptyOrgFlagIsRejected(t *testing.T) {
	orgs, _, _ := familyVault(t)

	_, err := resolveOwnershipTarget("Example Service", "  ", true, orgs[0].ID, orgs)
	if err == nil || !strings.Contains(err.Error(), "personal ownership") {
		t.Fatalf("expected unsharing to be rejected, got %v", err)
	}
}

func TestResolveOwnershipTarget_BetweenOrganizationsIsRejected(t *testing.T) {
	orgs, _, _ := familyVault(t)

	_, err := resolveOwnershipTarget("Example Service", "Test", true, orgs[0].ID, orgs)
	if err == nil {
		t.Fatal("expected moving between organizations to be rejected")
	}
	if !strings.Contains(err.Error(), "Family") || !strings.Contains(err.Error(), "Test") {
		t.Errorf("expected both organization names in the message, got %v", err)
	}
}

func TestResolveOwnershipTarget_UnknownOrganization(t *testing.T) {
	orgs, _, _ := familyVault(t)

	_, err := resolveOwnershipTarget("Example Service", "Neighbours", true, "", orgs)
	if err == nil || !strings.Contains(err.Error(), "organization not found") {
		t.Fatalf("expected a not-found error, got %v", err)
	}
}

func TestResolveOwnershipTarget_AmbiguousOrganizationShortID(t *testing.T) {
	orgs := []client.ProfileOrganization{
		{ID: "aaaaaaaa-1111-1111-1111-111111111111", Name: "One"},
		{ID: "aaaaaaaa-2222-2222-2222-222222222222", Name: "Two"},
	}
	_, err := resolveOwnershipTarget("Example Service", "aaaaaaaa", true, "", orgs)
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected an ambiguity error, got %v", err)
	}
}

func TestResolveOwnershipTarget_UnnamedOrganizationFallsBackToShortID(t *testing.T) {
	orgs := []client.ProfileOrganization{{ID: "12345678-0000-0000-0000-000000000000"}}

	got, err := resolveOwnershipTarget("Example Service", "12345678", true, "", orgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.orgName != "12345678" {
		t.Errorf("got %q, want the short ID", got.orgName)
	}
}

// ---------------------------------------------------------------------------
// setRawCollectionIDs
// ---------------------------------------------------------------------------

func TestSetRawCollectionIDs(t *testing.T) {
	// GET /api/ciphers/{id} does not report collection membership on every
	// server, so the field is added when absent and replaced when stale.
	got, err := setRawCollectionIDs(json.RawMessage(`{"id":"c1","name":"2.a|b|c"}`), []string{"col-1", "col-2"})
	if err != nil {
		t.Fatalf("setRawCollectionIDs: %v", err)
	}
	obj := decodeShareCipher(t, got)
	ids, ok := obj["collectionIds"].([]any)
	if !ok || len(ids) != 2 || ids[0] != "col-1" || ids[1] != "col-2" {
		t.Errorf("collectionIds: got %v", obj["collectionIds"])
	}
	if obj["name"] != "2.a|b|c" {
		t.Errorf("other fields must survive, got %v", obj)
	}

	got, err = setRawCollectionIDs(json.RawMessage(`{"id":"c1","collectionIds":["stale"]}`), []string{"col-1"})
	if err != nil {
		t.Fatalf("setRawCollectionIDs: %v", err)
	}
	obj = decodeShareCipher(t, got)
	if ids, ok := obj["collectionIds"].([]any); !ok || len(ids) != 1 || ids[0] != "col-1" {
		t.Errorf("stale collectionIds not replaced: %v", obj["collectionIds"])
	}

	if _, err := setRawCollectionIDs(json.RawMessage("not json"), []string{"col-1"}); err == nil {
		t.Error("expected an error for malformed JSON")
	}
}

// ---------------------------------------------------------------------------
// organizationKey
// ---------------------------------------------------------------------------

func TestOrganizationKey(t *testing.T) {
	orgKey := orgTestKey()

	got, err := organizationKey("org-1", "Family", map[string][]byte{"org-1": orgKey})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 64 {
		t.Errorf("expected a 64-byte key, got %d bytes", len(got))
	}

	// A missing key must be reported as such rather than surfacing later as a
	// failed collection lookup.
	_, err = organizationKey("org-1", "Family", nil)
	if err == nil || !strings.Contains(err.Error(), "no decryption key") {
		t.Fatalf("expected a missing-key error naming the organization, got %v", err)
	}
	if err != nil && !strings.Contains(err.Error(), "Family") {
		t.Errorf("expected the organization name in the message, got %v", err)
	}

	// A 32-byte key is expanded rather than rejected.
	got, err = organizationKey("org-1", "Family", map[string][]byte{"org-1": make([]byte, 32)})
	if err != nil {
		t.Fatalf("unexpected error for a 32-byte key: %v", err)
	}
	if len(got) != 64 {
		t.Errorf("expected the key to be expanded to 64 bytes, got %d", len(got))
	}

	if _, err := organizationKey("org-1", "Family", map[string][]byte{"org-1": make([]byte, 17)}); err == nil {
		t.Error("expected an error for an unusable key length")
	}
}

// ---------------------------------------------------------------------------
// End-to-end: a moved item must be readable through bx's normal read path
// ---------------------------------------------------------------------------

// shareAndReload runs buildShareCipher and parses the result the way bx parses a
// cipher coming back from the server, with the organization set — i.e. exactly
// what ends up in the local vault cache after a move.
func shareAndReload(t *testing.T, raw json.RawMessage, orgID string, accountKey, orgKey []byte) client.Cipher {
	t.Helper()
	shared, err := buildShareCipher(raw, orgID, testUserID, accountKey, orgKey)
	if err != nil {
		t.Fatalf("buildShareCipher: %v", err)
	}
	var cipher client.Cipher
	if err := json.Unmarshal(shared, &cipher); err != nil {
		t.Fatalf("Unmarshal shared cipher: %v", err)
	}
	if cipher.OrganizationID == nil || *cipher.OrganizationID != orgID {
		t.Fatalf("organizationId not set on the shared cipher: %+v", cipher.OrganizationID)
	}
	return cipher
}

func TestMovedItem_IsReadableWithOrganizationKeyOnly(t *testing.T) {
	accountKey := testKey()
	orgKey := orgTestKey()
	orgKeys := map[string][]byte{testOrgID: orgKey}

	cipher := shareAndReload(t, personalCipherJSON(t, accountKey), testOrgID, accountKey, orgKey)

	// A family member has the organization key but not our account key, so bx
	// must resolve the item key from the organization key alone.
	itemKey := cipherKey(cipher, nil, orgKeys)

	if got := mustDecrypt(t, cipherName(&cipher), itemKey); got != "Example Service" {
		t.Errorf("name: got %q", got)
	}
	if got := mustDecrypt(t, cipherUsername(&cipher), itemKey); got != "alice@example.com" {
		t.Errorf("username: got %q", got)
	}
	if got := mustDecrypt(t, cipherPassword(&cipher), itemKey); got != "s3cret" {
		t.Errorf("password: got %q", got)
	}
	uris := cipherURIs(&cipher)
	if len(uris) != 1 {
		t.Fatalf("expected 1 URI, got %d", len(uris))
	}
	if got := mustDecrypt(t, uris[0].URI, itemKey); got != "https://service.example.com" {
		t.Errorf("uri: got %q", got)
	}
	notes := cipherNotes(&cipher)
	if notes == nil {
		t.Fatal("expected notes to survive the move")
	}
	if got := mustDecrypt(t, *notes, itemKey); got != "family account" {
		t.Errorf("notes: got %q", got)
	}
	fields := cipherCustomFields(&cipher)
	if len(fields) != 1 {
		t.Fatalf("expected 1 custom field, got %d", len(fields))
	}
	name, value, err := decryptCustomField(fields[0], itemKey)
	if err != nil {
		t.Fatalf("decryptCustomField: %v", err)
	}
	if name != "PIN" || value != "1234" {
		t.Errorf("custom field: got %q = %q", name, value)
	}
	creds := cipherFido2Credentials(&cipher)
	if len(creds) != 1 {
		t.Fatalf("expected 1 passkey, got %d", len(creds))
	}
	if block := renderPasskeyBlock(creds[0], itemKey); !strings.Contains(block, "disneyplus.com") {
		t.Errorf("passkey is not readable after the move: %q", block)
	}
}

func TestMovedItemWithItemKey_IsReadableWithOrganizationKeyOnly(t *testing.T) {
	accountKey := testKey()
	orgKey := orgTestKey()
	orgKeys := map[string][]byte{testOrgID: orgKey}

	// bx uses a 64-byte item key as it is and HKDF-expands a 32-byte one, so both
	// must survive the re-wrap.
	for _, size := range []int{64, 32} {
		t.Run(fmt.Sprintf("%d-byte item key", size), func(t *testing.T) {
			keyMaterial := make([]byte, size)
			for i := range keyMaterial {
				keyMaterial[i] = byte(i + 7)
			}
			fieldKey := keyMaterial
			if size == 32 {
				expanded, err := crypto.ExpandKey(keyMaterial)
				if err != nil {
					t.Fatalf("ExpandKey: %v", err)
				}
				fieldKey = expanded
			}

			raw := itemKeyCipherJSON(t, accountKey, keyMaterial, fieldKey)
			cipher := shareAndReload(t, raw, testOrgID, accountKey, orgKey)
			key := cipherKey(cipher, nil, orgKeys)

			if got := mustDecrypt(t, cipherName(&cipher), key); got != "Example Service" {
				t.Errorf("name: got %q", got)
			}
			if got := mustDecrypt(t, cipherPassword(&cipher), key); got != "s3cret" {
				t.Errorf("password: got %q", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// attachmentsBlockMove
// ---------------------------------------------------------------------------

// rawCipherWithKeyAndAttachments builds a raw cipher JSON object with the given
// per-item key cipher string and attachment count.
func rawCipherWithKeyAndAttachments(t *testing.T, key string, attachments int) json.RawMessage {
	t.Helper()
	obj := map[string]any{"id": "item-1", "key": nil}
	if key != "" {
		obj["key"] = key
	}
	for i := 0; i < attachments; i++ {
		obj["attachments"] = []any{map[string]any{"id": "att-1", "fileName": "2.a|b|c", "key": "2.a|b|c"}}
	}
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAttachmentsBlockMove(t *testing.T) {
	tests := []struct {
		name string
		raw  json.RawMessage
		want bool
	}{
		{"no attachments, no item key", rawCipherWithKeyAndAttachments(t, "", 0), false},
		{"no attachments, item key", rawCipherWithKeyAndAttachments(t, "2.a|b|c", 0), false},
		{"attachments, no item key", rawCipherWithKeyAndAttachments(t, "", 1), true},
		{"attachments, item key", rawCipherWithKeyAndAttachments(t, "2.a|b|c", 1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := attachmentsBlockMove(tt.raw); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
