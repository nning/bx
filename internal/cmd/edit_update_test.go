package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
)

var testNow = time.Date(2000, 9, 25, 12, 0, 0, 0, time.UTC)

// serverCipher builds the raw JSON of a login item as the server returns it,
// including data bx does not model.
func serverCipher(t *testing.T, key []byte) (json.RawMessage, map[string]string) {
	t.Helper()
	enc := map[string]string{
		"name":     encryptStr(t, key, "GitHub"),
		"notes":    encryptStr(t, key, "notes\n"),
		"username": encryptStr(t, key, "alice"),
		"password": encryptStr(t, key, "old-pass"),
		"uri":      encryptStr(t, key, "https://github.com"),
		"checksum": encryptStr(t, key, "sum"),
		"field":    encryptStr(t, key, "PIN"),
		"value":    encryptStr(t, key, "1234"),
		"history":  encryptStr(t, key, "older-pass"),
		"passkey":  encryptStr(t, key, "passkey-secret"),
	}
	raw := `{
		"id": "cipher-id",
		"organizationId": null,
		"folderId": "folder-id",
		"type": 1,
		"name": "` + enc["name"] + `",
		"notes": "` + enc["notes"] + `",
		"favorite": true,
		"reprompt": 1,
		"key": null,
		"revisionDate": "2000-09-01T00:00:00.000000Z",
		"edit": true,
		"viewPassword": true,
		"object": "cipherDetails",
		"login": {
			"username": "` + enc["username"] + `",
			"password": "` + enc["password"] + `",
			"passwordRevisionDate": null,
			"totp": null,
			"autofillOnPageLoad": false,
			"uris": [{"uri": "` + enc["uri"] + `", "uriChecksum": "` + enc["checksum"] + `", "match": 3}],
			"fido2Credentials": [{"credentialId": "` + enc["passkey"] + `", "keyValue": "` + enc["passkey"] + `"}]
		},
		"fields": [{"type": 1, "name": "` + enc["field"] + `", "value": "` + enc["value"] + `", "linkedId": null}],
		"passwordHistory": [{"password": "` + enc["history"] + `", "lastUsedDate": "2000-01-01T00:00:00.000Z"}]
	}`
	return json.RawMessage(raw), enc
}

func strPtr(s string) *string { return &s }

// decodeObject parses a JSON object for assertions.
func decodeObject(t *testing.T, raw json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("not a JSON object: %v\n%s", err, raw)
	}
	return obj
}

// compactJSON normalizes a JSON value so that it can be compared as a string.
func compactJSON(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, raw)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func decryptJSONString(t *testing.T, key []byte, raw json.RawMessage) string {
	t.Helper()
	s, err := decryptRawString(raw, key)
	if err != nil {
		t.Fatalf("decrypt %s: %v", raw, err)
	}
	return s
}

func TestBuildEditCipher_KeepsEverythingNotEdited(t *testing.T) {
	key := testKey()
	raw, _ := serverCipher(t, key)

	body, err := buildEditCipher(raw, cipherUpdate{Name: strPtr("GitHub (work)")}, testUserID, key, testNow)
	if err != nil {
		t.Fatalf("buildEditCipher: %v", err)
	}
	in, out := decodeObject(t, raw), decodeObject(t, body)

	if got := decryptJSONString(t, key, out["name"]); got != "GitHub (work)" {
		t.Errorf("name: got %q", got)
	}
	for _, k := range []string{"type", "folderId", "organizationId", "favorite", "reprompt", "key", "notes", "login", "fields", "passwordHistory"} {
		if compactJSON(t, out[k]) != compactJSON(t, in[k]) {
			t.Errorf("%s changed:\n got %s\nwant %s", k, out[k], in[k])
		}
	}
	if compactJSON(t, out["lastKnownRevisionDate"]) != compactJSON(t, in["revisionDate"]) {
		t.Errorf("lastKnownRevisionDate: got %s", out["lastKnownRevisionDate"])
	}
	if string(out["encryptedFor"]) != `"`+testUserID+`"` {
		t.Errorf("encryptedFor: got %s, want %q", out["encryptedFor"], testUserID)
	}
	// Response-only keys must not be sent back.
	for _, k := range []string{"edit", "viewPassword", "object", "revisionDate"} {
		if _, ok := out[k]; ok {
			t.Errorf("response-only key %q was sent", k)
		}
	}
}

func TestBuildEditCipher_LoginEditKeepsPasskeysAndURISettings(t *testing.T) {
	key := testKey()
	raw, enc := serverCipher(t, key)

	body, err := buildEditCipher(raw, cipherUpdate{
		Username: strPtr("bob"),
		URLs:     &[]string{"https://github.com", "https://gitlab.com"},
	}, testUserID, key, testNow)
	if err != nil {
		t.Fatalf("buildEditCipher: %v", err)
	}
	login := decodeObject(t, decodeObject(t, body)["login"])
	inLogin := decodeObject(t, decodeObject(t, raw)["login"])

	if got := decryptJSONString(t, key, login["username"]); got != "bob" {
		t.Errorf("username: got %q", got)
	}
	for _, k := range []string{"password", "fido2Credentials", "autofillOnPageLoad", "passwordRevisionDate"} {
		if compactJSON(t, login[k]) != compactJSON(t, inLogin[k]) {
			t.Errorf("login.%s changed:\n got %s\nwant %s", k, login[k], inLogin[k])
		}
	}

	var uris []map[string]json.RawMessage
	if err := json.Unmarshal(login["uris"], &uris); err != nil || len(uris) != 2 {
		t.Fatalf("uris: %s", login["uris"])
	}
	// The existing URI keeps its match setting and checksum.
	if compactJSON(t, uris[0]["uriChecksum"]) != `"`+enc["checksum"]+`"` || string(uris[0]["match"]) != "3" {
		t.Errorf("existing URI changed: %v", uris[0])
	}
	// A new URI gets the checksum the official clients compute.
	if got := decryptJSONString(t, key, uris[1]["uri"]); got != "https://gitlab.com" {
		t.Errorf("new URI: got %q", got)
	}
	sum := sha256.Sum256([]byte("https://gitlab.com"))
	if got := decryptJSONString(t, key, uris[1]["uriChecksum"]); got != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Errorf("new URI checksum: got %q", got)
	}
}

func TestBuildEditCipher_PasswordChangeIsRecordedInHistory(t *testing.T) {
	key := testKey()
	raw, enc := serverCipher(t, key)

	body, err := buildEditCipher(raw, cipherUpdate{Password: strPtr("new-pass")}, testUserID, key, testNow)
	if err != nil {
		t.Fatalf("buildEditCipher: %v", err)
	}
	out := decodeObject(t, body)
	login := decodeObject(t, out["login"])

	if got := decryptJSONString(t, key, login["password"]); got != "new-pass" {
		t.Errorf("password: got %q", got)
	}
	if string(login["passwordRevisionDate"]) != `"2000-09-25T12:00:00.000Z"` {
		t.Errorf("passwordRevisionDate: got %s", login["passwordRevisionDate"])
	}

	var history []map[string]json.RawMessage
	if err := json.Unmarshal(out["passwordHistory"], &history); err != nil || len(history) != 2 {
		t.Fatalf("passwordHistory: %s", out["passwordHistory"])
	}
	if compactJSON(t, history[0]["password"]) != `"`+enc["password"]+`"` ||
		string(history[0]["lastUsedDate"]) != `"2000-09-25T12:00:00.000Z"` {
		t.Errorf("newest history entry: %v", history[0])
	}
	if compactJSON(t, history[1]["password"]) != `"`+enc["history"]+`"` {
		t.Errorf("older history entry lost: %v", history[1])
	}
}

func TestBuildEditCipher_PasswordHistoryIsCapped(t *testing.T) {
	key := testKey()
	raw, _ := serverCipher(t, key)
	obj := decodeObject(t, raw)
	var history []string
	for i := 0; i < passwordHistoryLimit; i++ {
		history = append(history, `{"password":"`+encryptStr(t, key, "p")+`","lastUsedDate":null}`)
	}
	obj["passwordHistory"] = json.RawMessage("[" + strings.Join(history, ",") + "]")
	raw, _ = json.Marshal(obj)

	body, err := buildEditCipher(raw, cipherUpdate{Password: strPtr("new-pass")}, testUserID, key, testNow)
	if err != nil {
		t.Fatalf("buildEditCipher: %v", err)
	}
	var got []json.RawMessage
	if err := json.Unmarshal(decodeObject(t, body)["passwordHistory"], &got); err != nil || len(got) != passwordHistoryLimit {
		t.Errorf("passwordHistory has %d entries, want %d", len(got), passwordHistoryLimit)
	}
}

func TestBuildEditCipher_UnchangedValuesKeepCiphertext(t *testing.T) {
	key := testKey()
	raw, _ := serverCipher(t, key)

	// Setting values to what they already are is not a change: no
	// re-encryption and, for the password, no history entry.
	body, err := buildEditCipher(raw, cipherUpdate{
		Name:     strPtr("GitHub"),
		Password: strPtr("old-pass"),
		URLs:     &[]string{"https://github.com"},
	}, testUserID, key, testNow)
	if err != nil {
		t.Fatalf("buildEditCipher: %v", err)
	}
	in, out := decodeObject(t, raw), decodeObject(t, body)
	for _, k := range []string{"name", "login", "passwordHistory"} {
		if compactJSON(t, out[k]) != compactJSON(t, in[k]) {
			t.Errorf("%s changed:\n got %s\nwant %s", k, out[k], in[k])
		}
	}
}

func TestBuildEditCipher_EmptyValuesBecomeNull(t *testing.T) {
	key := testKey()
	raw, _ := serverCipher(t, key)

	body, err := buildEditCipher(raw, cipherUpdate{Notes: strPtr(""), Username: strPtr("")}, testUserID, key, testNow)
	if err != nil {
		t.Fatalf("buildEditCipher: %v", err)
	}
	out := decodeObject(t, body)
	if string(out["notes"]) != "null" {
		t.Errorf("notes: got %s", out["notes"])
	}
	if got := decodeObject(t, out["login"])["username"]; string(got) != "null" {
		t.Errorf("username: got %s", got)
	}
}

func TestBuildEditCipher_KeepsOrganization(t *testing.T) {
	key := testKey()
	raw, _ := serverCipher(t, key)
	obj := decodeObject(t, raw)
	obj["organizationId"] = json.RawMessage(`"org-id"`)
	raw, _ = json.Marshal(obj)

	body, err := buildEditCipher(raw, cipherUpdate{Name: strPtr("x")}, testUserID, key, testNow)
	if err != nil {
		t.Fatalf("buildEditCipher: %v", err)
	}
	if got := decodeObject(t, body)["organizationId"]; string(got) != `"org-id"` {
		t.Errorf("organizationId: got %s", got)
	}
}

func TestApplyCustomFields(t *testing.T) {
	key := testKey()
	pinName := encryptStr(t, key, "PIN")
	pinValue := encryptStr(t, key, "1234")
	tokName := encryptStr(t, key, "Token")
	linkName := encryptStr(t, key, "Link")
	rawFields := []json.RawMessage{
		json.RawMessage(`{"type":1,"name":"` + pinName + `","value":"` + pinValue + `","linkedId":null,"future":"kept"}`),
		json.RawMessage(`{"type":1,"name":"` + tokName + `","value":"` + encryptStr(t, key, "old") + `","linkedId":null}`),
		json.RawMessage(`{"type":0,"name":"` + encryptStr(t, key, "Old") + `","value":"` + encryptStr(t, key, "gone") + `","linkedId":null}`),
		json.RawMessage(`{"type":3,"name":"` + linkName + `","value":null,"linkedId":100}`),
	}
	// Token changed and turned into a text field, Old removed, Link retargeted,
	// New added, PIN untouched.
	fields := []cipherCustomField{
		{Type: client.FieldTypeText, Name: "Token", Value: "new"},
		{Type: client.FieldTypeHidden, Name: "PIN", Value: "1234"},
		{Type: client.FieldTypeLinked, Name: "Link", Value: "password"},
		{Type: client.FieldTypeBoolean, Name: "New", Value: "true"},
	}

	got, err := applyCustomFields(rawFields, fields, key)
	if err != nil {
		t.Fatalf("applyCustomFields: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d fields, want 4", len(got))
	}

	token := decodeObject(t, got[0])
	if string(token["type"]) != "0" || compactJSON(t, token["name"]) != `"`+tokName+`"` ||
		decryptJSONString(t, key, token["value"]) != "new" {
		t.Errorf("changed field: %s", got[0])
	}
	if string(got[1]) != string(rawFields[0]) {
		t.Errorf("unchanged field not kept verbatim: %s", got[1])
	}
	link := decodeObject(t, got[2])
	if string(link["type"]) != "3" || string(link["linkedId"]) != "101" || string(link["value"]) != "null" {
		t.Errorf("linked field: %s", got[2])
	}
	added := decodeObject(t, got[3])
	if string(added["type"]) != "2" || decryptJSONString(t, key, added["name"]) != "New" ||
		decryptJSONString(t, key, added["value"]) != "true" || string(added["linkedId"]) != "null" {
		t.Errorf("new field: %s", got[3])
	}
}

func TestApplyCustomFields_DuplicateNamesMatchInOrder(t *testing.T) {
	key := testKey()
	rawFields := []json.RawMessage{
		json.RawMessage(`{"type":0,"name":"` + encryptStr(t, key, "dup") + `","value":"` + encryptStr(t, key, "one") + `"}`),
		json.RawMessage(`{"type":1,"name":"` + encryptStr(t, key, "dup") + `","value":"` + encryptStr(t, key, "two") + `"}`),
	}
	fields := []cipherCustomField{
		{Type: client.FieldTypeText, Name: "dup", Value: "one"},
		{Type: client.FieldTypeHidden, Name: "dup", Value: "two"},
	}

	got, err := applyCustomFields(rawFields, fields, key)
	if err != nil {
		t.Fatalf("applyCustomFields: %v", err)
	}
	if len(got) != 2 || string(got[0]) != string(rawFields[0]) || string(got[1]) != string(rawFields[1]) {
		t.Errorf("got %s", got)
	}
}

func TestApplyCustomFields_InvalidLinkedTarget(t *testing.T) {
	_, err := applyCustomFields(nil, []cipherCustomField{{Type: client.FieldTypeLinked, Name: "L", Value: "email"}}, testKey())
	if err == nil || !strings.Contains(err.Error(), "username or password") {
		t.Errorf("expected linked target error, got %v", err)
	}
}

func TestApplyCustomFields_UndecryptableFieldAborts(t *testing.T) {
	// Without the current plaintext a field cannot be matched, and guessing
	// could delete it — so the edit must fail instead.
	rawFields := []json.RawMessage{json.RawMessage(`{"type":0,"name":"2.bad|bad|bad","value":null}`)}
	if _, err := applyCustomFields(rawFields, nil, testKey()); err == nil {
		t.Error("expected an error")
	}
}

func TestEditRoundTrip_UntouchedEditorKeepsEverything(t *testing.T) {
	key := testKey()
	raw, _ := serverCipher(t, key)
	var c client.Cipher
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}

	original, err := decryptCipherToFields(&c, key)
	if err != nil {
		t.Fatalf("decryptCipherToFields: %v", err)
	}
	content := formatCipherForEditor(original)

	// Editing only a custom field leaves every other value as it was — also
	// the notes, whose trailing newline the editor format does not preserve.
	edited := strings.Replace(content, "hidden PIN: 1234", "hidden PIN: 5678", 1)
	u := diffEditFields(parseCipherFromEditor(content, client.CipherTypeLogin), parseCipherFromEditor(edited, client.CipherTypeLogin))
	if u.CustomFields == nil || u.Name != nil || u.Notes != nil || u.Password != nil || u.URLs != nil {
		t.Fatalf("unexpected changes: %+v", u)
	}
	body, err := buildEditCipher(raw, u, testUserID, key, testNow)
	if err != nil {
		t.Fatalf("buildEditCipher: %v", err)
	}
	in, out := decodeObject(t, raw), decodeObject(t, body)
	for _, k := range []string{"name", "notes", "login", "passwordHistory", "reprompt"} {
		if compactJSON(t, out[k]) != compactJSON(t, in[k]) {
			t.Errorf("%s changed:\n got %s\nwant %s", k, out[k], in[k])
		}
	}
	var fields []client.CipherField
	if err := json.Unmarshal(out["fields"], &fields); err != nil || len(fields) != 1 {
		t.Fatalf("fields: %s", out["fields"])
	}
	if f, err := decodeCustomField(fields[0], key); err != nil || f != (cipherCustomField{Type: client.FieldTypeHidden, Name: "PIN", Value: "5678"}) {
		t.Errorf("field: %+v, %v", f, err)
	}
}

func TestEditURLs(t *testing.T) {
	key := testKey()
	c := client.Cipher{Login: &client.CipherLogin{URIs: []client.CipherURI{
		{URI: encryptStr(t, key, "https://a.example")},
		{URI: encryptStr(t, key, "https://b.example")},
	}}}

	got, err := editURLs(&c, key, []string{"https://C.example", "HTTPS://A.EXAMPLE"}, []string{"https://B.example"})
	if err != nil {
		t.Fatalf("editURLs: %v", err)
	}
	if !urlsEqual(got, []string{"https://a.example", "https://C.example"}) {
		t.Errorf("got %v", got)
	}
}

func TestDecodeCustomField_EmptyValue(t *testing.T) {
	key := testKey()
	name := encryptStr(t, key, "Empty")
	f, err := decodeCustomField(client.CipherField{Name: &name}, key)
	if err != nil || f != (cipherCustomField{Name: "Empty"}) {
		t.Errorf("got %+v, %v", f, err)
	}
	if _, err := crypto.Decrypt("", key); err != nil {
		t.Errorf("empty cipher string should decrypt to nothing: %v", err)
	}
}

func TestBuildEditCipher_FolderChange(t *testing.T) {
	key := testKey()
	raw, _ := serverCipher(t, key)

	body, err := buildEditCipher(raw, cipherUpdate{FolderID: strPtr("new-folder-id")}, testUserID, key, testNow)
	if err != nil {
		t.Fatalf("buildEditCipher: %v", err)
	}
	if got := decodeObject(t, body)["folderId"]; string(got) != `"new-folder-id"` {
		t.Errorf("folderId: got %s", got)
	}
}

func TestBuildEditCipher_FolderClear(t *testing.T) {
	key := testKey()
	raw, _ := serverCipher(t, key)

	body, err := buildEditCipher(raw, cipherUpdate{FolderID: strPtr("")}, testUserID, key, testNow)
	if err != nil {
		t.Fatalf("buildEditCipher: %v", err)
	}
	if got := decodeObject(t, body)["folderId"]; string(got) != "null" {
		t.Errorf("folderId: got %s, want null", got)
	}
}

func TestBuildEditCipher_FolderUntouched(t *testing.T) {
	key := testKey()
	raw, _ := serverCipher(t, key)

	body, err := buildEditCipher(raw, cipherUpdate{Name: strPtr("GitHub")}, testUserID, key, testNow)
	if err != nil {
		t.Fatalf("buildEditCipher: %v", err)
	}
	in, out := decodeObject(t, raw), decodeObject(t, body)
	if compactJSON(t, out["folderId"]) != compactJSON(t, in["folderId"]) {
		t.Errorf("folderId changed although nil: %s", out["folderId"])
	}
}

func TestEdit_AgainstServer_FolderChange(t *testing.T) {
	fake, local := setupEditServer(t)
	key := testKey()
	before := fake.state

	if err := sendEdit(local, nil, cipherUpdate{}, testUserID, key); err == nil {
		t.Fatal("expected an error for an empty raw payload")
	}

	raw, _, editKey, err := fetchEditBase("GitHub", local, false, key, nil)
	if err != nil {
		t.Fatalf("fetchEditBase: %v", err)
	}
	if err := sendEdit(local, raw, cipherUpdate{FolderID: strPtr("folder-2")}, testUserID, editKey); err != nil {
		t.Fatalf("sendEdit: %v", err)
	}

	after := fake.state
	// folderId is expected to change; everything else must be untouched.
	for _, k := range []string{"reprompt", "favorite", "notes"} {
		if compactJSON(t, after[k]) != compactJSON(t, before[k]) {
			t.Errorf("%s changed:\n got %s\nwant %s", k, after[k], before[k])
		}
	}
	if got := after["folderId"]; string(got) != `"folder-2"` {
		t.Errorf("folderId: got %s, want \"folder-2\"", got)
	}
}
