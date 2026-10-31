package client

import (
	"encoding/json"
	"testing"
)

func TestErrTwoFactorRequired_Error(t *testing.T) {
	err := &ErrTwoFactorRequired{
		Response: TwoFactorResponse{
			TwoFactorProviders: []string{"0", "1"},
			Error:              "invalid_grant",
			ErrorDescription:   "Two-factor authentication required.",
		},
	}

	errMsg := err.Error()
	if errMsg != "two-factor authentication required" {
		t.Fatalf("Expected 'two-factor authentication required', got '%s'", errMsg)
	}
}

func TestPreloginRequest_Marshal(t *testing.T) {
	req := PreloginRequest{Email: "test@example.com"}

	// Should be JSON serializable
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal PreloginRequest: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("Marshaled data should not be empty")
	}

	// Verify it can be unmarshaled
	var decoded PreloginRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal PreloginRequest: %v", err)
	}

	if decoded.Email != "test@example.com" {
		t.Fatalf("Email mismatch: got '%s', want 'test@example.com'", decoded.Email)
	}
}

func TestPreloginResponse_Marshal(t *testing.T) {
	resp := PreloginResponse{
		Kdf:            0,
		KdfIterations:  100000,
		KdfMemory:      64,
		KdfParallelism: 4,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal PreloginResponse: %v", err)
	}

	var decoded PreloginResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal PreloginResponse: %v", err)
	}

	if decoded.Kdf != 0 || decoded.KdfIterations != 100000 {
		t.Fatal("PreloginResponse roundtrip failed")
	}
}

func TestTokenResponse_Marshal(t *testing.T) {
	resp := TokenResponse{
		AccessToken:  "test_access_token",
		ExpiresIn:    3600,
		TokenType:    "Bearer",
		RefreshToken: "test_refresh_token",
		Key:          "test_key",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal TokenResponse: %v", err)
	}

	var decoded TokenResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal TokenResponse: %v", err)
	}

	if decoded.AccessToken != "test_access_token" || decoded.ExpiresIn != 3600 {
		t.Fatal("TokenResponse roundtrip failed")
	}
}

func TestCipher_Marshal(t *testing.T) {
	cipher := Cipher{
		ID:   "test-id",
		Type: 1,
		Data: CipherData{
			Name:     "My Password",
			Username: "user@example.com",
			Password: "secret",
		},
		Favorite: true,
	}

	data, err := json.Marshal(cipher)
	if err != nil {
		t.Fatalf("Failed to marshal Cipher: %v", err)
	}

	var decoded Cipher
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal Cipher: %v", err)
	}

	if decoded.ID != "test-id" || decoded.Data.Name != "My Password" {
		t.Fatal("Cipher roundtrip failed")
	}
}

// TestCipher_Unmarshal_APIFormat verifies that a Cipher parsed from the actual
// Bitwarden/Vaultwarden /api/sync response format correctly populates the
// top-level Name and Notes fields.  The real API places "name" and "notes" at
// the cipher object's top level (not inside a "data" wrapper), and "username",
// "password", "totp", "uris", "fido2Credentials" inside a "login" object.
//
// This test prevents the regression where Name was only modelled inside
// CipherData (json:"data") and was therefore always empty when parsing real
// API responses.
func TestCipher_Unmarshal_APIFormat(t *testing.T) {
	apiJSON := `{
		"id": "cipher-1",
		"organizationId": null,
		"folderId": null,
		"type": 1,
		"name": "2.encryptedName|iv|mac",
		"notes": "2.encryptedNotes|iv|mac",
		"data": {},
		"key": null,
		"favorite": false,
		"login": {
			"username": "2.encryptedUser|iv|mac",
			"password": "2.encryptedPass|iv|mac",
			"totp": null,
			"uris": [{"uri": "2.encryptedURI|iv|mac", "match": null}],
			"fido2Credentials": null
		},
		"fields": null,
		"collectionIds": [],
		"revisionDate": "2000-01-01T00:00:00.000Z",
		"deletedDate": null
	}`

	var c Cipher
	if err := json.Unmarshal([]byte(apiJSON), &c); err != nil {
		t.Fatalf("Failed to unmarshal API-format cipher: %v", err)
	}

	if c.ID != "cipher-1" {
		t.Errorf("ID = %q, want %q", c.ID, "cipher-1")
	}
	if c.Name != "2.encryptedName|iv|mac" {
		t.Errorf("Name = %q, want %q", c.Name, "2.encryptedName|iv|mac")
	}
	if c.Notes == nil || *c.Notes != "2.encryptedNotes|iv|mac" {
		t.Errorf("Notes = %v, want %q", c.Notes, "2.encryptedNotes|iv|mac")
	}
	if c.Data.Name != "" {
		t.Errorf("Data.Name should be empty when API has no data.name, got %q", c.Data.Name)
	}
	if c.Login == nil {
		t.Fatal("Login should not be nil")
	}
	if c.Login.Username != "2.encryptedUser|iv|mac" {
		t.Errorf("Login.Username = %q, want %q", c.Login.Username, "2.encryptedUser|iv|mac")
	}
	if c.Login.Password != "2.encryptedPass|iv|mac" {
		t.Errorf("Login.Password = %q, want %q", c.Login.Password, "2.encryptedPass|iv|mac")
	}
	if len(c.Login.URIs) != 1 || c.Login.URIs[0].URI != "2.encryptedURI|iv|mac" {
		t.Errorf("Login.URIs = %+v, want 1 URI", c.Login.URIs)
	}
}

// TestCipher_Unmarshal_APIFormat_NilNotes verifies that a null notes field in
// the API response leaves the top-level Notes pointer nil.
func TestCipher_Unmarshal_APIFormat_NilNotes(t *testing.T) {
	apiJSON := `{
		"id": "c1",
		"type": 1,
		"name": "2.name|iv|mac",
		"notes": null,
		"data": {}
	}`

	var c Cipher
	if err := json.Unmarshal([]byte(apiJSON), &c); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
	if c.Notes != nil {
		t.Errorf("Notes should be nil for null notes, got %q", *c.Notes)
	}
	if c.Name != "2.name|iv|mac" {
		t.Errorf("Name = %q, want %q", c.Name, "2.name|iv|mac")
	}
}

// TestCipher_Unmarshal_APIFormat_WithFido2Credentials verifies that passkeys
// nested inside the login object of a real API response are correctly parsed.
func TestCipher_Unmarshal_APIFormat_WithFido2Credentials(t *testing.T) {
	apiJSON := `{
		"id": "c1",
		"type": 1,
		"name": "2.name|iv|mac",
		"notes": null,
		"data": {},
		"login": {
			"username": "2.user|iv|mac",
			"password": "2.pass|iv|mac",
			"fido2Credentials": [
				{
					"credentialId": "2.cid|cid|m=",
					"keyType": "2.kt|kt|m=",
					"keyAlgorithm": "2.ka|ka|m=",
					"keyCurve": "2.kv|kv|m=",
					"keyValue": "2.kvv|kvv|m=",
					"rpId": "2.rpid|rpid|m=",
					"rpName": null,
					"userHandle": "2.uh|uh|m=",
					"userName": "2.un|un|m=",
					"counter": "2.0|0|m=",
					"discoverable": "2.true|true|m=",
					"creationDate": "2023-01-01T12:00:00.0000000Z"
				}
			]
		}
	}`

	var c Cipher
	if err := json.Unmarshal([]byte(apiJSON), &c); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
	if c.Login == nil || len(c.Login.Fido2Credentials) != 1 {
		t.Fatalf("expected 1 Fido2Credential on Login, got Login=%v", c.Login)
	}
	cred := c.Login.Fido2Credentials[0]
	if cred.CredentialId != "2.cid|cid|m=" {
		t.Errorf("CredentialId = %q", cred.CredentialId)
	}
	if cred.RpId != "2.rpid|rpid|m=" {
		t.Errorf("RpId = %q", cred.RpId)
	}
	if cred.CreationDate != "2023-01-01T12:00:00.0000000Z" {
		t.Errorf("CreationDate = %q", cred.CreationDate)
	}
	if cred.RpName != nil {
		t.Errorf("RpName should be nil, got %q", *cred.RpName)
	}
}

func TestCipherURI_Marshal(t *testing.T) {
	match := 0
	cipher := Cipher{
		ID:   "test-id",
		Type: 1,
		Data: CipherData{
			Name:     "My Password",
			Username: "user@example.com",
			Password: "secret",
			URIs: []CipherURI{
				{URI: "2.encrypteduri==|iv==|mac==", Match: nil},
				{URI: "2.encrypteduri2==|iv==|mac==", Match: &match},
			},
		},
	}

	data, err := json.Marshal(cipher)
	if err != nil {
		t.Fatalf("Failed to marshal Cipher with URIs: %v", err)
	}

	var decoded Cipher
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal Cipher with URIs: %v", err)
	}

	if len(decoded.Data.URIs) != 2 {
		t.Fatalf("Expected 2 URIs, got %d", len(decoded.Data.URIs))
	}
	if decoded.Data.URIs[0].URI != "2.encrypteduri==|iv==|mac==" {
		t.Fatalf("URI[0] mismatch: got '%s'", decoded.Data.URIs[0].URI)
	}
	if decoded.Data.URIs[0].Match != nil {
		t.Fatal("URI[0] Match should be nil")
	}
	if decoded.Data.URIs[1].Match == nil || *decoded.Data.URIs[1].Match != 0 {
		t.Fatal("URI[1] Match should be 0")
	}
}

func TestFolder_Marshal(t *testing.T) {
	folder := Folder{
		ID:   "folder-id",
		Name: "Work",
	}

	data, err := json.Marshal(folder)
	if err != nil {
		t.Fatalf("Failed to marshal Folder: %v", err)
	}

	var decoded Folder
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal Folder: %v", err)
	}

	if decoded.ID != "folder-id" || decoded.Name != "Work" {
		t.Fatal("Folder roundtrip failed")
	}
}

func TestProfile_Marshal(t *testing.T) {
	profile := Profile{
		ID:    "profile-id",
		Email: "test@example.com",
		Key:   "encrypted-key",
	}

	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("Failed to marshal Profile: %v", err)
	}

	var decoded Profile
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal Profile: %v", err)
	}

	if decoded.Email != "test@example.com" {
		t.Fatal("Profile roundtrip failed")
	}
}

func TestSyncResponse_Marshal(t *testing.T) {
	resp := SyncResponse{
		Profile: Profile{
			ID:    "id",
			Email: "test@example.com",
			Key:   "key",
		},
		Folders: []Folder{
			{ID: "f1", Name: "Work"},
		},
		Ciphers: []Cipher{
			{
				ID:   "c1",
				Type: 1,
				Data: CipherData{Name: "Test"},
			},
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal SyncResponse: %v", err)
	}

	var decoded SyncResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal SyncResponse: %v", err)
	}

	if len(decoded.Folders) != 1 || len(decoded.Ciphers) != 1 {
		t.Fatal("SyncResponse roundtrip failed")
	}
}

func TestTwoFactorResponse_Marshal(t *testing.T) {
	resp := TwoFactorResponse{
		TwoFactorProviders: []string{"0", "3"},
		Error:              "invalid_grant",
		ErrorDescription:   "Two-factor required.",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal TwoFactorResponse: %v", err)
	}

	var decoded TwoFactorResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal TwoFactorResponse: %v", err)
	}

	if len(decoded.TwoFactorProviders) != 2 || decoded.Error != "invalid_grant" {
		t.Fatal("TwoFactorResponse roundtrip failed")
	}
}

func TestProfileOrganization_Marshal(t *testing.T) {
	org := ProfileOrganization{
		ID:  "org-123",
		Key: "encrypted-org-key",
	}

	data, err := json.Marshal(org)
	if err != nil {
		t.Fatalf("Failed to marshal ProfileOrganization: %v", err)
	}

	var decoded ProfileOrganization
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal ProfileOrganization: %v", err)
	}

	if decoded.ID != "org-123" || decoded.Key != "encrypted-org-key" {
		t.Fatal("ProfileOrganization roundtrip failed")
	}
}

func TestKdfConfig_Marshal_NilOptionals(t *testing.T) {
	cfg := KdfConfig{
		KdfType:    0,
		Iterations: 600000,
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Failed to marshal KdfConfig: %v", err)
	}

	var decoded KdfConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal KdfConfig: %v", err)
	}

	if decoded.KdfType != 0 || decoded.Iterations != 600000 {
		t.Fatal("KdfConfig roundtrip failed")
	}
	if decoded.Memory != nil || decoded.Parallelism != nil {
		t.Fatal("nil optional fields should remain nil after roundtrip")
	}
}

func TestKdfConfig_Marshal_WithOptionalFields(t *testing.T) {
	mem := 64
	par := 4
	cfg := KdfConfig{
		KdfType:     1,
		Iterations:  3,
		Memory:      &mem,
		Parallelism: &par,
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Failed to marshal KdfConfig with optional fields: %v", err)
	}

	var decoded KdfConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal KdfConfig with optional fields: %v", err)
	}

	if decoded.KdfType != 1 || decoded.Iterations != 3 {
		t.Fatal("KdfConfig optional fields roundtrip: wrong base fields")
	}
	if decoded.Memory == nil || *decoded.Memory != 64 {
		t.Fatal("KdfConfig optional fields roundtrip: wrong memory")
	}
	if decoded.Parallelism == nil || *decoded.Parallelism != 4 {
		t.Fatal("KdfConfig optional fields roundtrip: wrong parallelism")
	}
}

func TestMasterPasswordUnlock_Marshal(t *testing.T) {
	mem := 64
	par := 4
	unlock := MasterPasswordUnlock{
		Kdf: KdfConfig{
			KdfType:     1,
			Iterations:  3,
			Memory:      &mem,
			Parallelism: &par,
		},
		Salt: "user@example.com",
	}

	data, err := json.Marshal(unlock)
	if err != nil {
		t.Fatalf("Failed to marshal MasterPasswordUnlock: %v", err)
	}

	var decoded MasterPasswordUnlock
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal MasterPasswordUnlock: %v", err)
	}

	if decoded.Salt != "user@example.com" {
		t.Fatal("MasterPasswordUnlock roundtrip: wrong salt")
	}
	if decoded.Kdf.KdfType != 1 || decoded.Kdf.Iterations != 3 {
		t.Fatal("MasterPasswordUnlock roundtrip: wrong kdf fields")
	}
}

func TestUserDecryption_Marshal(t *testing.T) {
	mem := 64
	par := 4
	ud := UserDecryption{
		MasterPasswordUnlock: MasterPasswordUnlock{
			Kdf: KdfConfig{
				KdfType:     0,
				Iterations:  600000,
				Memory:      &mem,
				Parallelism: &par,
			},
			Salt: "test@example.com",
		},
	}

	data, err := json.Marshal(ud)
	if err != nil {
		t.Fatalf("Failed to marshal UserDecryption: %v", err)
	}

	var decoded UserDecryption
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal UserDecryption: %v", err)
	}

	if decoded.MasterPasswordUnlock.Salt != "test@example.com" {
		t.Fatal("UserDecryption roundtrip: wrong salt")
	}
	if decoded.MasterPasswordUnlock.Kdf.KdfType != 0 {
		t.Fatal("UserDecryption roundtrip: wrong kdf type")
	}
}

func TestCipherLogin_Marshal(t *testing.T) {
	login := CipherLogin{
		Username: "user@example.com",
		Password: "hunter2",
		URIs: []CipherURI{
			{URI: "https://example.com"},
		},
	}

	data, err := json.Marshal(login)
	if err != nil {
		t.Fatalf("Failed to marshal CipherLogin: %v", err)
	}

	var decoded CipherLogin
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal CipherLogin: %v", err)
	}

	if decoded.Username != "user@example.com" || decoded.Password != "hunter2" {
		t.Fatal("CipherLogin roundtrip: wrong username/password")
	}
	if len(decoded.URIs) != 1 || decoded.URIs[0].URI != "https://example.com" {
		t.Fatal("CipherLogin roundtrip: wrong URIs")
	}
	if decoded.Totp != nil {
		t.Fatal("CipherLogin roundtrip: Totp should be nil")
	}
}

func TestCipherLogin_Marshal_WithTotp(t *testing.T) {
	totpSecret := "JBSWY3DPEHPK3PXP"
	login := CipherLogin{
		Username: "user@example.com",
		Password: "hunter2",
		Totp:     &totpSecret,
	}

	data, err := json.Marshal(login)
	if err != nil {
		t.Fatalf("Failed to marshal CipherLogin with TOTP: %v", err)
	}

	var decoded CipherLogin
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal CipherLogin with TOTP: %v", err)
	}

	if decoded.Totp == nil || *decoded.Totp != totpSecret {
		t.Fatal("CipherLogin roundtrip: wrong Totp value")
	}
}

// TestFido2Credential_Marshal verifies that a single Fido2Credential
// roundtrips through JSON with all fields preserved, including the four
// nullable fields (rpName, userHandle, userName, userDisplayName).
func TestFido2Credential_Marshal(t *testing.T) {
	rpName := "Example Site"
	userHandle := "aGkK"
	userName := "alice@example.com"
	userDisplay := "Alice Example"
	cred := Fido2Credential{
		CredentialId:    "2.abc|def|ghi", // encrypted cipher string form
		KeyType:         "public-key",
		KeyAlgorithm:    "ECDSA",
		KeyCurve:        "P-256",
		KeyValue:        "2.kv|kv|kv",
		RpId:            "2.rpid|rpid|rpid",
		RpName:          &rpName,
		UserHandle:      &userHandle,
		UserName:        &userName,
		UserDisplayName: &userDisplay,
		Counter:         "2.0|0|0",
		Discoverable:    "2.true|true|true",
		CreationDate:    "2023-01-01T12:00:00.0000000Z",
	}

	data, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("Failed to marshal Fido2Credential: %v", err)
	}

	var decoded Fido2Credential
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal Fido2Credential: %v", err)
	}

	if decoded.CredentialId != cred.CredentialId ||
		decoded.KeyType != cred.KeyType ||
		decoded.KeyAlgorithm != cred.KeyAlgorithm ||
		decoded.KeyCurve != cred.KeyCurve ||
		decoded.KeyValue != cred.KeyValue ||
		decoded.RpId != cred.RpId ||
		decoded.Counter != cred.Counter ||
		decoded.Discoverable != cred.Discoverable ||
		decoded.CreationDate != cred.CreationDate {
		t.Fatalf("Fido2Credential roundtrip mismatch: got %+v", decoded)
	}
	if decoded.RpName == nil || *decoded.RpName != rpName {
		t.Errorf("Fido2Credential.RpName = %v, want %q", decoded.RpName, rpName)
	}
	if decoded.UserHandle == nil || *decoded.UserHandle != userHandle {
		t.Errorf("Fido2Credential.UserHandle = %v, want %q", decoded.UserHandle, userHandle)
	}
	if decoded.UserName == nil || *decoded.UserName != userName {
		t.Errorf("Fido2Credential.UserName = %v, want %q", decoded.UserName, userName)
	}
	if decoded.UserDisplayName == nil || *decoded.UserDisplayName != userDisplay {
		t.Errorf("Fido2Credential.UserDisplayName = %v, want %q", decoded.UserDisplayName, userDisplay)
	}
}

// TestCipherLogin_Marshal_WithFido2Credentials verifies that passkeys on a
// CipherLogin survive a marshal/unmarshal roundtrip.
func TestCipherLogin_Marshal_WithFido2Credentials(t *testing.T) {
	login := CipherLogin{
		Username: "user@example.com",
		Password: "hunter2",
		Fido2Credentials: []Fido2Credential{
			{
				CredentialId: "2.cid|cid|cid",
				KeyType:      "public-key",
				KeyAlgorithm: "ECDSA",
				KeyCurve:     "P-256",
				KeyValue:     "2.kv|kv|kv",
				RpId:         "2.rpid|rpid|rpid",
				Counter:      "2.0|0|0",
				Discoverable: "2.true|true|true",
				CreationDate: "2023-01-01T12:00:00.0000000Z",
			},
		},
	}

	data, err := json.Marshal(login)
	if err != nil {
		t.Fatalf("Failed to marshal CipherLogin with Fido2Credentials: %v", err)
	}

	var decoded CipherLogin
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal CipherLogin with Fido2Credentials: %v", err)
	}

	if len(decoded.Fido2Credentials) != 1 {
		t.Fatalf("CipherLogin roundtrip: expected 1 Fido2Credential, got %d", len(decoded.Fido2Credentials))
	}
	got := decoded.Fido2Credentials[0]
	if got.CredentialId != login.Fido2Credentials[0].CredentialId {
		t.Errorf("Fido2Credential.CredentialId = %q, want %q", got.CredentialId, login.Fido2Credentials[0].CredentialId)
	}
	if got.RpId != login.Fido2Credentials[0].RpId {
		t.Errorf("Fido2Credential.RpId = %q, want %q", got.RpId, login.Fido2Credentials[0].RpId)
	}
	if got.CreationDate != login.Fido2Credentials[0].CreationDate {
		t.Errorf("Fido2Credential.CreationDate = %q, want %q", got.CreationDate, login.Fido2Credentials[0].CreationDate)
	}
}

// TestCipher_Marshal_WithFido2Credentials verifies that passkeys survive a
// full Cipher marshal/unmarshal roundtrip whether stored on Cipher.Login
// (Vaultwarden primary) or Cipher.Data (Bitwarden legacy).
func TestCipher_Marshal_WithFido2Credentials(t *testing.T) {
	cred := Fido2Credential{
		CredentialId: "2.cid|cid|cid",
		KeyType:      "public-key",
		KeyAlgorithm: "ECDSA",
		KeyCurve:     "P-256",
		KeyValue:     "2.kv|kv|kv",
		RpId:         "2.rpid|rpid|rpid",
		Counter:      "2.0|0|0",
		Discoverable: "2.true|true|true",
		CreationDate: "2023-01-01T12:00:00.0000000Z",
	}

	t.Run("on Login", func(t *testing.T) {
		c := Cipher{
			ID:   "test-id",
			Type: 1,
			Data: CipherData{Name: "My Password"},
			Login: &CipherLogin{
				Username:         "user@example.com",
				Fido2Credentials: []Fido2Credential{cred},
			},
		}
		data, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var decoded Cipher
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if decoded.Login == nil || len(decoded.Login.Fido2Credentials) != 1 {
			t.Fatalf("expected 1 Fido2Credential on Login, got Login=%v", decoded.Login)
		}
	})
	t.Run("on Data", func(t *testing.T) {
		c := Cipher{
			ID:   "test-id",
			Type: 1,
			Data: CipherData{
				Name:             "My Password",
				Fido2Credentials: []Fido2Credential{cred},
			},
		}
		data, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var decoded Cipher
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(decoded.Data.Fido2Credentials) != 1 {
			t.Fatalf("expected 1 Fido2Credential on Data, got %d", len(decoded.Data.Fido2Credentials))
		}
	})
}

func TestSyncResponse_Marshal_WithUserDecryption(t *testing.T) {
	mem := 64
	par := 4
	resp := SyncResponse{
		Profile: Profile{
			ID:    "id",
			Email: "test@example.com",
			Key:   "key",
		},
		UserDecryption: &UserDecryption{
			MasterPasswordUnlock: MasterPasswordUnlock{
				Kdf: KdfConfig{
					KdfType:     1,
					Iterations:  3,
					Memory:      &mem,
					Parallelism: &par,
				},
				Salt: "test@example.com",
			},
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal SyncResponse with UserDecryption: %v", err)
	}

	var decoded SyncResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal SyncResponse with UserDecryption: %v", err)
	}

	if decoded.UserDecryption == nil {
		t.Fatal("SyncResponse: UserDecryption should not be nil after roundtrip")
	}
	if decoded.UserDecryption.MasterPasswordUnlock.Salt != "test@example.com" {
		t.Fatal("SyncResponse: wrong UserDecryption salt")
	}
}

func TestProfile_Marshal_WithOrganizations(t *testing.T) {
	profile := Profile{
		ID:         "profile-id",
		Email:      "test@example.com",
		Key:        "encrypted-key",
		PrivateKey: "encrypted-private-key",
		Organizations: []ProfileOrganization{
			{ID: "org-1", Key: "encrypted-org-key"},
			{ID: "org-2", Key: "encrypted-org-key-2"},
		},
	}

	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("Failed to marshal Profile with Organizations: %v", err)
	}

	var decoded Profile
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal Profile with Organizations: %v", err)
	}

	if decoded.PrivateKey != "encrypted-private-key" {
		t.Fatal("Profile roundtrip: wrong PrivateKey")
	}
	if len(decoded.Organizations) != 2 {
		t.Fatalf("Profile roundtrip: want 2 orgs, got %d", len(decoded.Organizations))
	}
	if decoded.Organizations[0].ID != "org-1" {
		t.Fatal("Profile roundtrip: wrong org ID")
	}
}

func TestCollection_Unmarshal_APIFormat(t *testing.T) {
	// Shape as returned in the "collections" array of /api/sync.
	raw := `{
		"id": "col-1",
		"organizationId": "org-1",
		"name": "2.iv|ct|mac",
		"externalId": null,
		"readOnly": false,
		"hidePasswords": false,
		"manage": true,
		"type": 0,
		"object": "collectionDetails"
	}`

	var col Collection
	if err := json.Unmarshal([]byte(raw), &col); err != nil {
		t.Fatalf("Failed to unmarshal Collection: %v", err)
	}

	if col.ID != "col-1" {
		t.Errorf("ID: got %q", col.ID)
	}
	if col.OrganizationID != "org-1" {
		t.Errorf("OrganizationID: got %q", col.OrganizationID)
	}
	if col.Name != "2.iv|ct|mac" {
		t.Errorf("Name: got %q", col.Name)
	}
	if !col.Manage || col.ReadOnly || col.HidePasswords {
		t.Errorf("permissions: %+v", col)
	}
}

func TestSyncResponse_Unmarshal_CollectionsAndOrganizationName(t *testing.T) {
	raw := `{
		"profile": {
			"id": "profile-1",
			"email": "user@example.com",
			"key": "2.pk|pk|pk",
			"organizations": [
				{"id": "org-1", "name": "Family", "key": "4.rsa-encrypted-org-key"}
			]
		},
		"folders": [],
		"ciphers": [],
		"collections": [
			{"id": "col-1", "organizationId": "org-1", "name": "2.wife|wife|wife"},
			{"id": "col-2", "organizationId": "org-1", "name": "2.kid|kid|kid"}
		]
	}`

	var resp SyncResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("Failed to unmarshal SyncResponse: %v", err)
	}

	if len(resp.Collections) != 2 {
		t.Fatalf("expected 2 collections, got %d", len(resp.Collections))
	}
	if resp.Collections[0].ID != "col-1" || resp.Collections[0].OrganizationID != "org-1" {
		t.Errorf("unexpected first collection: %+v", resp.Collections[0])
	}
	if len(resp.Profile.Organizations) != 1 {
		t.Fatalf("expected 1 organization, got %d", len(resp.Profile.Organizations))
	}
	// Organization names are plaintext and used to resolve --organization values.
	if resp.Profile.Organizations[0].Name != "Family" {
		t.Errorf("organization name: got %q, want %q", resp.Profile.Organizations[0].Name, "Family")
	}
}

func TestShareCipherRequest_Marshal(t *testing.T) {
	req := ShareCipherRequest{
		Cipher:        json.RawMessage(`{"id":"c1","organizationId":"org-1","futureField":true}`),
		CollectionIDs: []string{"col-1", "col-2"},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal ShareCipherRequest: %v", err)
	}

	var decoded struct {
		Cipher        map[string]any `json:"cipher"`
		CollectionIDs []string       `json:"collectionIds"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal ShareCipherRequest: %v", err)
	}

	// The raw cipher must be embedded as an object, not as a JSON string, and
	// keep the fields bx does not model.
	if decoded.Cipher["organizationId"] != "org-1" || decoded.Cipher["futureField"] != true {
		t.Errorf("cipher roundtrip failed: %v", decoded.Cipher)
	}
	if len(decoded.CollectionIDs) != 2 {
		t.Errorf("collectionIds: got %v", decoded.CollectionIDs)
	}
}

func TestCipherCollectionsRequest_Marshal(t *testing.T) {
	data, err := json.Marshal(CipherCollectionsRequest{CollectionIDs: []string{"col-1"}})
	if err != nil {
		t.Fatalf("Failed to marshal CipherCollectionsRequest: %v", err)
	}
	if string(data) != `{"collectionIds":["col-1"]}` {
		t.Errorf("got %s", string(data))
	}
}
