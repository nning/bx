package client

import "encoding/json"

// Cipher item type constants (matches Bitwarden's type field).
const (
	CipherTypeLogin    = 1
	CipherTypeNote     = 2
	CipherTypeCard     = 3
	CipherTypeIdentity = 4
	CipherTypeSshKey   = 5
)

// Custom field type constants (matches Bitwarden's field type).
const (
	FieldTypeText    = 0
	FieldTypeHidden  = 1
	FieldTypeBoolean = 2
	FieldTypeLinked  = 3
)

type PreloginRequest struct {
	Email string `json:"email"`
}

type PreloginResponse struct {
	Kdf            int `json:"kdf"`
	KdfIterations  int `json:"kdfIterations"`
	KdfMemory      int `json:"kdfMemory,omitempty"`
	KdfParallelism int `json:"kdfParallelism,omitempty"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Key          string `json:"Key"`
}

type TwoFactorResponse struct {
	TwoFactorProviders []string `json:"TwoFactorProviders"`
	Error              string   `json:"error"`
	ErrorDescription   string   `json:"error_description"`
}

type ErrTwoFactorRequired struct {
	Response TwoFactorResponse
}

func (e *ErrTwoFactorRequired) Error() string {
	return "two-factor authentication required"
}

type SyncResponse struct {
	Profile        Profile         `json:"profile"`
	Folders        []Folder        `json:"folders"`
	Ciphers        []Cipher        `json:"ciphers"`
	Collections    []Collection    `json:"collections"`
	UserDecryption *UserDecryption `json:"userDecryption"`
}

type UserDecryption struct {
	MasterPasswordUnlock MasterPasswordUnlock `json:"masterPasswordUnlock"`
}

type MasterPasswordUnlock struct {
	Kdf  KdfConfig `json:"kdf"`
	Salt string    `json:"salt"`
}

type KdfConfig struct {
	KdfType     int  `json:"kdfType"`
	Iterations  int  `json:"iterations"`
	Memory      *int `json:"memory"`
	Parallelism *int `json:"parallelism"`
}

// ProfileOrganization is one entry of profile.organizations in the sync
// response.  Name is plaintext (organization names are not encrypted); Key is
// the organization's symmetric key, RSA-encrypted to the account's public key.
type ProfileOrganization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

type Profile struct {
	ID            string                `json:"id"`
	Email         string                `json:"email"`
	Key           string                `json:"key"`
	PrivateKey    string                `json:"privateKey"`
	Organizations []ProfileOrganization `json:"organizations"`
}

type Folder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Collection is an organization collection as returned in the sync response.
// Name is encrypted with the owning organization's symmetric key (not the
// account key).  ReadOnly, HidePasswords, and Manage describe the active
// user's permissions on the collection.
type Collection struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"`
	ReadOnly       bool   `json:"readOnly"`
	HidePasswords  bool   `json:"hidePasswords"`
	Manage         bool   `json:"manage"`
	Type           int    `json:"type"`
}

type Cipher struct {
	ID              string                  `json:"id"`
	OrganizationID  *string                 `json:"organizationId"`
	FolderID        *string                 `json:"folderId"`
	Type            int                     `json:"type"`
	Name            string                  `json:"name"`
	Notes           *string                 `json:"notes"`
	Data            CipherData              `json:"data"`
	Key             *string                 `json:"key"`
	Favorite        bool                    `json:"favorite"`
	Login           *CipherLogin            `json:"login"`
	Card            *CipherCard             `json:"card,omitempty"`
	Identity        *CipherIdentity         `json:"identity,omitempty"`
	SshKey          *CipherSshKey           `json:"sshKey,omitempty"`
	Fields          []CipherField           `json:"fields"`
	Attachments     []CipherAttachment      `json:"attachments,omitempty"`
	PasswordHistory []CipherPasswordHistory `json:"passwordHistory,omitempty"`
	CollectionIDs   []string                `json:"collectionIds"`
	RevisionDate    string                  `json:"revisionDate"`
	DeletedDate     *string                 `json:"deletedDate"`
}

type CipherURI struct {
	URI   string `json:"uri"`
	Match *int   `json:"match"`
}

// CipherField represents a custom field on a cipher.  In Vaultwarden
// custom fields are stored at the Cipher level under the "fields" key;
// in Bitwarden they may appear inside CipherData as "customFields".
// Both Name and Value are encrypted cipher strings.  Type and LinkedID are
// plaintext; they must be carried along so that writing a field back does not
// turn a hidden or linked field into a text field.
type CipherField struct {
	Type     int     `json:"type"`
	Name     *string `json:"name"`
	Value    string  `json:"value"`
	LinkedID *int    `json:"linkedId"`
}

// Fido2Credential models a single passkey stored on a login cipher, as it
// appears in the on-disk vault cache under login.fido2Credentials. Twelve of
// these fields arrive as Bitwarden encrypted cipher strings (form
// "2.iv|ct|mac") and are decrypted on demand using the cipher's item key;
// CreationDate is a plaintext ISO-8601 string. The nullable fields
// (rpName, userHandle, userName, userDisplayName) follow Bitwarden's
// upstream spec. Counter and Discoverable are string-encoded on the wire —
// the client parses them after decryption.
type Fido2Credential struct {
	CredentialId    string  `json:"credentialId"`
	KeyType         string  `json:"keyType"`
	KeyAlgorithm    string  `json:"keyAlgorithm"`
	KeyCurve        string  `json:"keyCurve"`
	KeyValue        string  `json:"keyValue"`
	RpId            string  `json:"rpId"`
	RpName          *string `json:"rpName,omitempty"`
	UserHandle      *string `json:"userHandle,omitempty"`
	UserName        *string `json:"userName,omitempty"`
	UserDisplayName *string `json:"userDisplayName,omitempty"`
	Counter         string  `json:"counter"`
	Discoverable    string  `json:"discoverable"`
	CreationDate    string  `json:"creationDate"`
}

type CipherData struct {
	Name             string            `json:"name"`
	Username         string            `json:"username"`
	Password         string            `json:"password"`
	Notes            *string           `json:"notes"`
	Totp             *string           `json:"totp"`
	URIs             []CipherURI       `json:"uris"`
	CustomFields     []CipherField     `json:"customFields"`
	Fido2Credentials []Fido2Credential `json:"fido2Credentials,omitempty"`
}

type CipherLogin struct {
	Username         string            `json:"username"`
	Password         string            `json:"password"`
	Totp             *string           `json:"totp"`
	URIs             []CipherURI       `json:"uris"`
	Fido2Credentials []Fido2Credential `json:"fido2Credentials,omitempty"`
}

// CipherCard holds the card data of a card item (type 3).  Every field arrives
// as an encrypted cipher string and is decrypted on demand with the item key.
type CipherCard struct {
	CardholderName string `json:"cardholderName"`
	Brand          string `json:"brand"`
	Number         string `json:"number"`
	ExpMonth       string `json:"expMonth"`
	ExpYear        string `json:"expYear"`
	Code           string `json:"code"`
}

// CipherIdentity holds the identity data of an identity item (type 4).  Every
// field arrives as an encrypted cipher string and is decrypted on demand with
// the item key.
type CipherIdentity struct {
	Title          string `json:"title"`
	FirstName      string `json:"firstName"`
	MiddleName     string `json:"middleName"`
	LastName       string `json:"lastName"`
	Address1       string `json:"address1"`
	Address2       string `json:"address2"`
	Address3       string `json:"address3"`
	City           string `json:"city"`
	State          string `json:"state"`
	PostalCode     string `json:"postalCode"`
	Country        string `json:"country"`
	Company        string `json:"company"`
	Email          string `json:"email"`
	Phone          string `json:"phone"`
	Username       string `json:"username"`
	SSN            string `json:"ssn"`
	PassportNumber string `json:"passportNumber"`
	LicenseNumber  string `json:"licenseNumber"`
}

// CipherSshKey holds the SSH key data of an SSH key item (type 5).  Every field
// arrives as an encrypted cipher string and is decrypted on demand with the
// item key.
type CipherSshKey struct {
	PrivateKey     string `json:"privateKey"`
	PublicKey      string `json:"publicKey"`
	KeyFingerprint string `json:"keyFingerprint"`
}

// CipherAttachment describes one attachment of a cipher.  FileName and Key are
// encrypted cipher strings: Key wraps the attachment's own 64-byte encryption
// key with the item key, and the downloaded file is 0x02 || IV || MAC || ciphertext
// encrypted with that attachment key.  Size arrives as a number or a string
// depending on the server, so it is decoded as json.Number.
type CipherAttachment struct {
	ID       string      `json:"id"`
	FileName string      `json:"fileName"`
	Key      string      `json:"key"`
	Size     json.Number `json:"size"`
	SizeName string      `json:"sizeName,omitempty"`
}

// CipherPasswordHistory is one previous password of a login item.  Password is
// an encrypted cipher string; LastUsedDate is a plaintext ISO-8601 timestamp.
type CipherPasswordHistory struct {
	Password     string `json:"password"`
	LastUsedDate string `json:"lastUsedDate"`
}

// CipherRequest is the body sent to POST /api/ciphers and PUT /api/ciphers/{id}.
type CipherRequest struct {
	Type                  int                `json:"type"`
	OrganizationID        *string            `json:"organizationId,omitempty"`
	FolderID              *string            `json:"folderId,omitempty"`
	Name                  string             `json:"name"`            // encrypted
	Notes                 *string            `json:"notes,omitempty"` // encrypted
	Key                   *string            `json:"key,omitempty"`   // per-item key (encrypted), if used
	Favorite              bool               `json:"favorite"`
	Login                 *CipherLoginReq    `json:"login,omitempty"`
	Card                  *CipherCardReq     `json:"card,omitempty"`
	Identity              *CipherIdentityReq `json:"identity,omitempty"`
	SshKey                *CipherSshKeyReq   `json:"sshKey,omitempty"`
	CollectionIDs         []string           `json:"collectionIds,omitempty"`
	LastKnownRevisionDate string             `json:"lastKnownRevisionDate,omitempty"` // for conflict guard
	EncryptedFor          string             `json:"encryptedFor"`                    // ID of the user whose keys encrypted the item
}

// CipherLoginReq holds the encrypted login fields for a write request.
type CipherLoginReq struct {
	Username *string        `json:"username,omitempty"` // encrypted
	Password *string        `json:"password,omitempty"` // encrypted
	Totp     *string        `json:"totp,omitempty"`     // encrypted
	URIs     []CipherURIReq `json:"uris,omitempty"`
}

// CipherCardReq holds the encrypted card fields for a write request.  Absent
// fields are omitted so that the server stores null rather than an empty
// cipher string.
type CipherCardReq struct {
	CardholderName *string `json:"cardholderName,omitempty"` // encrypted
	Brand          *string `json:"brand,omitempty"`          // encrypted
	Number         *string `json:"number,omitempty"`         // encrypted
	ExpMonth       *string `json:"expMonth,omitempty"`       // encrypted
	ExpYear        *string `json:"expYear,omitempty"`        // encrypted
	Code           *string `json:"code,omitempty"`           // encrypted
}

// CipherIdentityReq holds the encrypted identity fields for a write request.
type CipherIdentityReq struct {
	Title          *string `json:"title,omitempty"`          // encrypted
	FirstName      *string `json:"firstName,omitempty"`      // encrypted
	MiddleName     *string `json:"middleName,omitempty"`     // encrypted
	LastName       *string `json:"lastName,omitempty"`       // encrypted
	Address1       *string `json:"address1,omitempty"`       // encrypted
	Address2       *string `json:"address2,omitempty"`       // encrypted
	Address3       *string `json:"address3,omitempty"`       // encrypted
	City           *string `json:"city,omitempty"`           // encrypted
	State          *string `json:"state,omitempty"`          // encrypted
	PostalCode     *string `json:"postalCode,omitempty"`     // encrypted
	Country        *string `json:"country,omitempty"`        // encrypted
	Company        *string `json:"company,omitempty"`        // encrypted
	Email          *string `json:"email,omitempty"`          // encrypted
	Phone          *string `json:"phone,omitempty"`          // encrypted
	Username       *string `json:"username,omitempty"`       // encrypted
	SSN            *string `json:"ssn,omitempty"`            // encrypted
	PassportNumber *string `json:"passportNumber,omitempty"` // encrypted
	LicenseNumber  *string `json:"licenseNumber,omitempty"`  // encrypted
}

// CipherSshKeyReq holds the encrypted SSH key fields for a write request.
type CipherSshKeyReq struct {
	PrivateKey     *string `json:"privateKey,omitempty"`     // encrypted
	PublicKey      *string `json:"publicKey,omitempty"`      // encrypted
	KeyFingerprint *string `json:"keyFingerprint,omitempty"` // encrypted
}

// CipherURIReq is a single URI entry in a write request.
type CipherURIReq struct {
	URI   string `json:"uri"`             // encrypted
	Match *int   `json:"match,omitempty"` // URI match type
}

// ShareCipherRequest is the body sent to PUT /api/ciphers/{id}/share, which
// transfers a personal item to an organization and assigns it to collections.
//
// Cipher is carried as raw JSON rather than a CipherRequest so that the item's
// complete server-side representation (custom fields, password history,
// passkeys, and any field bx does not model) can be forwarded verbatim after
// its encrypted values have been re-wrapped under the organization key.
type ShareCipherRequest struct {
	Cipher        json.RawMessage `json:"cipher"`
	CollectionIDs []string        `json:"collectionIds"`
}

// CipherCollectionsRequest is the body sent to PUT /api/ciphers/{id}/collections.
// It replaces the set of collections an organization item belongs to and
// requires no re-encryption, since ownership does not change.
type CipherCollectionsRequest struct {
	CollectionIDs []string `json:"collectionIds"`
}

// FolderRequest is the body sent to POST /api/folders and PUT /api/folders/{id}.
type FolderRequest struct {
	Name string `json:"name"` // encrypted
}

// AttachmentUploadRequest is the body sent to
// POST /api/ciphers/{id}/attachment/v2, which registers an attachment before
// the file is uploaded.  FileName and Key are encrypted cipher strings; Key
// wraps the attachment's own 64-byte encryption key with the item key.
type AttachmentUploadRequest struct {
	FileName    string `json:"fileName"` // encrypted
	FileSize    int64  `json:"fileSize"`
	Key         string `json:"key"` // encrypted
	AdminUpload bool   `json:"adminUpload"`
}

// AttachmentFileUploadResponse is returned by
// POST /api/ciphers/{id}/attachment/v2.  FileUploadType 0 is the direct flow
// (POST multipart data to URL, which is an API route), FileUploadType 1
// is the Azure blob flow (PUT with the x-ms-blob-type header).
type AttachmentFileUploadResponse struct {
	Object         string `json:"object"`
	AttachmentID   string `json:"attachmentId"`
	URL            string `json:"url"`
	FileUploadType int    `json:"fileUploadType"`
}
