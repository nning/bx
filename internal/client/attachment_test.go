package client

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetAttachment(t *testing.T) {
	want := []byte("encrypted file bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/file" {
			if r.Header.Get("Authorization") != "" {
				t.Error("vault token sent to download URL")
			}
			_, _ = w.Write(want)
			return
		}
		if r.URL.Path != "/api/ciphers/item-1/attachment/att-1" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization: %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"url": "http://" + r.Host + "/file"})
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	got, err := c.GetAttachment("item-1", "att-1")
	if err != nil {
		t.Fatalf("GetAttachment: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGetAttachment_Unauthenticated(t *testing.T) {
	c := New("http://localhost")
	if _, err := c.GetAttachment("item-1", "att-1"); err == nil {
		t.Error("expected an error without a token, got nil")
	}
}

func TestGetAttachment_StatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"
	if _, err := c.GetAttachment("item-1", "att-1"); err == nil {
		t.Error("expected an error for HTTP 404, got nil")
	}
}

func TestCreateAttachmentV2(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ciphers/item-1/attachment/v2" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"attachment-fileUpload","attachmentId":"att-1","url":"https://blob.example","fileUploadType":1}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"

	upload, err := c.CreateAttachmentV2("item-1", AttachmentUploadRequest{
		FileName: "2.a|b|c",
		FileSize: 123,
		Key:      "2.d|e|f",
	})
	if err != nil {
		t.Fatalf("CreateAttachmentV2: %v", err)
	}
	if upload.AttachmentID != "att-1" || upload.FileUploadType != 1 || upload.URL != "https://blob.example" {
		t.Errorf("upload: %+v", upload)
	}
}

// TestUploadAttachmentFile_Azure verifies the Azure flow: the body is PUT to
// the URL with the x-ms-blob-type header and no Authorization header.
func TestUploadAttachmentFile_Azure(t *testing.T) {
	want := []byte("iv||ct||mac")
	var gotHeaders http.Header
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		gotBody = make([]byte, r.ContentLength)
		_, _ = r.Body.Read(gotBody)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"
	err := c.UploadAttachmentFile(&AttachmentFileUploadResponse{
		URL:            srv.URL + "/blob",
		FileUploadType: 1,
	}, want)
	if err != nil {
		t.Fatalf("UploadAttachmentFile: %v", err)
	}
	if gotHeaders.Get("x-ms-blob-type") != "BlockBlob" {
		t.Errorf("x-ms-blob-type: %q", gotHeaders.Get("x-ms-blob-type"))
	}
	if gotHeaders.Get("Authorization") != "" {
		t.Errorf("the Azure flow must not send an Authorization header")
	}
	if !bytes.Contains(gotBody, want) {
		t.Errorf("body: %q", gotBody)
	}
}

// TestUploadAttachmentFile_Direct verifies the direct flow: the raw body is
// POSTed as multipart data with the Bearer token to the API URL.
func TestUploadAttachmentFile_Direct(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if r.Method != http.MethodPost {
			t.Errorf("method: %s", r.Method)
		}
		if err := r.ParseMultipartForm(1024); err != nil {
			t.Error(err)
			return
		}
		f, _, err := r.FormFile("data")
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = f.Close() }()
		gotBody, _ = io.ReadAll(f)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"
	err := c.UploadAttachmentFile(&AttachmentFileUploadResponse{
		URL:            "/ciphers/item-1/attachment/att-1",
		FileUploadType: 0,
	}, []byte("data"))
	if err != nil {
		t.Fatalf("UploadAttachmentFile: %v", err)
	}
	if string(gotBody) != "data" {
		t.Errorf("multipart data: %q", gotBody)
	}
	if gotPath != "/api/ciphers/item-1/attachment/att-1" {
		t.Errorf("path: %q", gotPath)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization: %q", gotAuth)
	}
}

func TestUploadAttachmentFile_StatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.Token = "test-token"
	if err := c.UploadAttachmentFile(&AttachmentFileUploadResponse{
		URL:            srv.URL,
		FileUploadType: 1,
	}, []byte("data")); err == nil {
		t.Error("expected an error for HTTP 403, got nil")
	}
}
