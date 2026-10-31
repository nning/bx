package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAttachmentForceReplacesWithPrivateFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission and hard-link semantics")
	}
	dir := t.TempDir()
	path, alias := filepath.Join(dir, "output"), filepath.Join(dir, "alias")
	if err := os.WriteFile(path, []byte("public"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if err := writeAttachmentFile([]byte("synthetic secret"), path, true); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("output permissions: %v, %v", fi, err)
	}
	data, err := os.ReadFile(alias)
	if err != nil || string(data) != "public" {
		t.Fatalf("hard-linked file was overwritten: %q, %v", data, err)
	}
	if err := writeAttachmentFile([]byte("replacement"), path, false); err == nil {
		t.Fatal("existing destination overwritten without --force")
	}
}
