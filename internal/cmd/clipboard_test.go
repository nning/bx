package cmd

import (
	"errors"
	"testing"
)

func TestShouldClearClipboard(t *testing.T) {
	want := clipboardDigest("s3cret")
	tests := []struct {
		name    string
		current string
		readErr error
		clear   bool
	}{
		{"clipboard still holds the secret", "s3cret", nil, true},
		{"user copied something else", "unrelated", nil, false},
		{"clipboard already empty", "", nil, false},
		{"clipboard unreadable", "", errors.New("no xclip"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldClearClipboard(tt.current, tt.readErr, want); got != tt.clear {
				t.Errorf("shouldClearClipboard() = %v, want %v", got, tt.clear)
			}
		})
	}
}

func TestClipboardDigest(t *testing.T) {
	if got := clipboardDigest("abc"); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("clipboardDigest(abc) = %s", got)
	}
}
