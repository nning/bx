package cmd

import (
	"testing"
)

func TestValidateUnlockTimeout(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "zero disables caching", value: "0", wantErr: false},
		{name: "positive integer", value: "15", wantErr: false},
		{name: "large positive integer", value: "1440", wantErr: false},
		{name: "negative integer", value: "-1", wantErr: true},
		{name: "non-numeric string", value: "thirty", wantErr: true},
		{name: "float string", value: "1.5", wantErr: true},
		{name: "empty string", value: "", wantErr: true},
		{name: "whitespace string", value: " ", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUnlockTimeout(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateUnlockTimeout(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestValidateClipboardClearTimeout(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "zero disables clearing", value: "0", wantErr: false},
		{name: "positive integer", value: "30", wantErr: false},
		{name: "large positive integer", value: "300", wantErr: false},
		{name: "negative integer", value: "-1", wantErr: true},
		{name: "non-numeric string", value: "thirty", wantErr: true},
		{name: "float string", value: "1.5", wantErr: true},
		{name: "empty string", value: "", wantErr: true},
		{name: "whitespace string", value: " ", wantErr: true},
		{name: "overflow duration", value: "9223372037", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClipboardClearTimeout(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateClipboardClearTimeout(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}
