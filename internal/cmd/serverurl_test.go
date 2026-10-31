package cmd

import "testing"

func TestCheckServerURL(t *testing.T) {
	tests := []struct {
		url string
		ok  bool
	}{
		{"https://vault.example.com", true},
		{"https://vault.example.com:8443/", true},
		{"HTTPS://vault.example.com", true},
		{"http://localhost:8000", true},
		{"http://127.0.0.1", true},
		{"http://[::1]:8080", true},
		{"http://vault.example.com", false},
		{"http://192.168.1.10", false},
		{"vault.example.com", false},
		{"ftp://vault.example.com", false},
		{"https://", false},
	}
	for _, tt := range tests {
		err := checkServerURL(tt.url)
		if (err == nil) != tt.ok {
			t.Errorf("checkServerURL(%q) = %v, want ok=%v", tt.url, err, tt.ok)
		}
	}
}
