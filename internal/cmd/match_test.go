package cmd

import "testing"

func TestMatchByName(t *testing.T) {
	tests := []struct {
		name      string
		itemName  string
		pattern   string
		wantMatch bool
		wantExact bool
	}{
		{"exact match", "GitHub", "GitHub", true, true},
		{"case-insensitive exact", "GitHub", "github", true, true},
		{"case-insensitive exact reversed", "github", "GitHub", true, true},
		{"substring match", "GitHub Personal", "github", true, false},
		{"substring case-insensitive", "My GitHub Account", "GITHUB", true, false},
		{"no match", "Google", "github", false, false},
		{"empty pattern matches all", "GitHub", "", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch, gotExact := matchByName(tt.itemName, tt.pattern)
			if gotMatch != tt.wantMatch || gotExact != tt.wantExact {
				t.Errorf("matchByName(%q, %q) = (%v, %v), want (%v, %v)",
					tt.itemName, tt.pattern, gotMatch, gotExact, tt.wantMatch, tt.wantExact)
			}
		})
	}
}

func TestMatchByURL(t *testing.T) {
	tests := []struct {
		name      string
		uris      []string
		pattern   string
		wantMatch bool
	}{
		{"simple domain match", []string{"https://github.com"}, "github.com", true},
		{"domain in path", []string{"https://github.com/user/repo"}, "github.com", true},
		{"case-insensitive", []string{"https://GitHub.com"}, "github.com", true},
		{"no match", []string{"https://google.com"}, "github.com", false},
		{"empty URIs", []string{}, "github.com", false},
		{"nil equivalent empty", nil, "github.com", false},
		{"multiple URIs first matches", []string{"https://github.com", "https://google.com"}, "github.com", true},
		{"multiple URIs second matches", []string{"https://google.com", "https://github.com"}, "github.com", true},
		{"pattern without scheme", []string{"https://api.github.com/endpoint"}, "github.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchByURL(tt.uris, tt.pattern)
			if got != tt.wantMatch {
				t.Errorf("matchByURL(%v, %q) = %v, want %v", tt.uris, tt.pattern, got, tt.wantMatch)
			}
		})
	}
}
