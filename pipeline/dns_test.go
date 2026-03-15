package pipeline

import "testing"

func TestMatchesWildcard(t *testing.T) {
	tests := []struct {
		hostname   string
		baseDomain string
		want       bool
	}{
		{"sub.example.com", "example.com", true},
		{"deep.sub.example.com", "example.com", true},
		{"example.com", "example.com", true},
		{"notexample.com", "example.com", false},
		{"sub.other.com", "example.com", false},
		{"fakeexample.com", "example.com", false},
		{"sub.example.com", "sub.example.com", true},
		{"deep.sub.example.com", "sub.example.com", true},
	}

	for _, tt := range tests {
		got := matchesWildcard(tt.hostname, tt.baseDomain)
		if got != tt.want {
			t.Errorf("matchesWildcard(%q, %q) = %v, want %v", tt.hostname, tt.baseDomain, got, tt.want)
		}
	}
}

func TestNilIfEmpty(t *testing.T) {
	if got := nilIfEmpty(nil); got != nil {
		t.Errorf("nilIfEmpty(nil) = %v, want nil", got)
	}

	if got := nilIfEmpty([]string{}); got != nil {
		t.Errorf("nilIfEmpty([]) = %v, want nil", got)
	}

	input := []string{"a", "b"}
	got := nilIfEmpty(input)
	if got == nil {
		t.Fatal("nilIfEmpty([a,b]) = nil, want [a,b]")
	}
	if len(got) != 2 {
		t.Errorf("nilIfEmpty([a,b]) len = %d, want 2", len(got))
	}
}
