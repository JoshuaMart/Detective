package config

import (
	"testing"
	"time"
)

func TestLoad_AllRequiredVars(t *testing.T) {
	t.Setenv("WILDCARD", "*.example.com")
	t.Setenv("JOB_ID", "550e8400-e29b-41d4-a716-446655440000")
t.Setenv("MODE", "normal")
	t.Setenv("API_URL", "https://api.example.com")
	t.Setenv("INGEST_API_KEY", "secret")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Wildcard != "*.example.com" {
		t.Errorf("wildcard = %q, want %q", cfg.Wildcard, "*.example.com")
	}
	if cfg.Mode != ModeNormal {
		t.Errorf("mode = %q, want %q", cfg.Mode, ModeNormal)
	}
	if cfg.JobTimeout != 4*time.Hour {
		t.Errorf("timeout = %v, want %v", cfg.JobTimeout, 4*time.Hour)
	}
}

func TestLoad_IntensiveRequiresWordlist(t *testing.T) {
	t.Setenv("WILDCARD", "*.example.com")
	t.Setenv("JOB_ID", "550e8400-e29b-41d4-a716-446655440000")
t.Setenv("MODE", "intensive")
	t.Setenv("API_URL", "https://api.example.com")
	t.Setenv("INGEST_API_KEY", "secret")
	// WORDLIST_URL not set

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing WORDLIST_URL in intensive mode")
	}
}

func TestLoad_IntensiveWithWordlist(t *testing.T) {
	t.Setenv("WILDCARD", "*.example.com")
	t.Setenv("JOB_ID", "550e8400-e29b-41d4-a716-446655440000")
t.Setenv("MODE", "intensive")
	t.Setenv("API_URL", "https://api.example.com")
	t.Setenv("INGEST_API_KEY", "secret")
	t.Setenv("WORDLIST_URL", "https://wordlists.example.com/list.txt")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Mode != ModeIntensive {
		t.Errorf("mode = %q, want %q", cfg.Mode, ModeIntensive)
	}
	if cfg.JobTimeout != 8*time.Hour {
		t.Errorf("timeout = %v, want %v", cfg.JobTimeout, 8*time.Hour)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	// All env vars empty
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing required vars")
	}
}

func TestLoad_InvalidMode(t *testing.T) {
	t.Setenv("WILDCARD", "*.example.com")
	t.Setenv("JOB_ID", "id")
	t.Setenv("MODE", "turbo")
	t.Setenv("API_URL", "https://api.example.com")
	t.Setenv("INGEST_API_KEY", "secret")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestBaseDomain(t *testing.T) {
	tests := []struct {
		wildcard string
		want     string
	}{
		{"*.example.com", "example.com"},
		{"*.sub.example.com", "sub.example.com"},
		{"example.com", "example.com"},
	}

	for _, tt := range tests {
		cfg := &Config{Wildcard: tt.wildcard}
		got := cfg.BaseDomain()
		if got != tt.want {
			t.Errorf("BaseDomain(%q) = %q, want %q", tt.wildcard, got, tt.want)
		}
	}
}
