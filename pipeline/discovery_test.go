package pipeline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jomar/recon/config"
)

func TestDiscover_Normal_ReturnsDeduplicatedHostnames(t *testing.T) {
	// This is an integration-level test — it calls real subfinder sources.
	// Skip in CI or when running short tests.
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := &config.Config{
		Wildcard: "*.hackerone.com",
		Mode:     config.ModeNormal,
	}

	ctx := context.Background()
	hostnames, err := Discover(ctx, cfg)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	if len(hostnames) == 0 {
		t.Fatal("expected at least one hostname, got 0")
	}

	// Check deduplication
	seen := make(map[string]struct{})
	for _, h := range hostnames {
		if _, exists := seen[h]; exists {
			t.Errorf("duplicate hostname: %s", h)
		}
		seen[h] = struct{}{}
	}

	t.Logf("discovered %d hostnames", len(hostnames))
}

func TestRunBruteforce_DownloadsAndGenerates(t *testing.T) {
	// Serve a fake wordlist
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("www\napi\ndev\nstaging\n"))
	}))
	defer srv.Close()

	cfg := &config.Config{
		Wildcard:    "*.example.com",
		Mode:        config.ModeIntensive,
		WordlistURL: srv.URL + "/wordlist.txt",
	}

	hostnames, err := runBruteforce(context.Background(), cfg, "example.com")
	if err != nil {
		t.Fatalf("runBruteforce failed: %v", err)
	}

	expected := map[string]bool{
		"www.example.com":     false,
		"api.example.com":     false,
		"dev.example.com":     false,
		"staging.example.com": false,
	}

	for _, h := range hostnames {
		if _, ok := expected[h]; ok {
			expected[h] = true
		}
	}

	for host, found := range expected {
		if !found {
			t.Errorf("expected hostname %q not found", host)
		}
	}
}

func TestRunBruteforce_BadURL(t *testing.T) {
	cfg := &config.Config{
		Wildcard:    "*.example.com",
		Mode:        config.ModeIntensive,
		WordlistURL: "http://127.0.0.1:1/nonexistent",
	}

	_, err := runBruteforce(context.Background(), cfg, "example.com")
	if err == nil {
		t.Fatal("expected error for unreachable wordlist URL")
	}
}

func TestRunPermutations_GeneratesVariants(t *testing.T) {
	input := []string{
		"api.example.com",
		"dev.example.com",
	}

	results, err := runPermutations(context.Background(), input)
	if err != nil {
		t.Fatalf("runPermutations failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("expected permutations, got 0")
	}

	t.Logf("generated %d permutations", len(results))
}

func TestRunPermutations_EmptyInput(t *testing.T) {
	results, err := runPermutations(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestDownloadWordlist_Success(t *testing.T) {
	content := "word1\nword2\nword3\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(content))
	}))
	defer srv.Close()

	path, err := downloadWordlist(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("downloadWordlist failed: %v", err)
	}

	// File should exist and have content
	if path == "" {
		t.Fatal("expected non-empty path")
	}
}

func TestDownloadWordlist_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := downloadWordlist(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}
