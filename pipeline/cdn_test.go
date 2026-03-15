package pipeline

import (
	"context"
	"testing"

	"github.com/jomar/recon/push"
)

func TestDetectCDN_SplitsCorrectly(t *testing.T) {
	// Use a known Cloudflare IP and a private IP (non-CDN)
	resolved := []ResolvedHost{
		{
			FQDN: "cdn.example.com",
			IP:   "173.245.48.12", // Cloudflare range
			DNS:  push.DNS{A: []string{"173.245.48.12"}},
		},
		{
			FQDN: "internal.example.com",
			IP:   "192.168.1.1", // Private, not CDN
			DNS:  push.DNS{A: []string{"192.168.1.1"}},
		},
	}

	cdnHosts, nonCDNHosts, err := DetectCDN(context.Background(), resolved)
	if err != nil {
		t.Fatalf("DetectCDN failed: %v", err)
	}

	// Cloudflare IP should be detected as CDN
	if len(cdnHosts) != 1 {
		t.Fatalf("expected 1 CDN host, got %d", len(cdnHosts))
	}
	if cdnHosts[0].FQDN != "cdn.example.com" {
		t.Errorf("CDN host FQDN = %q, want %q", cdnHosts[0].FQDN, "cdn.example.com")
	}
	if cdnHosts[0].CDN == nil || *cdnHosts[0].CDN == "" {
		t.Error("CDN provider should be set")
	}

	// Private IP should not be CDN
	if len(nonCDNHosts) != 1 {
		t.Fatalf("expected 1 non-CDN host, got %d", len(nonCDNHosts))
	}
	if nonCDNHosts[0].FQDN != "internal.example.com" {
		t.Errorf("non-CDN host FQDN = %q, want %q", nonCDNHosts[0].FQDN, "internal.example.com")
	}
}

func TestDetectCDN_IPDeduplication(t *testing.T) {
	// Two hostnames sharing the same IP — should only check IP once
	resolved := []ResolvedHost{
		{FQDN: "a.example.com", IP: "192.168.1.1", DNS: push.DNS{A: []string{"192.168.1.1"}}},
		{FQDN: "b.example.com", IP: "192.168.1.1", DNS: push.DNS{A: []string{"192.168.1.1"}}},
	}

	cdnHosts, nonCDNHosts, err := DetectCDN(context.Background(), resolved)
	if err != nil {
		t.Fatalf("DetectCDN failed: %v", err)
	}

	if len(cdnHosts) != 0 {
		t.Errorf("expected 0 CDN hosts, got %d", len(cdnHosts))
	}
	if len(nonCDNHosts) != 2 {
		t.Errorf("expected 2 non-CDN hosts, got %d", len(nonCDNHosts))
	}
}

func TestDetectCDN_EmptyInput(t *testing.T) {
	cdnHosts, nonCDNHosts, err := DetectCDN(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cdnHosts) != 0 || len(nonCDNHosts) != 0 {
		t.Errorf("expected empty results for empty input")
	}
}
