package pipeline

import (
	"context"
	"testing"

	"github.com/jomar/recon/push"
)

func TestDetectCDN_EnrichesCorrectly(t *testing.T) {
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

	hosts, err := DetectCDN(context.Background(), resolved)
	if err != nil {
		t.Fatalf("DetectCDN failed: %v", err)
	}

	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}

	// Cloudflare IP should be detected as CDN
	if hosts[0].FQDN != "cdn.example.com" {
		t.Errorf("host[0] FQDN = %q, want %q", hosts[0].FQDN, "cdn.example.com")
	}
	if hosts[0].CDN == "" {
		t.Error("CDN provider should be set for Cloudflare IP")
	}

	// Private IP should not be CDN
	if hosts[1].FQDN != "internal.example.com" {
		t.Errorf("host[1] FQDN = %q, want %q", hosts[1].FQDN, "internal.example.com")
	}
	if hosts[1].CDN != "" {
		t.Errorf("CDN should be empty for private IP, got %q", hosts[1].CDN)
	}
}

func TestDetectCDN_IPDeduplication(t *testing.T) {
	// Two hostnames sharing the same IP — should only check IP once
	resolved := []ResolvedHost{
		{FQDN: "a.example.com", IP: "192.168.1.1", DNS: push.DNS{A: []string{"192.168.1.1"}}},
		{FQDN: "b.example.com", IP: "192.168.1.1", DNS: push.DNS{A: []string{"192.168.1.1"}}},
	}

	hosts, err := DetectCDN(context.Background(), resolved)
	if err != nil {
		t.Fatalf("DetectCDN failed: %v", err)
	}

	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(hosts))
	}
	for _, h := range hosts {
		if h.CDN != "" {
			t.Errorf("expected no CDN for private IP, got %q for %s", h.CDN, h.FQDN)
		}
	}
}

func TestDetectCDN_EmptyInput(t *testing.T) {
	hosts, err := DetectCDN(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("expected empty results for empty input")
	}
}
