package pipeline

import (
	"testing"

	"github.com/jomar/recon/push"
)

func TestBuildURL(t *testing.T) {
	tests := []struct {
		scheme string
		fqdn   string
		port   int
		want   string
	}{
		{"http", "example.com", 80, "http://example.com"},
		{"https", "example.com", 443, "https://example.com"},
		{"http", "example.com", 8080, "http://example.com:8080"},
		{"https", "example.com", 8443, "https://example.com:8443"},
		{"http", "example.com", 443, "http://example.com:443"},
		{"https", "example.com", 80, "https://example.com:80"},
	}

	for _, tt := range tests {
		got := buildURL(tt.scheme, tt.fqdn, tt.port)
		if got != tt.want {
			t.Errorf("buildURL(%q, %q, %d) = %q, want %q", tt.scheme, tt.fqdn, tt.port, got, tt.want)
		}
	}
}

func TestExtractHostPort(t *testing.T) {
	tests := []struct {
		rawURL   string
		wantHost string
		wantPort string
	}{
		{"http://example.com", "example.com", "80"},
		{"https://example.com", "example.com", "443"},
		{"http://example.com:8080", "example.com", "8080"},
		{"https://example.com:9090", "example.com", "9090"},
		{"https://sub.example.com:8443/path", "sub.example.com", "8443"},
	}

	for _, tt := range tests {
		host, port := extractHostPort(tt.rawURL)
		if host != tt.wantHost || port != tt.wantPort {
			t.Errorf("extractHostPort(%q) = (%q, %q), want (%q, %q)", tt.rawURL, host, port, tt.wantHost, tt.wantPort)
		}
	}
}

func TestBuildProbeTargets(t *testing.T) {
	hosts := []ScannedHost{
		{
			ResolvedHost: ResolvedHost{FQDN: "example.com"},
			OpenPorts:    []int{80, 443, 8080},
		},
	}

	targets := buildProbeTargets(hosts)

	// port 80 → http only, port 443 → https only, port 8080 → both = 4 targets
	if len(targets) != 4 {
		t.Fatalf("expected 4 targets, got %d: %v", len(targets), targets)
	}

	expected := map[string]bool{
		"http://example.com":       false,
		"https://example.com":      false,
		"http://example.com:8080":  false,
		"https://example.com:8080": false,
	}

	for _, target := range targets {
		if _, ok := expected[target]; ok {
			expected[target] = true
		} else {
			t.Errorf("unexpected target: %s", target)
		}
	}

	for target, found := range expected {
		if !found {
			t.Errorf("missing expected target: %s", target)
		}
	}
}

func TestBuildProbeTargets_Empty(t *testing.T) {
	targets := buildProbeTargets(nil)
	if len(targets) != 0 {
		t.Errorf("expected 0 targets, got %d", len(targets))
	}
}

func TestBuildProbeTargets_NoPorts(t *testing.T) {
	hosts := []ScannedHost{
		{
			ResolvedHost: ResolvedHost{FQDN: "example.com"},
			OpenPorts:    nil,
		},
	}
	targets := buildProbeTargets(hosts)
	if len(targets) != 0 {
		t.Errorf("expected 0 targets for host with no open ports, got %d", len(targets))
	}
}

func TestBuildHosts_WithWebURLs(t *testing.T) {
	hosts := []ScannedHost{
		{
			ResolvedHost: ResolvedHost{
				FQDN: "example.com",
				IP:   "1.2.3.4",
				DNS:  push.DNS{A: []string{"1.2.3.4"}},
			},
			OpenPorts: []int{22, 80, 443},
		},
	}

	webURLs := map[string]map[string]string{
		"example.com": {
			"80":  "http://example.com",
			"443": "https://example.com",
		},
	}

	result := buildHosts(hosts, webURLs)
	if len(result) != 1 {
		t.Fatalf("expected 1 host, got %d", len(result))
	}

	h := result[0]
	if h.Ports == nil {
		t.Fatal("expected ports to be set")
	}

	// Port 22 should have web: null
	p22, ok := h.Ports.TCP["22"]
	if !ok {
		t.Fatal("port 22 not found")
	}
	if p22.Web != nil {
		t.Errorf("port 22 web should be nil, got %v", *p22.Web)
	}

	// Port 80 should have web URL
	p80, ok := h.Ports.TCP["80"]
	if !ok {
		t.Fatal("port 80 not found")
	}
	if p80.Web == nil || *p80.Web != "http://example.com" {
		t.Errorf("port 80 web = %v, want %q", p80.Web, "http://example.com")
	}

	// Port 443 should have web URL
	p443, ok := h.Ports.TCP["443"]
	if !ok {
		t.Fatal("port 443 not found")
	}
	if p443.Web == nil || *p443.Web != "https://example.com" {
		t.Errorf("port 443 web = %v, want %q", p443.Web, "https://example.com")
	}
}

func TestBuildHostsWithoutWeb(t *testing.T) {
	hosts := []ScannedHost{
		{
			ResolvedHost: ResolvedHost{
				FQDN: "example.com",
				IP:   "1.2.3.4",
				DNS:  push.DNS{A: []string{"1.2.3.4"}},
			},
			OpenPorts: []int{22, 25},
		},
	}

	result := buildHostsWithoutWeb(hosts)
	if len(result) != 1 {
		t.Fatalf("expected 1 host, got %d", len(result))
	}

	h := result[0]
	if h.Ports == nil {
		t.Fatal("expected ports to be set")
	}
	if len(h.Ports.TCP) != 2 {
		t.Errorf("expected 2 TCP ports, got %d", len(h.Ports.TCP))
	}

	for _, portStr := range []string{"22", "25"} {
		p, ok := h.Ports.TCP[portStr]
		if !ok {
			t.Errorf("port %s not found", portStr)
			continue
		}
		if p.Web != nil {
			t.Errorf("port %s web should be nil", portStr)
		}
	}
}

func TestDetectWeb_EmptyInput(t *testing.T) {
	result, err := DetectWeb(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d", len(result))
	}
}
