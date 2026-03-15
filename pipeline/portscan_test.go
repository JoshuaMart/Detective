package pipeline

import (
	"context"
	"testing"

	"github.com/jomar/recon/config"
	"github.com/jomar/recon/push"
)

func TestScanPorts_EmptyInput(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeNormal}
	result, err := ScanPorts(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d", len(result))
	}
}

func TestScanPorts_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := &config.Config{Mode: config.ModeNormal}
	hosts := []ResolvedHost{
		{
			FQDN: "scanme.sh",
			IP:   "188.166.42.37",
			DNS:  push.DNS{A: []string{"188.166.42.37"}},
		},
	}

	scanned, err := ScanPorts(context.Background(), cfg, hosts)
	if err != nil {
		t.Fatalf("ScanPorts failed: %v", err)
	}

	if len(scanned) != 1 {
		t.Fatalf("expected 1 scanned host, got %d", len(scanned))
	}

	t.Logf("scanme.sh open ports: %v", scanned[0].OpenPorts)
}

func TestScanPorts_IPDeduplication(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := &config.Config{Mode: config.ModeNormal}
	// Two hostnames sharing the same IP
	hosts := []ResolvedHost{
		{FQDN: "a.scanme.sh", IP: "188.166.42.37", DNS: push.DNS{A: []string{"188.166.42.37"}}},
		{FQDN: "b.scanme.sh", IP: "188.166.42.37", DNS: push.DNS{A: []string{"188.166.42.37"}}},
	}

	scanned, err := ScanPorts(context.Background(), cfg, hosts)
	if err != nil {
		t.Fatalf("ScanPorts failed: %v", err)
	}

	if len(scanned) != 2 {
		t.Fatalf("expected 2 scanned hosts, got %d", len(scanned))
	}

	// Both should have the same ports
	if len(scanned[0].OpenPorts) != len(scanned[1].OpenPorts) {
		t.Errorf("hosts sharing IP should have same ports: %v vs %v", scanned[0].OpenPorts, scanned[1].OpenPorts)
	}
}
