package pipeline

import (
	"context"
	"log/slog"
	"net"

	"github.com/projectdiscovery/cdncheck"
)

// cdnResult holds the CDN/WAF detection result for a single IP.
type cdnResult struct {
	IsCDN    bool
	Provider string
}

// DetectCDN checks resolved hosts for CDN/WAF IPs and enriches them with the CDN label.
// All hosts are returned — CDN hosts proceed to port scanning like non-CDN hosts.
func DetectCDN(ctx context.Context, resolved []ResolvedHost) ([]ResolvedHost, error) {
	slog.Debug("initializing cdncheck client")
	client := cdncheck.New()

	// Group hostnames by IP for deduplication
	ipToHosts := make(map[string][]int) // ip → indices into resolved
	for i, h := range resolved {
		ipToHosts[h.IP] = append(ipToHosts[h.IP], i)
	}
	slog.Info("IP deduplication", "unique_ips", len(ipToHosts), "total_hosts", len(resolved))

	// Check each unique IP once
	ipResults := make(map[string]cdnResult, len(ipToHosts))
	for ip := range ipToHosts {
		if ctx.Err() != nil {
			slog.Warn("context cancelled during CDN detection")
			break
		}

		parsed := net.ParseIP(ip)
		if parsed == nil {
			slog.Warn("invalid IP, skipping CDN check", "ip", ip)
			ipResults[ip] = cdnResult{}
			continue
		}

		// Check CDN first, then WAF
		if matched, provider, err := client.CheckCDN(parsed); err == nil && matched {
			slog.Debug("CDN detected", "ip", ip, "provider", provider)
			ipResults[ip] = cdnResult{IsCDN: true, Provider: provider}
			continue
		}

		if matched, provider, err := client.CheckWAF(parsed); err == nil && matched {
			slog.Debug("WAF detected", "ip", ip, "provider", provider)
			ipResults[ip] = cdnResult{IsCDN: true, Provider: provider}
			continue
		}

		ipResults[ip] = cdnResult{}
	}

	// Enrich hosts with CDN label
	enriched := make([]ResolvedHost, len(resolved))
	copy(enriched, resolved)

	cdnCount := 0
	for ip, result := range ipResults {
		if result.IsCDN {
			for _, idx := range ipToHosts[ip] {
				enriched[idx].CDN = result.Provider
			}
			cdnCount += len(ipToHosts[ip])
		}
	}

	slog.Info("CDN detection complete", "cdn", cdnCount, "non_cdn", len(resolved)-cdnCount)
	return enriched, nil
}
