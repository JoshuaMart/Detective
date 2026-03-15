package pipeline

import (
	"context"
	"log/slog"
	"net"

	"github.com/jomar/recon/push"
	"github.com/projectdiscovery/cdncheck"
)

// cdnResult holds the CDN/WAF detection result for a single IP.
type cdnResult struct {
	IsCDN    bool
	Provider string
}

// DetectCDN checks resolved hosts for CDN/WAF IPs.
// Deduplicates by IP so each unique IP is checked only once.
// Returns CDN hosts (ready to push) and non-CDN hosts (proceed to port scan).
func DetectCDN(ctx context.Context, resolved []ResolvedHost) ([]push.Host, []ResolvedHost, error) {
	slog.Debug("initializing cdncheck client")
	client := cdncheck.New()

	// Group hostnames by IP for deduplication
	ipToHosts := make(map[string][]ResolvedHost)
	for _, h := range resolved {
		ipToHosts[h.IP] = append(ipToHosts[h.IP], h)
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

	// Map results back to hostnames
	var cdnHosts []push.Host
	var nonCDNHosts []ResolvedHost

	for _, h := range resolved {
		result := ipResults[h.IP]
		if result.IsCDN {
			cdn := result.Provider
			ip := h.IP
			cdnHosts = append(cdnHosts, push.Host{
				FQDN: h.FQDN,
				IP:   &ip,
				CDN:  &cdn,
				DNS:  &h.DNS,
			})
		} else {
			nonCDNHosts = append(nonCDNHosts, h)
		}
	}

	return cdnHosts, nonCDNHosts, nil
}
