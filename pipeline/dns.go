package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jomar/recon/config"
	"github.com/jomar/recon/push"
	miekgdns "github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

// ResolvedHost holds a hostname with its DNS data and resolved IP.
type ResolvedHost struct {
	FQDN string
	IP   string
	DNS  push.DNS
	CDN  string // empty when not behind a CDN/WAF
}

// ResolveDNS resolves all hostnames and extracts SANs from TLS certificates.
// New SANs matching the wildcard are resolved in a second pass.
// Returns resolved hosts and a list of unresolved FQDNs.
func ResolveDNS(ctx context.Context, cfg *config.Config, hostnames []string) ([]ResolvedHost, []string, error) {
	slog.Debug("initializing dnsx client")
	dnsClient, err := dnsx.New(dnsx.Options{
		BaseResolvers: []string{
			"udp:1.1.1.1:53",         // Cloudflare
			"udp:1.0.0.1:53",         // Cloudflare secondary
			"udp:8.8.8.8:53",         // Google
			"udp:8.8.4.4:53",         // Google secondary
			"udp:9.9.9.9:53",         // Quad9
			"udp:149.112.112.112:53", // Quad9 secondary
			"udp:208.67.222.222:53",  // OpenDNS
			"udp:208.67.220.220:53",  // OpenDNS secondary
			"udp:77.88.8.8:53",       // Yandex
			"udp:185.228.168.9:53",   // CleanBrowsing
			"udp:76.76.2.0:53",       // Control D
		},
		MaxRetries: 3,
		QuestionTypes: []uint16{
			miekgdns.TypeA,
			miekgdns.TypeAAAA,
			miekgdns.TypeCNAME,
			miekgdns.TypeNS,
			miekgdns.TypeMX,
			miekgdns.TypeTXT,
			miekgdns.TypePTR,
		},
	})
	if err != nil {
		return nil, nil, err
	}

	workers := cfg.DNSWorkers

	resolved, unresolved := resolveHosts(ctx, dnsClient, hostnames, workers)
	slog.Info("DNS resolution complete", "resolved", len(resolved), "unresolved", len(unresolved))

	return resolved, unresolved, nil
}

// dnsResult holds the result of resolving a single FQDN.
type dnsResult struct {
	host       *ResolvedHost
	unresolved string
}

// resolveHosts resolves a list of FQDNs using dnsx with a concurrent worker pool.
func resolveHosts(ctx context.Context, client *dnsx.DNSX, hostnames []string, workers int) ([]ResolvedHost, []string) {
	if len(hostnames) == 0 {
		return nil, nil
	}

	slog.Debug("starting DNS resolution pool", "hostnames", len(hostnames), "workers", workers)

	jobs := make(chan string, len(hostnames))
	results := make(chan dnsResult, len(hostnames))

	total := len(hostnames)
	var done atomic.Int64
	var resolvedCount atomic.Int64

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for fqdn := range jobs {
				if ctx.Err() != nil {
					results <- dnsResult{unresolved: fqdn}
					done.Add(1)
					continue
				}
				r := resolveOne(client, fqdn)
				if r.host != nil {
					resolvedCount.Add(1)
				}
				results <- r
				if d := done.Add(1); d%1000 == 0 {
					slog.Info("DNS resolution progress",
						"done", d,
						"total", total,
						"resolved", resolvedCount.Load(),
						"progress", fmt.Sprintf("%.1f%%", float64(d)/float64(total)*100),
					)
				}
			}
		}()
	}

	// Feed jobs
	for _, fqdn := range hostnames {
		jobs <- fqdn
	}
	close(jobs)

	// Close results channel when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var resolved []ResolvedHost
	var unresolved []string
	for r := range results {
		if r.host != nil {
			resolved = append(resolved, *r.host)
		} else {
			unresolved = append(unresolved, r.unresolved)
		}
	}

	return resolved, unresolved
}

// resolveOne resolves a single FQDN and returns the result.
func resolveOne(client *dnsx.DNSX, fqdn string) dnsResult {
	data, err := client.QueryMultiple(fqdn)
	if err != nil || data == nil {
		slog.Debug("unresolved hostname", "fqdn", fqdn, "error", err)
		return dnsResult{unresolved: fqdn}
	}

	// Determine the resolved IP: prefer A records, fall back to Lookup
	ip := ""
	if len(data.A) > 0 {
		ip = data.A[0]
	} else {
		ips, lookupErr := client.Lookup(fqdn)
		if lookupErr != nil || len(ips) == 0 {
			slog.Debug("unresolved hostname (no A record)", "fqdn", fqdn, "cname", data.CNAME)
			return dnsResult{unresolved: fqdn}
		}
		ip = ips[0]
		data.A = ips
	}

	host := ResolvedHost{
		FQDN: fqdn,
		IP:   ip,
		DNS: push.DNS{
			A:     data.A,
			AAAA:  nilIfEmpty(data.AAAA),
			CNAME: nilIfEmpty(data.CNAME),
			NS:    nilIfEmpty(data.NS),
			MX:    nilIfEmpty(data.MX),
			TXT:   nilIfEmpty(data.TXT),
			PTR:   nilIfEmpty(data.PTR),
		},
	}
	slog.Debug("resolved hostname", "fqdn", fqdn, "ip", host.IP)
	return dnsResult{host: &host}
}

// ExtractSANs connects to scanned hosts that have port 443 open and extracts SANs
// that match the wildcard pattern. Returns new FQDNs not already known.
func ExtractSANs(ctx context.Context, cfg *config.Config, hosts []ScannedHost) []string {
	// Filter to hosts with port 443 open
	var targets []ResolvedHost
	for _, h := range hosts {
		for _, p := range h.OpenPorts {
			if p == 443 {
				targets = append(targets, h.ResolvedHost)
				break
			}
		}
	}
	if len(targets) == 0 {
		return nil
	}

	slog.Debug("initializing tlsx service", "scan_mode", "auto")
	tlsService, err := tlsx.New(&clients.Options{
		ScanMode: "auto",
		Timeout:  10,
		Retries:  2,
	})
	if err != nil {
		slog.Error("failed to create tlsx service", "error", err)
		return nil
	}

	workers := cfg.TLSWorkers
	wildcardPattern := cfg.BaseDomain()

	// Build known set from ALL hosts (not just targets) to avoid rediscovering existing FQDNs
	known := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		known[h.FQDN] = struct{}{}
	}

	slog.Info("extracting SANs from TLS certificates", "targets", len(targets), "workers", workers)

	jobs := make(chan ResolvedHost, len(targets))
	results := make(chan []string, len(targets))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				if ctx.Err() != nil {
					continue
				}
				resp, err := tlsService.Connect(host.FQDN, host.IP, "443")
				if err != nil {
					slog.Debug("tlsx connect failed", "fqdn", host.FQDN, "error", err)
					continue
				}
				if resp.CertificateResponse == nil {
					continue
				}
				var sans []string
				for _, san := range resp.SubjectAN {
					san = strings.ToLower(san)
					san = strings.TrimPrefix(san, "*.")
					if matchesWildcard(san, wildcardPattern) {
						sans = append(sans, san)
					}
				}
				if len(sans) > 0 {
					results <- sans
				}
			}
		}()
	}

	// Feed jobs
	for _, host := range targets {
		jobs <- host
	}
	close(jobs)

	// Close results when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and deduplicate
	var newHosts []string
	for sans := range results {
		for _, san := range sans {
			if _, exists := known[san]; exists {
				continue
			}
			known[san] = struct{}{}
			newHosts = append(newHosts, san)
			slog.Debug("new SAN discovered", "san", san)
		}
	}

	return newHosts
}

// matchesWildcard checks if a hostname belongs to the wildcard's base domain.
// e.g. "sub.example.com" matches "example.com", "deep.sub.example.com" also matches.
func matchesWildcard(hostname, baseDomain string) bool {
	if hostname == baseDomain {
		return true
	}
	return strings.HasSuffix(hostname, "."+baseDomain)
}

// nilIfEmpty returns nil if the slice is empty, otherwise returns the slice as-is.
func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
