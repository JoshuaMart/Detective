package pipeline

import (
	"context"
	"log/slog"

	"github.com/jomar/recon/config"
	"github.com/jomar/recon/push"
)

// pushCtx is a background context used for all push operations.
// Pushes are decoupled from the pipeline timeout — each HTTP request
// is already bounded by the client's own 30s timeout.
var pushCtx = context.Background()

// Run executes the full recon pipeline for the configured wildcard.
// On context timeout, it pushes whatever was collected so far and returns nil
// so that the job is marked as completed (partial results are better than nothing).
func Run(ctx context.Context, cfg *config.Config, client *push.Client) error {
	baseDomain := cfg.BaseDomain()
	slog.Info("starting recon pipeline", "wildcard", cfg.Wildcard, "domain", baseDomain, "mode", cfg.Mode)

	// Step 1 — Subdomain discovery
	slog.Info("step 1: subdomain discovery")
	hostnames, err := Discover(ctx, cfg)
	if err != nil {
		if ctx.Err() != nil {
			slog.Warn("timeout during subdomain discovery, no results to push")
			return nil
		}
		return err
	}
	slog.Info("discovery complete", "count", len(hostnames))

	// Step 2 — DNS resolution + SAN extraction
	slog.Info("step 2: DNS resolution")
	resolved, unresolved, err := ResolveDNS(ctx, cfg, hostnames)
	if err != nil {
		if ctx.Err() != nil {
			slog.Warn("timeout during DNS resolution, pushing unresolved hostnames")
			pushUnresolved(client, cfg, hostnames)
			return nil
		}
		return err
	}
	slog.Info("DNS resolution complete", "resolved", len(resolved), "unresolved", len(unresolved))

	// Push unresolved hostnames immediately
	pushUnresolved(client, cfg, unresolved)

	// Step 3 — IP deduplication & CDN detection
	slog.Info("step 3: CDN detection")
	cdnHosts, nonCDNHosts, err := DetectCDN(ctx, resolved)
	if err != nil {
		if ctx.Err() != nil {
			slog.Warn("timeout during CDN detection, pushing resolved hosts as-is")
			pushResolvedAsIs(client, cfg, resolved)
			return nil
		}
		return err
	}
	slog.Info("CDN detection complete", "cdn", len(cdnHosts), "non_cdn", len(nonCDNHosts))

	// Push CDN hostnames immediately
	for _, h := range cdnHosts {
		payload := push.ReconPayload{
			JobID: cfg.JobID,
			Host:  h,
		}
		if err := client.PushHost(pushCtx, payload); err != nil {
			slog.Error("failed to push CDN host", "fqdn", h.FQDN, "error", err)
		}
	}

	// Step 4 — Port scan
	slog.Info("step 4: port scan")
	scanned, err := ScanPorts(ctx, cfg, nonCDNHosts)
	if err != nil {
		if ctx.Err() != nil {
			slog.Warn("timeout during port scan, pushing non-CDN hosts without ports")
			pushResolvedAsIs(client, cfg, nonCDNHosts)
			return nil
		}
		return err
	}
	slog.Info("port scan complete", "hosts", len(scanned))

	// Step 5 — Web detection
	slog.Info("step 5: web detection")
	enriched, err := DetectWeb(scanned)
	if err != nil {
		if ctx.Err() != nil {
			slog.Warn("timeout during web detection, pushing hosts with ports only")
			pushScannedAsIs(client, cfg, scanned)
			return nil
		}
		return err
	}
	slog.Info("web detection complete", "hosts", len(enriched))

	// Step 6 — Push remaining results
	slog.Info("step 6: pushing results")
	for _, h := range enriched {
		payload := push.ReconPayload{
			JobID: cfg.JobID,
			Host:  h,
		}
		if err := client.PushHost(pushCtx, payload); err != nil {
			slog.Error("failed to push host", "fqdn", h.FQDN, "error", err)
		}
	}

	slog.Info("recon pipeline complete")
	return nil
}

// pushUnresolved pushes a list of FQDNs as unresolved hostnames.
func pushUnresolved(client *push.Client, cfg *config.Config, fqdns []string) {
	for _, fqdn := range fqdns {
		payload := push.ReconPayload{
			JobID: cfg.JobID,
			Host:  push.Host{FQDN: fqdn},
		}
		if err := client.PushHost(pushCtx, payload); err != nil {
			slog.Error("failed to push unresolved host", "fqdn", fqdn, "error", err)
		}
	}
}

// pushResolvedAsIs pushes resolved hosts with DNS data but without port/web enrichment.
func pushResolvedAsIs(client *push.Client, cfg *config.Config, hosts []ResolvedHost) {
	for _, h := range hosts {
		ip := h.IP
		payload := push.ReconPayload{
			JobID: cfg.JobID,
			Host: push.Host{
				FQDN: h.FQDN,
				IP:   &ip,
				DNS:  &h.DNS,
			},
		}
		if err := client.PushHost(pushCtx, payload); err != nil {
			slog.Error("failed to push resolved host", "fqdn", h.FQDN, "error", err)
		}
	}
}

// pushScannedAsIs pushes scanned hosts with port data but without web detection.
func pushScannedAsIs(client *push.Client, cfg *config.Config, hosts []ScannedHost) {
	for _, h := range hosts {
		host := buildHostsWithoutWeb([]ScannedHost{h})
		if len(host) == 0 {
			continue
		}
		payload := push.ReconPayload{
			JobID: cfg.JobID,
			Host:  host[0],
		}
		if err := client.PushHost(pushCtx, payload); err != nil {
			slog.Error("failed to push scanned host", "fqdn", h.FQDN, "error", err)
		}
	}
}
