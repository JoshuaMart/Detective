package pipeline

import (
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"sync"

	"github.com/jomar/recon/push"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"
)

// DetectWeb probes HTTP/HTTPS on each open port and builds the final Host payload.
// Returns fully enriched hosts ready to push to the API.
func DetectWeb(hosts []ScannedHost) ([]push.Host, error) {
	if len(hosts) == 0 {
		return nil, nil
	}

	// Build probe targets: for each hostname + open port, generate both http:// and https:// URLs
	targets := buildProbeTargets(hosts)
	if len(targets) == 0 {
		return buildHostsWithoutWeb(hosts), nil
	}

	slog.Info("probing web services", "targets", len(targets))

	// Collect httpx results
	var mu sync.Mutex
	// webURLs maps "fqdn:port" → responding URL (keeps the last successful one per scheme)
	webURLs := make(map[string]map[string]string) // fqdn → port → url

	options := runner.Options{
		Methods:          "GET",
		InputTargetHost:  goflags.StringSlice(targets),
		NoFallbackScheme: true,
		Silent:           true,
		DisableStdin:     true,
		DisableStdout:    true,
		OnResult: func(r runner.Result) {
			if r.Err != nil {
				return
			}

			fqdn, port := extractHostPort(r.URL)
			if fqdn == "" {
				return
			}

			mu.Lock()
			defer mu.Unlock()
			if webURLs[fqdn] == nil {
				webURLs[fqdn] = make(map[string]string)
			}
			// If both http and https respond on the same port, prefer https
			existing := webURLs[fqdn][port]
			if existing == "" || r.URL[:5] == "https" {
				webURLs[fqdn][port] = r.URL
			}
			slog.Debug("web service detected", "url", r.URL, "status", r.StatusCode)
		},
	}

	if err := options.ValidateOptions(); err != nil {
		return nil, fmt.Errorf("validate httpx options: %w", err)
	}

	slog.Debug("initializing httpx runner", "targets", len(targets))
	httpxRunner, err := runner.New(&options)
	if err != nil {
		return nil, fmt.Errorf("create httpx runner: %w", err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()

	// Build final host payloads
	return buildHosts(hosts, webURLs), nil
}

// buildProbeTargets generates probe URLs for each hostname + open port.
// Port 80 → http:// only, port 443 → https:// only, other ports → both.
func buildProbeTargets(hosts []ScannedHost) []string {
	var targets []string
	for _, h := range hosts {
		for _, port := range h.OpenPorts {
			switch port {
			case 80:
				targets = append(targets, buildURL("http", h.FQDN, port))
			case 443:
				targets = append(targets, buildURL("https", h.FQDN, port))
			default:
				targets = append(targets, buildURL("http", h.FQDN, port))
				targets = append(targets, buildURL("https", h.FQDN, port))
			}
		}
	}
	return targets
}

// buildURL constructs a URL, omitting the port for standard ports (80/443).
func buildURL(scheme, fqdn string, port int) string {
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return fmt.Sprintf("%s://%s", scheme, fqdn)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, fqdn, port)
}

// extractHostPort parses a URL and returns the FQDN and port as strings.
func extractHostPort(rawURL string) (string, string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", ""
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return host, port
}

// buildHosts constructs the final push.Host payloads with ports JSONB structure.
func buildHosts(hosts []ScannedHost, webURLs map[string]map[string]string) []push.Host {
	result := make([]push.Host, 0, len(hosts))

	for _, h := range hosts {
		tcp := make(map[string]push.PortInfo)
		hasWeb := false

		for _, port := range h.OpenPorts {
			portStr := strconv.Itoa(port)
			if urls, ok := webURLs[h.FQDN]; ok {
				if webURL, found := urls[portStr]; found {
					tcp[portStr] = push.PortInfo{Web: &webURL}
					hasWeb = true
					continue
				}
			}
			tcp[portStr] = push.PortInfo{Web: nil}
		}

		ip := h.IP
		host := push.Host{
			FQDN: h.FQDN,
			IP:   &ip,
			DNS:  &h.DNS,
			Ports: &push.Ports{
				TCP: tcp,
				UDP: make(map[string]push.PortInfo),
			},
		}

		_ = hasWeb // type determination is done by the API based on ports data
		result = append(result, host)
	}

	return result
}

// buildHostsWithoutWeb handles the case where there are no open ports to probe.
func buildHostsWithoutWeb(hosts []ScannedHost) []push.Host {
	result := make([]push.Host, 0, len(hosts))
	for _, h := range hosts {
		ip := h.IP
		host := push.Host{
			FQDN: h.FQDN,
			IP:   &ip,
			DNS:  &h.DNS,
		}
		if len(h.OpenPorts) > 0 {
			tcp := make(map[string]push.PortInfo)
			for _, port := range h.OpenPorts {
				tcp[strconv.Itoa(port)] = push.PortInfo{Web: nil}
			}
			host.Ports = &push.Ports{
				TCP: tcp,
				UDP: make(map[string]push.PortInfo),
			}
		}
		result = append(result, host)
	}
	return result
}
