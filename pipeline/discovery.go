package pipeline

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"strings"

	"github.com/jomar/recon/config"
	"github.com/projectdiscovery/alterx"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// Discover runs subdomain discovery for the configured wildcard.
// Returns a deduplicated list of FQDNs.
func Discover(ctx context.Context, cfg *config.Config) ([]string, error) {
	domain := cfg.BaseDomain()
	seen := make(map[string]struct{})

	// Step 1a — Passive enumeration with subfinder
	slog.Info("running subfinder", "domain", domain)
	passiveHosts, err := runSubfinder(ctx, domain, cfg.SubfinderConfig)
	if err != nil {
		return nil, fmt.Errorf("subfinder: %w", err)
	}
	for _, h := range passiveHosts {
		seen[strings.ToLower(h)] = struct{}{}
	}
	slog.Info("subfinder complete", "count", len(passiveHosts))

	if cfg.Mode == config.ModeIntensive {
		// Step 1b — Wordlist bruteforce
		slog.Info("running wordlist bruteforce", "wordlist_url", cfg.WordlistURL)
		bruteHosts, err := runBruteforce(ctx, cfg, domain)
		if err != nil {
			slog.Error("bruteforce failed, continuing", "error", err)
		} else {
			added := 0
			for _, h := range bruteHosts {
				h = strings.ToLower(h)
				if _, exists := seen[h]; !exists {
					seen[h] = struct{}{}
					added++
				}
			}
			slog.Info("bruteforce complete", "new", added)
		}

		// Step 1c — Permutations with alterx
		slog.Info("running alterx permutations")
		current := make([]string, 0, len(seen))
		for h := range seen {
			current = append(current, h)
		}
		permHosts, err := runPermutations(ctx, current)
		if err != nil {
			slog.Error("permutations failed, continuing", "error", err)
		} else {
			added := 0
			for _, h := range permHosts {
				h = strings.ToLower(h)
				if _, exists := seen[h]; !exists {
					seen[h] = struct{}{}
					added++
				}
			}
			slog.Info("permutations complete", "new", added)
		}
	}

	hostnames := make([]string, 0, len(seen))
	for h := range seen {
		hostnames = append(hostnames, h)
	}
	return hostnames, nil
}

// runSubfinder performs passive subdomain enumeration.
func runSubfinder(ctx context.Context, domain string, providerConfig string) ([]string, error) {
	opts := &runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
		Silent:             true,
	}
	if providerConfig != "" {
		opts.ProviderConfig = providerConfig
	}

	slog.Debug("initializing subfinder runner")
	sfRunner, err := runner.NewRunner(opts)
	if err != nil {
		return nil, fmt.Errorf("create runner: %w", err)
	}

	slog.Debug("starting subfinder enumeration", "domain", domain)
	sourceMap, err := sfRunner.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{})
	if err != nil {
		return nil, fmt.Errorf("enumerate: %w", err)
	}

	hostnames := make([]string, 0, len(sourceMap))
	for hostname := range sourceMap {
		hostnames = append(hostnames, hostname)
	}
	return hostnames, nil
}

// runBruteforce downloads a wordlist and generates candidates by prepending words to the domain.
func runBruteforce(ctx context.Context, cfg *config.Config, domain string) ([]string, error) {
	wordlistPath, err := downloadWordlist(ctx, cfg.WordlistURL)
	if err != nil {
		return nil, fmt.Errorf("download wordlist: %w", err)
	}
	defer func() { _ = os.Remove(wordlistPath) }()

	data, err := os.ReadFile(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("read wordlist: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	hostnames := make([]string, 0, len(lines))
	for _, word := range lines {
		word = strings.TrimSpace(word)
		if word == "" {
			continue
		}
		hostnames = append(hostnames, word+"."+domain)
	}

	return hostnames, nil
}

// runPermutations generates subdomain permutations from known hostnames using alterx.
func runPermutations(ctx context.Context, hostnames []string) ([]string, error) {
	if len(hostnames) == 0 {
		return nil, nil
	}

	opts := &alterx.Options{
		Domains: hostnames,
		MaxSize: math.MaxInt,
		Enrich:  true,
	}

	slog.Debug("initializing alterx mutator", "domains", len(hostnames))
	mutator, err := alterx.New(opts)
	if err != nil {
		return nil, fmt.Errorf("create mutator: %w", err)
	}

	slog.Debug("running alterx permutations")
	var results []string
	for subdomain := range mutator.Execute(ctx) {
		results = append(results, subdomain)
	}
	return results, nil
}

// downloadWordlist fetches a wordlist from a URL and saves it to a temp file.
func downloadWordlist(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer func() { _ = tmpFile.Close() }()

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		_ = os.Remove(tmpFile.Name())
		return "", fmt.Errorf("write temp file: %w", err)
	}

	return tmpFile.Name(), nil
}
