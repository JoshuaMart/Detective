package pipeline

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/jomar/recon/config"
)

// ScannedHost holds a hostname with its open ports after scanning.
type ScannedHost struct {
	ResolvedHost
	OpenPorts []int
}

// portJob represents a single (ip, port) probe to execute.
type portJob struct {
	ip   string
	port int
}

// ScanPorts runs a TCP connect scan on all hosts, grouped by unique IP.
// CDN IPs are only probed on ports 80 and 443; others get the full port list.
// A single global worker pool processes all (ip, port) pairs concurrently.
// Returns hosts enriched with open port data.
func ScanPorts(ctx context.Context, cfg *config.Config, hosts []ResolvedHost) ([]ScannedHost, error) {
	if len(hosts) == 0 {
		return nil, nil
	}

	// Build unique IP set and mapping
	ipToHosts := make(map[string][]ResolvedHost)
	var uniqueIPs []string
	for _, h := range hosts {
		if _, exists := ipToHosts[h.IP]; !exists {
			uniqueIPs = append(uniqueIPs, h.IP)
		}
		ipToHosts[h.IP] = append(ipToHosts[h.IP], h)
	}

	// Determine ports to scan per IP
	var fullPorts []int
	if cfg.Mode == config.ModeIntensive {
		for p := 1; p <= 65535; p++ {
			fullPorts = append(fullPorts, p)
		}
	} else {
		fullPorts = parseNmapTop1000()
	}
	cdnPorts := []int{80, 443}

	// Build CDN IP set for port selection
	cdnIPs := make(map[string]bool, len(uniqueIPs))
	for _, ip := range uniqueIPs {
		cdnIPs[ip] = ipToHosts[ip][0].CDN != ""
	}

	workers := cfg.PortScanWorkers
	totalJobs := 0
	for _, ip := range uniqueIPs {
		if cdnIPs[ip] {
			totalJobs += len(cdnPorts)
		} else {
			totalJobs += len(fullPorts)
		}
	}
	slog.Info("scanning ports", "unique_ips", len(uniqueIPs), "total_hosts", len(hosts), "workers", workers)

	jobs := make(chan portJob, workers)
	results := make(chan portJob, workers)

	// Start global worker pool
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					continue
				}
				addr := net.JoinHostPort(j.ip, strconv.Itoa(j.port))
				conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
				if err == nil {
					_ = conn.Close()
					results <- j
				}
			}
		}()
	}

	// Feed (ip, port) pairs — CDN IPs only get 80/443
	go func() {
		for _, ip := range uniqueIPs {
			ports := fullPorts
			if cdnIPs[ip] {
				ports = cdnPorts
			}
			for _, port := range ports {
				jobs <- portJob{ip: ip, port: port}
			}
		}
		close(jobs)
	}()

	// Close results when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results grouped by IP
	ipPorts := make(map[string][]int, len(uniqueIPs))
	collected := 0
	for r := range results {
		ipPorts[r.ip] = append(ipPorts[r.ip], r.port)
		collected++
	}
	slog.Info("port scan complete", "total_probes", totalJobs, "open_ports_found", collected)

	// Sort open ports per IP and map back to hostnames
	for ip := range ipPorts {
		sort.Ints(ipPorts[ip])
	}

	var scanned []ScannedHost
	for _, h := range hosts {
		scanned = append(scanned, ScannedHost{
			ResolvedHost: h,
			OpenPorts:    ipPorts[h.IP],
		})
	}

	return scanned, nil
}

