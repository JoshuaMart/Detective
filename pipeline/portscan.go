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

// ScanPorts runs a TCP connect scan on non-CDN hosts, grouped by unique IP.
// Returns hosts enriched with open port data.
func ScanPorts(ctx context.Context, cfg *config.Config, hosts []ResolvedHost) ([]ScannedHost, error) {
	if len(hosts) == 0 {
		return nil, nil
	}

	// Build unique IP list and mapping
	ipToHosts := make(map[string][]ResolvedHost)
	var uniqueIPs []string
	for _, h := range hosts {
		if _, exists := ipToHosts[h.IP]; !exists {
			uniqueIPs = append(uniqueIPs, h.IP)
		}
		ipToHosts[h.IP] = append(ipToHosts[h.IP], h)
	}
	slog.Info("scanning ports", "unique_ips", len(uniqueIPs), "total_hosts", len(hosts))

	// Determine ports to scan
	var ports []int
	if cfg.Mode == config.ModeIntensive {
		for p := 1; p <= 65535; p++ {
			ports = append(ports, p)
		}
	} else {
		ports = parseNmapTop1000()
	}

	slog.Debug("starting port scan", "port_count", len(ports), "workers", 200)

	// Scan each unique IP
	var mu sync.Mutex
	ipPorts := make(map[string][]int)

	for _, ip := range uniqueIPs {
		if ctx.Err() != nil {
			break
		}
		open := scanIP(ctx, ip, ports, 200, 2*time.Second)
		mu.Lock()
		ipPorts[ip] = open
		mu.Unlock()
		slog.Debug("scan complete for IP", "ip", ip, "open_ports", len(open))
	}

	// Map open ports back to hostnames
	var scanned []ScannedHost
	for _, h := range hosts {
		scanned = append(scanned, ScannedHost{
			ResolvedHost: h,
			OpenPorts:    ipPorts[h.IP],
		})
	}

	return scanned, nil
}

// scanIP probes all ports on a single IP using a worker pool.
func scanIP(ctx context.Context, ip string, ports []int, workers int, timeout time.Duration) []int {
	jobs := make(chan int, len(ports))
	results := make(chan int, len(ports))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				if ctx.Err() != nil {
					continue
				}
				addr := net.JoinHostPort(ip, strconv.Itoa(port))
				conn, err := net.DialTimeout("tcp", addr, timeout)
				if err == nil {
					conn.Close()
					results <- port
					slog.Debug("open port found", "ip", ip, "port", port)
				}
			}
		}()
	}

	for _, p := range ports {
		jobs <- p
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var open []int
	for port := range results {
		open = append(open, port)
	}
	sort.Ints(open)
	return open
}

