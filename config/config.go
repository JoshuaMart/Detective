package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Mode string

const (
	ModeNormal    Mode = "normal"
	ModeIntensive Mode = "intensive"
)

type Config struct {
	Wildcard        string
	JobID           string
	Mode            Mode
	APIURL          string
	IngestAPIKey    string
	WordlistURL     string
	JobTimeout      time.Duration
	DNSWorkers      int
	SubfinderConfig string
}

func Load() (*Config, error) {
	cfg := &Config{
		Wildcard:     os.Getenv("WILDCARD"),
		JobID:        os.Getenv("JOB_ID"),
		APIURL:       os.Getenv("API_URL"),
		IngestAPIKey: os.Getenv("INGEST_API_KEY"),
		WordlistURL:     os.Getenv("WORDLIST_URL"),
		SubfinderConfig: os.Getenv("SUBFINDER_CONFIG"),
	}

	mode := os.Getenv("MODE")
	switch Mode(mode) {
	case ModeNormal:
		cfg.Mode = ModeNormal
	case ModeIntensive:
		cfg.Mode = ModeIntensive
	case "":
		cfg.Mode = ModeNormal
	default:
		return nil, fmt.Errorf("invalid MODE %q: must be \"normal\" or \"intensive\"", mode)
	}

	timeout := os.Getenv("JOB_TIMEOUT")
	if timeout == "" {
		if cfg.Mode == ModeIntensive {
			cfg.JobTimeout = 6 * time.Hour
		} else {
			cfg.JobTimeout = 2 * time.Hour
		}
	} else {
		d, err := time.ParseDuration(timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid JOB_TIMEOUT %q: %w", timeout, err)
		}
		cfg.JobTimeout = d
	}

	dnsWorkers := os.Getenv("DNS_WORKERS")
	if dnsWorkers == "" {
		cfg.DNSWorkers = 5
	} else {
		n, err := strconv.Atoi(dnsWorkers)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("invalid DNS_WORKERS %q: must be a positive integer", dnsWorkers)
		}
		cfg.DNSWorkers = n
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	var errs []error

	if c.Wildcard == "" {
		errs = append(errs, fmt.Errorf("WILDCARD is required"))
	}
	if c.JobID == "" {
		errs = append(errs, fmt.Errorf("JOB_ID is required"))
	}
	if c.APIURL == "" {
		errs = append(errs, fmt.Errorf("API_URL is required"))
	}
	if c.IngestAPIKey == "" {
		errs = append(errs, fmt.Errorf("INGEST_API_KEY is required"))
	}
	if c.Mode == ModeIntensive && c.WordlistURL == "" {
		errs = append(errs, fmt.Errorf("WORDLIST_URL is required when MODE=intensive"))
	}

	return errors.Join(errs...)
}

// BaseDomain returns the wildcard without the "*." prefix.
func (c *Config) BaseDomain() string {
	if len(c.Wildcard) > 2 && c.Wildcard[:2] == "*." {
		return c.Wildcard[2:]
	}
	return c.Wildcard
}
