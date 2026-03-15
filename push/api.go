package push

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// PortInfo represents the web service info for a single port.
type PortInfo struct {
	Web *string `json:"web"`
}

// Ports represents the open ports for a hostname.
type Ports struct {
	TCP map[string]PortInfo `json:"tcp"`
	UDP map[string]PortInfo `json:"udp"`
}

// DNS represents the full DNS record set for a hostname.
type DNS struct {
	A     []string `json:"a"`
	AAAA  []string `json:"aaaa"`
	CNAME []string `json:"cname"`
	NS    []string `json:"ns"`
	MX    []string `json:"mx"`
	TXT   []string `json:"txt"`
	PTR   []string `json:"ptr"`
}

// Host represents a single hostname with all enrichment data.
type Host struct {
	FQDN  string  `json:"fqdn"`
	IP    *string `json:"ip"`
	CDN   *string `json:"cdn"`
	DNS   *DNS    `json:"dns"`
	Ports *Ports  `json:"ports"`
}

// ReconPayload is the payload sent to POST /api/ingest/recon.
type ReconPayload struct {
	JobID string `json:"job_id"`
	Host  Host   `json:"host"`
}

// JobStatusPayload is used to update the recon job status.
type JobStatusPayload struct {
	Status string `json:"status"`
}

// Client pushes recon results to the API.
type Client struct {
	apiURL       string
	ingestAPIKey string
	httpClient   *http.Client
}

// NewClient creates a new API push client.
func NewClient(apiURL, ingestAPIKey string) *Client {
	return &Client{
		apiURL:       apiURL,
		ingestAPIKey: ingestAPIKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// PushHost sends a single hostname result to the API.
func (c *Client) PushHost(ctx context.Context, payload ReconPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL+"/api/ingest/recon", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.ingestAPIKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d from ingest endpoint", resp.StatusCode)
	}

	slog.Debug("pushed host to API", "fqdn", payload.Host.FQDN)
	return nil
}

// UpdateJobStatus updates the recon job status (completed or failed).
func (c *Client) UpdateJobStatus(ctx context.Context, jobID, status string) error {
	body, err := json.Marshal(JobStatusPayload{Status: status})
	if err != nil {
		return fmt.Errorf("marshal status: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.apiURL+"/api/jobs/"+jobID+"/status", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.ingestAPIKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d updating job status", resp.StatusCode)
	}

	slog.Info("updated job status", "job_id", jobID, "status", status)
	return nil
}
