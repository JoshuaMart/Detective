![Image](https://github.com/user-attachments/assets/17e7c4cc-2c02-42ef-b871-5d9ec06eef7a)

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-green"></a>
  <img src="https://img.shields.io/badge/docker-supported-blue?logo=docker">
  <img src="https://img.shields.io/badge/golang-1.26-blue?logo=go">
</p>

Automated reconnaissance pipeline that discovers subdomains, resolves DNS, detects CDNs, scans ports, and identifies web services — then pushes everything to your API in real time.

Runs as a [Scaleway Serverless Job](https://www.scaleway.com/en/serverless-jobs/) or locally. One container, one wildcard, full discovery.

## Pipeline

```
1. Subdomain discovery (subfinder + alterx in intensive mode)
        │
        ▼
2. DNS resolution (dnsx) + SAN extraction (tlsx) → new hostnames → back to step 2
        │
        ▼
3. IP deduplication + CDN/WAF detection (cdncheck) → CDN hosts pushed immediately
        │
        ▼
4. Port scan (TCP connect) — per unique non-CDN IP
        │
        ▼
5. Web detection (httpx) — HTTP + HTTPS on every open port
        │
        ▼
6. Push to API (/api/ingest/recon) — per hostname as completed
```

## Quick start

```bash
docker run --rm \
  -e WILDCARD="*.example.com" \
  -e JOB_ID="550e8400-e29b-41d4-a716-446655440000" \
  -e API_URL="http://host.docker.internal:8080" \
  -e INGEST_API_KEY="secret" \
  ghcr.io/joshuamart/detective:latest
```

Or build from source:

```bash
docker build -t detective .
```

## Modes

**Normal** (default) — passive subdomain enumeration via subfinder, top 1000 TCP ports.

**Intensive** — subfinder + wordlist bruteforce + alterx permutations, full port range (1-65535).

Set `MODE=intensive` and provide `WORDLIST_URL` to enable.

<details>
<summary>Environment variables</summary>

| Variable | Required | Description |
|---|---|---|
| `WILDCARD` | yes | Target wildcard, e.g. `*.example.com` |
| `JOB_ID` | yes | UUID of the `recon_jobs` record |
| `MODE` | no | `normal` (default) or `intensive` |
| `API_URL` | yes | Base URL of the platform API |
| `INGEST_API_KEY` | yes | Secret for the ingest endpoint |
| `WORDLIST_URL` | intensive | URL to fetch bruteforce wordlist |
| `SUBFINDER_CONFIG` | no | Path to subfinder provider-config.yaml (API keys) |
| `JOB_TIMEOUT` | no | Job timeout duration (default: `4h`, intensive: `8h`) |
| `DNS_WORKERS` | no | Concurrent DNS resolution workers (default: `20`) |
| `LOG_LEVEL` | no | `debug` for verbose output (default: `info`) |

</details>

## Subfinder API keys

Provide API keys for subfinder sources (SecurityTrails, Shodan, Censys, etc.) to improve subdomain discovery.

Create a `provider-config.yaml`:

```yaml
securitytrails:
  - your-api-key
shodan:
  - your-api-key
censys:
  - your-id:your-secret
```

See the [subfinder documentation](https://docs.projectdiscovery.io/opensource/subfinder/install#post-install-configuration) for the full list of supported providers.

**Local** — mount the file:

```bash
docker run --rm --env-file .env \
  -v /path/to/provider-config.yaml:/config/provider-config.yaml \
  -e SUBFINDER_CONFIG=/config/provider-config.yaml \
  detective
```

**Scaleway** — store the file in [Secret Manager](https://www.scaleway.com/en/docs/serverless-jobs/how-to/reference-secret-in-job/) and inject it at `/config/provider-config.yaml`, then set `SUBFINDER_CONFIG=/config/provider-config.yaml`.

## Deploy to Scaleway

```bash
# Create the Job Definition (once)
scw jobs definition create \
  name=detective \
  cpu-limit=2000 \
  memory-limit=2048 \
  image-uri=ghcr.io/joshuamart/detective:latest \
  environment-variables.API_URL="https://api.example.com" \
  environment-variables.INGEST_API_KEY="secret" \
  environment-variables.SUBFINDER_CONFIG="/config/provider-config.yaml"

# Start a run (per scan)
scw jobs definition start <definition-id> \
  environment-variables.WILDCARD="*.example.com" \
  environment-variables.JOB_ID="uuid-here" \
  environment-variables.MODE="normal"
```

Shared variables (`API_URL`, `INGEST_API_KEY`) go in the definition. Per-scan variables (`WILDCARD`, `JOB_ID`, `MODE`) are passed at run time.

## API output

Each hostname is pushed individually to `POST /api/ingest/recon`.

<details>
<summary>Unresolved hostname</summary>

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "host": {
    "fqdn": "old.example.com",
    "ip": null,
    "cdn": null,
    "dns": null,
    "ports": null
  }
}
```

</details>

<details>
<summary>Resolved hostname with open ports</summary>

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "host": {
    "fqdn": "app.example.com",
    "ip": "93.184.216.34",
    "cdn": null,
    "dns": {
      "a": ["93.184.216.34"],
      "aaaa": null,
      "cname": ["lb.example.com", "example.com"],
      "ns": ["ns1.example.net", "ns2.example.net"],
      "mx": ["mx1.mail.example.com", "mx2.mail.example.com"],
      "txt": ["v=spf1 include:mx.example.com -all"],
      "ptr": null
    },
    "ports": {
      "tcp": {
        "22": { "web": null },
        "80": { "web": "http://app.example.com" },
        "443": { "web": "https://app.example.com" }
      },
      "udp": {}
    }
  }
}
```

</details>

## Timeout behavior

On timeout, the pipeline pushes whatever was collected so far (partial results) using a fresh 2-minute context, then exits cleanly. The job is marked as `completed` — partial data is better than no data.

## Testing

```bash
go test -short ./...   # Unit tests only
go test ./...          # All tests including integration
```

## DNS resolvers

Uses 11 trusted resolvers from 7 providers (Cloudflare, Google, Quad9, OpenDNS, Yandex, CleanBrowsing, Control D) with 3 retries per query.
