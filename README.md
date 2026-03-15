# Recon Job

Stateless Go binary packaged as a Docker container, executed as a Scaleway Serverless Job. Takes a wildcard as input, runs the full discovery pipeline, and pushes results to the API in real time.

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

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `WILDCARD` | yes | Target wildcard, e.g. `*.example.com` |
| `JOB_ID` | yes | UUID of the `recon_jobs` record |
| `MODE` | no | `normal` (default) or `intensive` |
| `API_URL` | yes | Base URL of the platform API |
| `INGEST_API_KEY` | yes | Secret for the ingest endpoint |
| `WORDLIST_URL` | intensive | URL to fetch bruteforce wordlist |
| `SUBFINDER_CONFIG` | no | Path to subfinder provider-config.yaml (API keys) |
| `JOB_TIMEOUT` | no | Job timeout duration (default: `2h`, intensive: `6h`) |
| `DNS_WORKERS` | no | Concurrent DNS resolution workers (default: `5`) |
| `LOG_LEVEL` | no | `debug` for verbose output (default: `info`) |

## Modes

**Normal** — passive subdomain enumeration (subfinder), top 1000 ports.

**Intensive** — subfinder + wordlist bruteforce + alterx permutations, full port range (1-65535).

## Subfinder API keys

To improve subdomain discovery, you can provide API keys for subfinder's sources (SecurityTrails, Shodan, Censys, etc.).

Create a `provider-config.yaml` file:

```yaml
securitytrails:
  - your-api-key
shodan:
  - your-api-key
censys:
  - your-id:your-secret
```

For the full list of supported providers, see the [subfinder documentation](https://github.com/projectdiscovery/subfinder#post-installation-instructions).

Pass the file via `SUBFINDER_CONFIG` pointing to its path inside the container.

**Local dev** — mount the file:

```bash
docker run --rm \
  --env-file .env \
  -v /path/to/provider-config.yaml:/config/provider-config.yaml \
  -e SUBFINDER_CONFIG=/config/provider-config.yaml \
  recon
```

**Scaleway** — store the file in [Secret Manager](https://www.scaleway.com/en/docs/serverless-jobs/how-to/reference-secret-in-job/) and inject it as a file in the Job Definition at `/config/provider-config.yaml`, then set `SUBFINDER_CONFIG=/config/provider-config.yaml`.

## Build

```bash
docker build -t recon .
```

## Run locally

```bash
docker run --rm \
  -e WILDCARD="*.example.com" \
  -e JOB_ID="550e8400-e29b-41d4-a716-446655440000" \
  -e MODE="normal" \
  -e API_URL="http://host.docker.internal:8080" \
  -e INGEST_API_KEY="secret" \
  recon
```

## Deploy to Scaleway

Push the image to Scaleway Container Registry, create a Job Definition once, then start runs with different parameters.

```bash
# 1. Push image to Scaleway Container Registry
docker login rg.fr-par.scw.cloud/recon -u nologin --password-stdin <<< "$SCW_SECRET_KEY"
docker tag recon:latest rg.fr-par.scw.cloud/recon/recon:latest
docker push rg.fr-par.scw.cloud/recon/recon:latest

# 2. Create the Job Definition (once)
scw jobs definition create \
  name=recon \
  cpu-limit=2000 \
  memory-limit=2048 \
  image-uri=rg.fr-par.scw.cloud/recon/recon:latest \
  environment-variables.API_URL="https://api.example.com" \
  environment-variables.INGEST_API_KEY="secret"

# 3. Start a run (per scan)
scw jobs definition start <definition-id> \
  environment-variables.WILDCARD="*.example.com" \
  environment-variables.JOB_ID="uuid-here" \
  environment-variables.MODE="normal"
```

Shared variables (`API_URL`, `INGEST_API_KEY`) go in the definition. Per-scan variables (`WILDCARD`, `JOB_ID`, `MODE`) are passed at run time.

## API payload examples

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

## Run tests

```bash
# Unit tests only (fast)
go test -short ./...

# All tests including integration
go test ./...
```

## Project structure

```
recon/
├── main.go              # Entrypoint, config loading, timeout, job status
├── config/
│   ├── config.go        # Env var loading + validation
│   └── config_test.go
├── pipeline/
│   ├── pipeline.go      # Orchestrates steps 1→6, graceful timeout handling
│   ├── discovery.go     # Step 1 — subfinder, bruteforce, alterx
│   ├── dns.go           # Step 2 — dnsx resolution + tlsx SAN extraction
│   ├── cdn.go           # Step 3 — cdncheck CDN/WAF detection
│   ├── portscan.go      # Step 4 — TCP connect scan
│   ├── ports.go         # Nmap top 1000 TCP ports list
│   ├── webdetect.go     # Step 5 — httpx web service detection
│   └── *_test.go
├── push/
│   └── api.go           # HTTP client for API ingest + job status
├── Dockerfile
├── go.mod
└── go.sum
```

## Timeout behavior

On timeout, the pipeline pushes whatever was collected so far (partial results) using a fresh 2-minute context, then exits cleanly. The job is marked as `completed` — partial data is better than no data.

## DNS resolvers

Uses 11 trusted resolvers from 7 providers (Cloudflare, Google, Quad9, OpenDNS, Yandex, CleanBrowsing, Control D) with 3 retries per query.
