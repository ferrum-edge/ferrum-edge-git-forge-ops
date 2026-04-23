# Ferrum Edge GitForgeOps

GitOps workflow for managing [Ferrum Edge](https://github.com/ferrum-edge/ferrum-edge) gateway configuration via pull requests.

Fork this repo, configure a few environment variables, and get a full-featured GitOps pipeline: PR-based resource submission, automated validation, intelligent review commentary, and config application to your running gateways.

## Quick Start

```
1. Fork this repo
2. Go to Settings > Secrets and variables > Actions
3. Add secrets:
   - FERRUM_GATEWAY_URL        → your Admin API URL (e.g. https://gw.example.com:9000)
   - FERRUM_ADMIN_JWT_SECRET   → HS256 secret for minting Admin API JWTs (min 32 chars)
4. Add resources as YAML files under resources/<namespace>/
5. Open a PR — CI validates and posts a review comment
6. Merge — CI applies to your gateway
```

## How It Works

You define gateway resources (proxies, consumers, upstreams, plugins) as individual YAML files organized by namespace. The built-in CI workflows handle the rest:

- **On PR open/update**: Validates config via `ferrum-edge validate`, posts a structured review comment with change summary, breaking change detection, security audit, and best practice recommendations.
- **On merge to main**: Applies the validated config to your gateway — either via the Admin API (database/CP mode) or by assembling a flat file (file mode).

## Repository Layout

```
resources/
  ferrum/                        # namespace: ferrum (default)
    proxies/
      my-api.yaml                # kind: Proxy
    consumers/
      alice.yaml                 # kind: Consumer
    upstreams/
      api-cluster.yaml           # kind: Upstream
    plugins/
      rate-limit.yaml            # kind: PluginConfig
  team-alpha/                    # namespace: team-alpha (multi-tenant)
    proxies/
      alpha-service.yaml

overlays/                        # optional environment overrides
  staging/
    ferrum/
      proxies/
        my-api.yaml              # override backend_host, timeouts, etc.
  production/
    ferrum/
      proxies/
        my-api.yaml

assembled/
  resources.yaml                 # auto-generated flat file (file mode)
```

## Resource File Format

Each file contains one resource with a `kind` discriminator. The namespace is inferred from the directory name under `resources/` (e.g. `resources/ferrum/proxies/` → namespace `ferrum`).

### Proxy

```yaml
kind: Proxy
spec:
  id: "proxy-my-api"
  name: "My API"
  listen_path: "/api/v1"
  backend_protocol: https
  backend_host: "api.internal"
  backend_port: 8443
  strip_listen_path: true
  backend_connect_timeout_ms: 5000
  backend_read_timeout_ms: 30000
  upstream_id: "api-cluster"
  auth_mode: single
  plugins:
    - plugin_config_id: "plugin-api-keyauth"
```

### Consumer

```yaml
kind: Consumer
spec:
  id: "consumer-alice"
  username: "alice"
  credentials:
    keyauth:
      key: "${ALICE_API_KEY}"        # secret ref — resolved at apply time
  acl_groups:
    - "engineering"
```

### Upstream

```yaml
kind: Upstream
spec:
  id: "api-cluster"
  name: "API Backend Pool"
  algorithm: round_robin
  targets:
    - host: "api-1.internal"
      port: 8443
      weight: 1
    - host: "api-2.internal"
      port: 8443
      weight: 1
  health_checks:
    active:
      http_path: "/health"
      interval_seconds: 10
```

### PluginConfig

```yaml
kind: PluginConfig
spec:
  id: "plugin-api-keyauth"
  plugin_name: "key_auth"
  scope: proxy
  proxy_id: "proxy-my-api"
  enabled: true
  config:
    key_location: "header:X-API-Key"
```

## Configuration

All configuration is via GitHub repository **secrets** and **variables**. No config files to write.

### Secrets

Set in: Settings > Secrets and variables > Actions > Secrets

| Secret | Description |
|--------|-------------|
| `FERRUM_GATEWAY_URL` | Admin API base URL (e.g. `https://gw.example.com:9000`) |
| `FERRUM_ADMIN_JWT_SECRET` | HS256 secret for minting Admin API JWTs (min 32 chars) |
| `FERRUM_GATEWAY_CA_CERT` | Custom CA cert (PEM, base64-encoded) for Admin API TLS. Omit for public CA. |
| `FERRUM_GATEWAY_CLIENT_CERT` | Client cert (PEM, base64-encoded) for mTLS to Admin API. Optional. |
| `FERRUM_GATEWAY_CLIENT_KEY` | Client key (PEM, base64-encoded) for mTLS. Required if `CLIENT_CERT` set. |

### Variables

Set in: Settings > Secrets and variables > Actions > Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FERRUM_GATEWAY_MODE` | `api` | `api` = push via Admin API, `file` = assemble flat YAML |
| `FERRUM_NAMESPACE` | — | Filter to one namespace. Omit to process all. |
| `FERRUM_APPLY_STRATEGY` | `incremental` | `incremental` (CRUD) or `full-replace` (POST /restore) |
| `FERRUM_OVERLAY` | — | Overlay directory (e.g. `staging`, `production`) |
| `FERRUM_EDGE_VERSION` | `latest` | Ferrum Edge release tag for validation binary (e.g. `v0.9.0`). Pin this to match your runtime. |
| `FERRUM_TLS_NO_VERIFY` | `false` | Skip TLS verification (dev only) |

## Apply Modes

### API Mode (default)

For gateways running in `database` or `cp` mode with a live Admin API. On merge, gitforgeops:

1. Assembles resources + overlays
2. Resolves secret references (`${VAR_NAME}` → env var values)
3. Fetches current state via `GET /backup`
4. Computes minimal changeset (add/modify/delete)
5. Applies via `POST /batch` or individual CRUD calls
6. Verifies applied state

Resources are grouped by namespace and sent with the appropriate `X-Ferrum-Namespace` header.

### File Mode

For gateways running in `FERRUM_MODE=file` — no database, no control plane. On merge, gitforgeops:

1. Assembles all resources + overlays into `assembled/resources.yaml`
2. Validates via `ferrum-edge validate`
3. Commits the assembled file back to main

Operators consume `assembled/resources.yaml` via their deployment pipeline (git pull, K8s ConfigMap, Docker volume, Ansible, ArgoCD, etc.). The gateway picks it up on SIGHUP or restart.

## Multi-Namespace

Multiple teams share one repo. Each namespace is a top-level directory under `resources/`:

```
resources/
  ferrum/            # default namespace
  team-alpha/        # team-alpha namespace
  team-beta/         # team-beta namespace
```

Set `FERRUM_NAMESPACE=team-alpha` to filter to a single namespace (e.g. for team-scoped CI). Omit to process all namespaces.

## Overlays

For multi-environment deployments, overlay files deep-merge with base resources matched by `id`:

```yaml
# overlays/production/ferrum/proxies/my-api.yaml
kind: Proxy
spec:
  id: "proxy-my-api"
  backend_host: "api-prod.internal"
  backend_read_timeout_ms: 15000
```

Only overridden fields are needed. Set `FERRUM_OVERLAY=production` to activate.

## TLS Connectivity

The tool connects to the Ferrum Admin API over HTTPS:

- **Public CA**: No config needed — system roots used.
- **Internal PKI / self-signed**: Set `FERRUM_GATEWAY_CA_CERT` (base64-encoded PEM).
- **mTLS**: Set `FERRUM_GATEWAY_CLIENT_CERT` and `FERRUM_GATEWAY_CLIENT_KEY`.
- **Dev only**: `FERRUM_TLS_NO_VERIFY=true` disables verification.

## CLI

The `gitforgeops` binary can be used locally or in CI:

```
gitforgeops validate              # Assemble and validate via ferrum-edge validate
gitforgeops diff                  # Semantic diff against live gateway
gitforgeops plan                  # Full analysis: validate + diff + breaking + security
gitforgeops apply                 # Apply to gateway (API or file)
gitforgeops import                # Import from live gateway into resource files
gitforgeops export                # Assemble into single flat YAML
gitforgeops review                # Generate PR review comment
```

## PR Review Comments

When a PR modifies resources, CI posts a structured review:

```
## GitForgeOps Config Review

### Validation: PASS (0 errors, 1 warning)
- [warn] Proxy "new-service" has no rate limiting plugin

### Changes
| Action | Kind | ID | Details |
|--------|------|----|---------|
| ADD | Proxy | new-service | /api/new → new-svc.internal:8080 |
| MODIFY | Proxy | my-api | backend_read_timeout_ms: 30000 → 15000 |

### Breaking Changes: NONE

### Security: PASS

### Best Practices
- [info] Consider adding rate_limiting to proxy "new-service"
```

## Drift Detection

A scheduled workflow checks daily for config drift between git and the live gateway:

```bash
gitforgeops diff --exit-on-drift
```

Reports drifted (changed outside git), orphaned (in live but not git), and missing (in git but not live) resources.

## Docker

A Dockerfile is included that bundles both `gitforgeops` and `ferrum-edge` into a single image. The `ferrum-edge` binary is pulled from the official `ferrumedge/ferrum-edge` Docker Hub image.

### Building

```bash
# Uses latest ferrum-edge
docker build -t gitforgeops .

# Pin to a specific ferrum-edge version (match your runtime)
docker build --build-arg FERRUM_EDGE_VERSION=v0.9.0 -t gitforgeops .
```

### Running locally

```bash
docker run --rm -v $(pwd):/repo gitforgeops validate
docker run --rm -v $(pwd):/repo gitforgeops export --output assembled/resources.yaml
```

### Version Pinning

Set the `FERRUM_EDGE_VERSION` GitHub Actions variable to pin the `ferrum-edge` binary version used in CI workflows. This should match the version of Ferrum Edge running in your environment to ensure validation rules are consistent.

For example, if your gateways run `v0.9.0`, set `FERRUM_EDGE_VERSION=v0.9.0` in your repo's Actions variables. The CI workflows will download that specific release for validation. If unset, `latest` is used.

## License

PolyForm Noncommercial License 1.0.0
