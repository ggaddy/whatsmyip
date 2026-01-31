# whatsmyip

A tiny, hardened Rust service that returns the caller's IP address.

## Behavior

- `GET /` returns the resolved client IP as plain text with a trailing newline.
- `GET /healthz` returns `ok`.
- `GET /readyz` returns `ready`.

By default the service **does not** trust forwarded headers. If you are running
behind Cloudflare Tunnel (cloudflared), configure `TRUSTED_PROXIES` so the
service will honor `CF-Connecting-IP` and `X-Forwarded-For` only when the
request came from the trusted proxy.

## Configuration

- `BIND_ADDR` (default: `0.0.0.0:8080`) - address to bind the server.
- `PORT` (optional) - if set and `BIND_ADDR` is not set, binds `0.0.0.0:$PORT`.
- `TRUSTED_PROXIES` (optional) - comma-separated IPs or CIDRs for trusted
  proxies. Example: `10.0.0.0/24, 192.168.1.10`.
- `RUST_LOG` (optional) - log level (default: `info`).

### Cloudflare Tunnel guidance

For cloudflared, set `TRUSTED_PROXIES` to the IP/CIDR of the cloudflared
workload that connects to this service (for example, the Pod CIDR, Service
CIDR, or a dedicated network policy-restricted range). **Do not** use
`0.0.0.0/0`, as that allows any client to spoof headers.

The resolver prefers headers in this order when the immediate peer is trusted:
`CF-Connecting-IP`, `X-Forwarded-For`, then `X-Real-IP`.

## Running locally

```bash
cargo run
```

```bash
curl http://127.0.0.1:8080/
```

## Container build

```bash
docker build -t whatsmyip .
```

```bash
docker run --rm -p 8080:8080 whatsmyip
```

For reproducible builds, generate and commit `Cargo.lock` and build with
`--locked` (the Dockerfile is written to be easy to adjust for that).

## Tests

```bash
cargo test
```
