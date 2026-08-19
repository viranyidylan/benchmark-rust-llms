# webhook-delivery

A durable, at-least-once webhook delivery service in Rust.

It exposes an HTTP API for accepting webhooks, persists them to an embedded
SQLite (WAL) queue, and delivers them to arbitrary `http`/`https`
destinations via a background worker with exponential backoff retries, a
dead letter queue (DLQ), and requeue support.

## Quickstart

```bash
export WEBHOOK_SIGNING_SECRET="$(openssl rand -hex 32)"
export API_TOKEN="some-token-for-clients"   # optional; protects all API routes
cargo run --release
```

```bash
curl -s -X POST localhost:8080/webhook \
  -H 'content-type: application/json' \
  -H 'x-api-token: some-token-for-clients' \
  -d '{"data":{"event":"order.created","id":123},"destination":"https://example.com/hook"}'
# => {"id":"0199...","status":"pending"}   (202 Accepted)

curl -s localhost:8080/webhook/0199... -H 'x-api-token: some-token-for-clients'
# => {"id":"0199...","status":"delivered","attempts":1,...}
```

## API

| Method | Path                | Description                                              |
|--------|---------------------|----------------------------------------------------------|
| POST   | `/webhook`          | Enqueue a delivery: `{ "data": <any json>, "destination": "https://..." }`. Returns `202` with `{"id", "status"}` after the job is durably persisted. |
| GET    | `/webhook/{id}`     | Delivery status: `pending`, `processing`, `delivered`, `dead_lettered` (+ attempts, errors, timestamps). |
| GET    | `/dlq?limit=100`    | List dead-lettered deliveries (newest first).            |
| POST   | `/dlq/{id}/requeue` | Move a dead-lettered delivery back to the queue with a fresh attempt budget. |
| GET    | `/stats`            | Delivery counts grouped by status.                       |
| GET    | `/healthz`          | Liveness probe (no auth required).                       |

All routes except `/healthz` require the `X-API-Token` header when `API_TOKEN`
is configured.

## Delivery semantics (at-least-once)

- **Durable accept**: a webhook is committed to SQLite (WAL journal,
  `synchronous=FULL`) *before* the `202` is returned. An accepted job is never
  lost, even if the process dies immediately after.
- **Retries**: any non-2xx response, connection failure, or timeout counts as
  a failed attempt. Retries use exponential backoff with full jitter
  (`delay ∈ [min(base·2^n, cap)/2, cap]`), default base 1s, cap 5min.
- **Dead letter queue**: after `MAX_ATTEMPTS` (default 10) failed attempts the
  job is parked in `dead_lettered` state with the last error, inspectable via
  `/dlq` and replayable via `/dlq/{id}/requeue`.
- **Crash recovery**: on startup, and continuously via a visibility timeout,
  jobs stuck in `processing` are returned to the queue. This means a job can
  be delivered more than once (e.g. delivered but not marked before a crash),
  which is exactly the at-least-once contract.
- **Idempotency for receivers**: every attempt carries a stable `X-Webhook-Id`
  header, so receivers can deduplicate and turn at-least-once into
  effectively-once.
- The identical payload bytes are delivered and signed on every attempt.

## Security

- **HMAC signatures**: each delivery includes
  - `X-Webhook-Id`: stable delivery id (dedupe key)
  - `X-Webhook-Timestamp`: unix seconds
  - `X-Webhook-Signature: v1=<hex>`: `HMAC-SHA256(secret, "{timestamp}.{body}")`

  Receivers should verify the signature and reject timestamps outside a small
  window (e.g. 5 minutes) to prevent replay. Example verification (Python):

  ```python
  import hmac, hashlib

  def verify(secret: str, timestamp: str, body: bytes, signature: str) -> bool:
      expected = "v1=" + hmac.new(
          secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256
      ).hexdigest()
      return hmac.compare_digest(expected, signature)
  ```

- **SSRF protection**: destinations must be absolute `http`/`https` URLs
  without credentials; the host must resolve only to public addresses.
  Loopback, private, link-local (incl. `169.254.169.254` metadata),
  multicast, CGNAT `100.64/10`, documentation, and unspecified ranges are
  blocked, for both IPv4 and IPv6 (including IPv4-mapped). The check runs at
  enqueue time *and* again before every delivery attempt, and outbound
  redirects are disabled so a destination cannot bounce to a blocked host.
  Set `ALLOW_PRIVATE_DESTINATIONS=true` for local development only.
- **Payload limits**: request bodies are capped (`MAX_PAYLOAD_BYTES`,
  default 256 KiB; oversized requests get `413`).
- **API authentication**: optional bearer-style `X-API-Token` compared in
  constant time.
- **Delivery timeouts**: each attempt is capped (`DELIVERY_TIMEOUT_SECS`,
  default 10s) with a 5s connect timeout.

## Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `BIND_ADDR` | `0.0.0.0:8080` | HTTP listen address |
| `DATABASE_URL` | `sqlite://webhooks.db?mode=rwc` | SQLite database |
| `WEBHOOK_SIGNING_SECRET` | *(random, ephemeral)* | HMAC signing key; set a stable value in production |
| `API_TOKEN` | *(none)* | When set, required on all routes except `/healthz` |
| `MAX_PAYLOAD_BYTES` | `262144` | Max request/payload size in bytes |
| `MAX_ATTEMPTS` | `10` | Attempts before dead-lettering |
| `RETRY_BASE_MS` | `1000` | Base retry delay |
| `RETRY_MAX_MS` | `300000` | Max retry delay (cap) |
| `POLL_INTERVAL_MS` | `200` | Worker poll interval |
| `BATCH_SIZE` | `50` | Max deliveries claimed per poll |
| `VISIBILITY_TIMEOUT_SECS` | `60` | Reclaim `processing` jobs older than this |
| `DELIVERY_TIMEOUT_SECS` | `10` | Per-attempt outbound timeout |
| `MAX_CONCURRENT_DELIVERIES` | `64` | Concurrent outbound deliveries |
| `DB_MAX_CONNECTIONS` | `8` | SQLite pool size |
| `ALLOW_PRIVATE_DESTINATIONS` | `false` | Allow private/loopback destinations (dev only) |

## Development

```bash
cargo test     # unit + integration tests (spins up real servers)
cargo run      # dev server
RUST_LOG=debug cargo run
```

## Design notes

- `src/routes.rs` — HTTP API, auth middleware, body limit.
- `src/worker.rs` — polling loop; atomic job claim
  (`UPDATE ... WHERE id IN (SELECT due jobs ...) RETURNING ...`), visibility
  timeout reclaim, per-job bounded delivery tasks.
- `src/deliver.rs` — outbound delivery, signing headers, backoff with jitter.
- `src/security.rs` — SSRF guard and HMAC signing.
- `src/db.rs` — SQLite setup (WAL, `synchronous=FULL`), startup recovery.

Limitations by design (single-process scope): the queue is SQLite-backed and
the worker runs in-process; scale vertically or shard by destination. DNS is
re-validated per attempt, which shrinks (but does not fully eliminate) the
DNS-rebinding window; for strict pinning, front this service with an
egress-proxy that enforces IP allowlists.
