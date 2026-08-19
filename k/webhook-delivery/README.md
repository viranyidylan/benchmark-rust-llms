# webhook-delivery

A small, durable webhook delivery service in Rust. `POST /webhook` accepts any JSON
payload plus a destination URL, persists the job to SQLite **before** acknowledging it,
and guarantees **at-least-once delivery** with exponential-backoff retries and a
dead-letter queue (DLQ) for jobs that exhaust their retries.

## Architecture

```
                                  +------------------------+
        POST /webhook             |      api (axum)        |     GET /health
 client ------------------------> |  POST /webhook         | <--------------
              202 {id}            |  GET /dlq              |
                                  |  POST /dlq/{id}/retry  |
                                  +-----------+------------+
                                              |
                                     INSERT (pending)    <-- persist-before-ack
                                              v
                                  +------------------------+
                                  |  sqlite  jobs  table   |
                                  | (id, destination,      |
                                  |  payload, status,      |
                                  |  attempts, next_       |
                                  |  attempt_at, ...)      |
                                  +-----------+------------+
                                              |
                              BEGIN IMMEDIATE | claim due pending jobs
                                              v
                                  +------------------------+
                                  |  workers (tokio tasks) |
                                  |  backoff + jitter      |
                                  +-----+--------------+---+
                                        |              |
                                  POST  | 2xx          | non-2xx / transport error
           +----------+   delivered     v              v
           | requests | <--------  [delivered]   attempts < max ?
           |  signed  |                                  |      \
           +----+-----+                            reschedule      attempts >= max
                |                                   (+backoff)           |
                v                                                        v
        +---------------+                                        +--------------+
        |  destination  |                                        |     DLQ      |
        |  (receiver)   |                                        | (status=dead)|
        +---------------+                                        +------+-------+
                                                                        |
                                                   POST /dlq/{id}/retry |
                                                                        v
                                                               back to pending
```

Every job flows `pending → in_flight → delivered`, or `pending → in_flight →
pending (rescheduled) → ... → dead`. The DLQ is just the `jobs` table filtered
on `status='dead'`; a manual retry moves a row back to `pending` with `attempts=0`.

## Quick start

```sh
cargo run
# or with overrides:
DATABASE_URL=sqlite://webhook.db?mode=rwc BIND_ADDR=0.0.0.0:3000 HMAC_SECRET=s3cret cargo run
```

Docker:

```sh
docker build -t webhook-delivery .
docker run -p 3000:3000 -e HMAC_SECRET=s3cret webhook-delivery
```

End-to-end demo (starts a local sink, delivers to it, forces a job into the DLQ,
then retries it):

```sh
./scripts/smoke.sh
```

## API reference

All responses are JSON. Errors are `{"error": "..."}` with an appropriate status.

### `POST /webhook` — enqueue a delivery

Body: `{"data": <any JSON>, "destination": "<absolute http(s) URL>"}`.
The job is persisted to SQLite *before* the `202` is returned.

```sh
curl -i -X POST http://127.0.0.1:3000/webhook \
  -H 'Content-Type: application/json' \
  -d '{"data": {"order_id": 123, "event": "created"}, "destination": "https://example.com/hooks/orders"}'
```

```
HTTP/1.1 202 Accepted
{"id":"f47ac10b-58cc-4372-a567-0e02b2c3d479"}
```

Failures: `400` invalid JSON / destination rejected by the SSRF guard;
`413` payload larger than `MAX_PAYLOAD_BYTES`.

### `GET /health` — liveness

```sh
curl -s http://127.0.0.1:3000/health
# {"status":"ok"}
```

### `GET /dlq` — list dead-lettered jobs

Returns up to 100 dead jobs, most recently updated first.

```sh
curl -s http://127.0.0.1:3000/dlq | jq
```

```json
[
  {
    "id": "9d3c8f8e-...",
    "destination": "http://127.0.0.1:39999/dead",
    "attempts": 8,
    "last_error": "transport error: error sending request ...",
    "updated_at": "2026-08-18T21:00:00Z"
  }
]
```

### `POST /dlq/{id}/retry` — requeue a dead job

Moves a dead job back to `pending` with `attempts=0` and `next_attempt_at=now`,
giving it a fresh round of delivery attempts.

```sh
curl -s -X POST http://127.0.0.1:3000/dlq/9d3c8f8e-0000-4000-8000-000000000000/retry
# {"requeued":true}           (200)
# {"error":"no dead job with id ..."}   (404 if not found / not dead)
```

## Configuration (environment variables)

| Name                         | Default                        | Meaning |
|------------------------------|--------------------------------|---------|
| `DATABASE_URL`               | `sqlite://webhook.db?mode=rwc` | SQLx SQLite connection string (`sqlite::memory:` works for tests). |
| `BIND_ADDR`                  | `0.0.0.0:3000`                 | Address the HTTP API binds to. |
| `MAX_ATTEMPTS`               | `8`                            | Total delivery attempts before a job is moved to the DLQ. |
| `BASE_DELAY_MS`              | `1000`                         | Base of the exponential backoff: `min(base * 2^(attempts-1), max)` with ±20% jitter. |
| `MAX_DELAY_MS`               | `300000`                       | Cap for the backoff delay (5 min). |
| `REQUEST_TIMEOUT_SECS`       | `10`                           | Timeout for a single delivery HTTP request. |
| `MAX_PAYLOAD_BYTES`          | `262144`                       | Max accepted body size for `POST /webhook` (256 KiB); larger bodies get `413`. |
| `HMAC_SECRET`                | `dev-insecure-secret`          | Secret used to sign deliveries. **Set this in production** — a warning is logged when the default is in use. |
| `ALLOW_PRIVATE_DESTINATIONS` | `false`                        | Set to `true` to allow private/loopback destinations (dev/tests). See Security. |
| `WORKER_POLL_MS`             | `500`                          | How long a worker sleeps when no jobs are due. |
| `WORKER_CONCURRENCY`         | `4`                            | Number of background delivery worker tasks. |
| `RUST_LOG`                   | —                              | `tracing_subscriber` env-filter, e.g. `info,tower_http=debug`. |

## Security

### SSRF guard

`destination` is validated **at enqueue time** (`POST /webhook`):

- must be an absolute `http://` or `https://` URL;
- no userinfo credentials (`http://user:pass@host/` is rejected);
- the host is resolved (DNS) and **every** resolved IP is checked — if *any* is
  loopback, private (RFC 1918 etc.), link-local (incl. `169.254.169.254`, the
  cloud metadata address), multicast, or unspecified, the request is rejected
  with `400`. IPv4-mapped IPv6 (`::ffff:10.0.0.1`) is unwrapped before the check.

Escape hatch: `ALLOW_PRIVATE_DESTINATIONS=true` skips the IP-range checks. This
exists for local development and for the test suite (destinations on `127.0.0.1`).
Never enable it on an internet-facing deployment.

Additionally, delivery requests use a fixed 10s timeout (configurable) and
**redirects are disabled**, so a validated destination cannot bounce the worker
to an internal address.

### HMAC signatures

Every delivery POST carries:

```
X-Webhook-Id: <job uuid>
X-Webhook-Signature: sha256=<hex(HMAC-SHA256(HMAC_SECRET, raw-body))>
Content-Type: application/json
```

Receivers should recompute the HMAC over the **raw request body** and compare in
constant time. Python:

```python
import hmac, hashlib

def verify(secret: str, body: bytes, signature_header: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)

# Flask-style usage:
# verify(SECRET, request.get_data(), request.headers["X-Webhook-Signature"])
```

### Payload limits

`POST /webhook` bodies above `MAX_PAYLOAD_BYTES` (default 256 KiB) are rejected
with `413` before parsing.

## At-least-once delivery

- **Persist-before-ack**: a job is INSERTed into SQLite (`status='pending'`,
  WAL journal + busy timeout) *before* `POST /webhook` returns `202`. An
  acknowledged webhook can never be silently lost.
- **Redelivery on crash**: workers claim due jobs by marking them `in_flight`
  inside an immediate transaction. If the process crashes mid-delivery, the
  job is either still `pending` (reclaimed on the next poll) or `in_flight`
  with a `next_attempt_at` in the past; on restart it is picked up and retried.
  Nothing lives only in memory.
- **Backoff**: failures reschedule with `min(base * 2^(attempts-1), max)` ± 20%
  jitter; after `MAX_ATTEMPTS` failures the job becomes `dead` (DLQ) and waits
  for a human to inspect and `POST /dlq/{id}/retry`.
- **Consumers must be idempotent**: because delivery is at-least-once, a
  destination can receive the same webhook more than once (e.g. the response
  was lost after the destination processed it). Receivers should deduplicate
  on `X-Webhook-Id` or their own idempotency key.

## Development

```sh
cargo test                                   # unit + integration tests
cargo clippy --all-targets -- -D warnings    # lint
cargo fmt                                    # format
./scripts/smoke.sh                           # end-to-end demo on a high port
```

Integration tests drive the full app (router + worker) against a mock
destination server on ephemeral ports; the smoke script uses a temp database
and cleans up all processes on exit.
