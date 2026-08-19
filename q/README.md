# webhook-delivery

A small, self-contained webhook ingestion and delivery service in Rust.

Clients `POST` a JSON payload plus a destination URL; the service stores the
delivery in SQLite, then a background worker retries it with exponential
backoff until it succeeds, fails permanently, or is dead-lettered. Dead
letters can be inspected and replayed through a tiny admin API.

Built with [axum](https://docs.rs/axum) 0.8, tokio, rusqlite (bundled SQLite),
and reqwest (rustls). One binary, one database file, no external dependencies.

## Quickstart

```sh
cargo build --release
export WEBHOOK_API_KEYS="my-secret-key"
export WEBHOOK_ADMIN_KEY="my-admin-key"
./target/release/webhook-delivery
```

Then submit a webhook:

```sh
curl -s -X POST http://127.0.0.1:8080/webhook \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"data": {"hello": "world"}, "destination": "https://example.com/hook"}'
# -> 202 {"id": "<uuid>", "status": "pending"}
```

Track it:

```sh
curl -s http://127.0.0.1:8080/deliveries/<uuid> -H "Authorization: Bearer my-admin-key"
```

Run the test suite (unit + end-to-end):

```sh
cargo test
```

## Configuration

All configuration is via environment variables (a `.env` file is loaded if
present).

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `127.0.0.1:8080` | HTTP listen address |
| `WEBHOOK_API_KEYS` | *(required)* | Comma-separated list of accepted bearer API keys |
| `WEBHOOK_ADMIN_KEY` | *(required)* | Bearer key for the admin endpoints |
| `HMAC_SECRET` | *(unset)* | When set, requests may authenticate with an `X-Webhook-Signature: sha256=<hex>` header instead of a bearer key |
| `DATABASE_PATH` | `./data/webhook.db` | SQLite file path (`:memory:` for ephemeral) |
| `WORKER_COUNT` | `4` | Delivery worker tasks per process |
| `POLL_INTERVAL_MS` | `500` | Worker poll interval |
| `MAX_ATTEMPTS` | `8` | Sends per delivery before dead-lettering |
| `BASE_RETRY_DELAY_MS` | `5000` | Exponential backoff base |
| `MAX_RETRY_DELAY_MS` | `3600000` | Exponential backoff cap (1 h) |
| `REQUEST_TIMEOUT_MS` | `10000` | Per-delivery HTTP timeout |
| `MAX_PAYLOAD_BYTES` | `1048576` | Max request body for `POST /webhook` (1 MiB) |
| `ALLOW_PRIVATE_DESTINATIONS` | `false` | Allow delivering to private/loopback/link-local addresses (SSRF guard) |
| `RATE_LIMIT_PER_MIN` | `120` | Max `POST /webhook` requests per minute per API key |
| `STALE_IN_FLIGHT_MS` | `300000` | Age after which an `in_flight` row is considered crashed and reset on startup (5 min) |

## API

### `POST /webhook`

Submit a webhook for delivery.

- Auth: `Authorization: Bearer <api-key>` **or**
  `X-Webhook-Signature: sha256=<hex-hmac-of-body>` (when `HMAC_SECRET` is set).
- Body: `{"data": <any JSON>, "destination": "https://..."}`.
  `data` is stored verbatim and re-sent on delivery.
- Optional header: `Idempotency-Key` — resubmitting with the same key returns
  the original delivery instead of creating a new one.

Responses:

- `202 {"id": "<uuid>", "status": "pending"}` — accepted.
- `200 {"id": "<uuid>", "status": "...", "duplicate": true}` — idempotent replay.
- `400` — malformed JSON, bad destination, non-http(s) scheme.
- `401` — missing/invalid credentials.
- `403` — destination rejected by the SSRF policy (private IP, disallowed port, userinfo).
- `413` — body larger than `MAX_PAYLOAD_BYTES`.
- `429` — per-key rate limit exceeded.

```sh
curl -s -X POST http://127.0.0.1:8080/webhook \
  -H "Authorization: Bearer my-secret-key" \
  -H "Idempotency-Key: order-123" \
  -d '{"data": {"order": 123}, "destination": "https://example.com/hook"}'
```

### `GET /deliveries/{id}` (admin)

Full delivery record: id, idempotency key, destination, payload, status
(`pending` / `in_flight` / `delivered` / `dead_letter`), attempt counts,
next retry time, last error, timestamps (epoch ms).

```sh
curl -s http://127.0.0.1:8080/deliveries/<uuid> -H "Authorization: Bearer my-admin-key"
```

### `GET /admin/dead-letters?limit=&offset=` (admin)

Bare JSON array of dead-lettered deliveries (newest first):

```json
[
  {
    "id": "<dlq-uuid>",
    "delivery_id": "<delivery-uuid>",
    "destination": "https://example.com/hook",
    "payload": {"order": 123},
    "attempts": 8,
    "last_error": "HTTP 500",
    "dead_lettered_at": 1712345678901
  }
]
```

### `POST /admin/dead-letters/{id}/replay` (admin)

Requeues the dead-lettered delivery (`pending`, `attempts = 0`, due now).
`{id}` is the **DLQ entry id** from the list above. The DLQ row is kept for
audit. Returns `202 {"requeued": true, "delivery_id": "<uuid>"}`.

### `GET /admin/stats` (admin)

```json
{
  "queue": {
    "submitted": 0, "delivered": 0, "dead_lettered": 0,
    "pending": 0, "in_flight": 0, "dead_letters": 0
  },
  "process": {
    "submitted": 0, "delivered": 0, "dead_lettered": 0,
    "permanent_failures": 0, "retryable_failures": 0
  }
}
```

`queue` is counted from the database; `process` is counted for this process
lifetime.

### `GET /healthz`, `GET /readyz`

`healthz` returns `200` when the process is up. `readyz` returns `200` when
the database answers, `503` otherwise. No auth.

## Security model

- **Auth** — `POST /webhook` accepts either a bearer API key from
  `WEBHOOK_API_KEYS` or, when `HMAC_SECRET` is configured, an
  `X-Webhook-Signature: sha256=<hex>` header (HMAC-SHA256 of the raw body,
  constant-time compared). If the signature header is present the bearer key
  is *not* consulted (no fallback); if it is absent the bearer key is used.
  Admin endpoints accept only `WEBHOOK_ADMIN_KEY`.
- **Rate limiting** — per-minute fixed window, keyed by the bearer token (or
  an `anonymous` bucket). Auth is checked before rate limiting, so rejected
  requests do not consume quota.
- **SSRF guard** — destinations are validated before storage *and* re-validated
  on every delivery attempt: http/https only, no userinfo, port must be in the
  allowed set (80/443 by default), and — unless
  `ALLOW_PRIVATE_DESTINATIONS=true` — the resolved address must not be
  private, loopback, link-local, or otherwise internal.
- **Payload bound** — request bodies over `MAX_PAYLOAD_BYTES` are rejected
  with `413` before reaching the handler.

## Delivery semantics

- **At-least-once.** A delivery is retried until it is marked `delivered`
  (2xx from the destination), `dead_letter` (retryable failures exhaust
  `MAX_ATTEMPTS`, or a permanent 4xx), or replayed by an operator. The
  destination must be idempotent — the same payload can be delivered more
  than once (e.g. after a crash between send and status update).
- **Backoff.** Full jitter: the delay before retry `attempt` (1-based) is
  uniform in `0..=min(BASE_RETRY_DELAY_MS * 2^(attempt-1),
  MAX_RETRY_DELAY_MS)` (exponent capped at 20).
- **Attempt accounting.** `attempts` counts sends actually made. A
  dead-lettered row with `MAX_ATTEMPTS = N` made exactly `N` sends.
- **Crash recovery.** On startup, workers reset `in_flight` rows whose
  `updated_at` is older than `STALE_IN_FLIGHT_MS` back to `pending` (due
  now), so a process that died mid-delivery does not lose the row.
- **Idempotency.** `Idempotency-Key` (unique per key) makes resubmission safe:
  the second call returns `200` with the original delivery id.
- **Replay.** `POST /admin/dead-letters/{id}/replay` requeues a dead letter
  with `attempts = 0`; the DLQ row is kept for audit.

## Limitations & scaling

- **Single process, single SQLite file.** The worker claims rows with an
  atomic `UPDATE ... WHERE status = 'pending'`, which is safe for multiple
  worker tasks *within one process* (shared connection pool, one writer at a
  time). Running multiple *processes* against the same file is not supported.
- **Scale-out path.** To run multiple instances, swap the SQLite backend for
  Postgres (the `Db` layer isolates all SQL) and point every instance at the
  shared database; the claim query already makes cross-process claiming safe.
- **In-memory metrics.** The `process` counters in `/admin/stats` are per
  process lifetime, not persisted.
- **No TLS termination.** Terminate TLS in front of the service (reverse
  proxy / load balancer) or run it on a private network.
- **DNS re-resolution.** Destinations are re-resolved and re-validated on
  every attempt (SSRF guard), so DNS-rebinding to an internal address is
  caught at delivery time, not just at submission time.

## Operations

- **Backup.** Copy the SQLite file (e.g. `sqlite3 webhook.db ".backup
  backup.db"` or a file copy while the service is stopped). Everything —
  queue, deliveries, dead letters — lives in that one file.
- **Logging.** `RUST_LOG` controls the tracing subscriber
  (`RUST_LOG=webhook_delivery=debug,info` for verbose service logs;
  `RUST_LOG=debug` for everything).
- **Shutdown.** `SIGINT`/`SIGTERM` stop the HTTP server and workers cleanly
  (exit code 0); in-flight rows are picked up by the next startup via the
  stale-reset described above.
- **Dead-letter hygiene.** Dead letters are never pruned automatically.
  Replay what you can, and consider periodic archival of the
  `dead_letters` table as it grows.
