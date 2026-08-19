# Webhook Delivery Service (Rust)

A production-grade webhook delivery service that accepts events and guarantees
**at-least-once** delivery to a destination URL, with retries, a dead-letter
queue, persistence, and security hardening.

## Endpoints

All endpoints require the `X-Api-Key` header (configurable via `API_KEY`).

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/webhook` | Enqueue a delivery. Body: `{"data": <json>, "destination": "<url>"}`. Returns `202` with the job id. |
| `GET`  | `/dlq`    | List dead-letter entries (permanently failed deliveries). |
| `POST` | `/dlq/:id/redeliver` | Re-queue a dead-letter entry for a fresh delivery attempt. |

## Delivery semantics

- Each submitted job is persisted to SQLite **before** acknowledging, so no job
  is lost even if the process dies right after `POST` (durable enqueue).
- A background worker polls for due jobs and `POST`s the payload to the
  destination.
- On failure it retries with **exponential backoff + jitter**, capped at
  `RETRY_MAX_SECS`, up to `MAX_ATTEMPTS` attempts.
- After exhausting attempts the job moves to the **dead-letter queue**, keeping
  the full payload, destination, attempt count, and last error.
- Because the job stays in the `jobs` table until delivered (or moved to DLQ),
  a crash/restart does **not** lose a pending job — the worker resumes it
  (durable at-least-once).

## Security

- **Authentication**: shared-secret `X-Api-Key` required on every endpoint
  (middleware).
- **Input validation**: `destination` must be an absolute `http(s)://` URL;
  `data` may be arbitrary JSON.
- **SSRF protection**: destination hosts are rejected if they are loopback,
  private, link-local, carrier-grade NAT, reserved, or resolve (via DNS) to a
  private address. Disable with `ALLOW_PRIVATE=true` (test/local only).
- **Body size limit**: 1 MiB per request (configurable).
- **Outbound TLS**: outbound delivery uses rustls-backed `reqwest` (no plaintext
  to non-TLS except `http://` destinations, which the caller explicitly opts
  into).

## Configuration (environment variables)

| Var | Default | Meaning |
|-----|---------|---------|
| `BIND_ADDR` | `0.0.0.0:8080` | HTTP listen address |
| `API_KEY` | `dev-secret` | Shared secret for `X-Api-Key` |
| `DB_PATH` | `webhook.db` | SQLite database file |
| `MAX_ATTEMPTS` | `5` | Max delivery attempts before DLQ |
| `RETRY_BASE_SECS` | `1` | Base backoff delay |
| `RETRY_MAX_SECS` | `300` | Backoff cap |
| `POLL_INTERVAL_MS` | `500` | Worker poll interval |
| `ALLOW_PRIVATE` | `false` | Allow delivering to private hosts (test only) |

## Build & run

```bash
cargo build --release
API_KEY='my-secret' DB_PATH='data.db' cargo run
```

## Test

```bash
cargo test
```

## Development notes

See [`PLAN.md`](PLAN.md) for the design and incremental implementation plan.
