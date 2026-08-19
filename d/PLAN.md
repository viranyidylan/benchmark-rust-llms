# Webhook Delivery Service — Implementation Plan (Rust)

## Goals
A production-grade webhook delivery service exposing `POST /webhook` that accepts
`{"data": <payload>, "destination": <url>}`, guarantees *at-least-once* delivery to
`destination`, with retries, a dead-letter queue, and security.

## Architecture Overview

```
Client ──POST /webhook {"data", "destination"}──▶ HTTP Server (axum)
                                                        │  validate + authenticate
                                                        ▼
                                                 Delivery Queue (in-memory + optional SQLite persistence)
                                                        │
                                          ┌─────────────┴──────────────┐
                                          │    Delivery Worker         │
                                          │  - attempt delivery        │
                                          │  - backoff retry schedule   │
                                          │  - max attempts → DLQ       │
                                          └─────────────┬──────────────┘
                                                        ▼
                                              Destination HTTP POST
```

- **Endpoint (axum)**: validates payload shape, authenticates callers, enqueues job, returns 202 Accepted.
- **Delivery Queue**: holds pending webhook jobs with attempt counter + next-retry-at timestamp. Backed by SQLite (rusqlite) so jobs survive restarts.
- **Delivery Worker (tokio)**: polls due jobs, POSTs payload to destination, increments attempts, schedules retry with exponential backoff + jitter, moves permanently-failed jobs to DLQ.
- **Retry policy**: exponential backoff (e.g., 1s, 2s, 4s, ... up to a cap), max attempts (e.g., 5) before DLQ.
- **Dead Letter Queue**: SQLite table storing permanently-failed deliveries keeping the full payload + destination + error, with an admin endpoint to inspect/redeliver.
- **Security**: 
  - Auth: shared-secret header (`X-Api-Key`) validated for `/webhook` and admin endpoints (via `tower-http` or manual middleware).
  - Input validation: destination must be an `http(s)://` URL; data can be arbitrary JSON.
  - SSRF guard firming: also reject private/reserved destination hosts (loopback, link-local, RFC1918) by default.
  - TLS for outbound via `reqwest` default.

## Tech Stack
- `tokio` (async runtime), `axum` (web framework), `reqwest` (HTTP client), `serde`/`serde_json`, `rusqlite` (SQLite with bundled feature), `tracing` (+ `tracing-subscriber`), `chrono`/`time` for timestamps, `uuid` for job ids, `thiserror`.

## Deliverables (file tree)
```
Cargo.toml
src/
  main.rs          – bootstrapping: config, router, worker, DB init
  config.rs        – Config (port, auth token, retry params, DLQ, persistence path)
  db.rs            – SQLite storage: queue + DLQ tables, CRUD operations
  models.rs        – WebhookRequest, WebhookJob, DeliveryStatus, DqlEntry
  webhook.rs       – POST /webhook handler: validate + enqueue
  worker.rs        – background delivery loop with retries/backoff → DLQ
  dlq.rs           – admin handlers: list DQL entries, redeliver
  security.rs      – auth middleware + input validation + SSRF host checks
  error.rs         – AppError + axum error responses
tests/
  integration.rs   – end-to-end tests for delivery, retry, DLQ
```

## Break into small individually-runnable pieces (each fits a fresh context window)

### Piece 1 — Project scaffold + Config + Models
Create Cargo project, define `Config`, `WebhookRequest`, `WebhookJob`, `DeliveryStatus`, `DqlEntry` models, and parsing/serde. Compiles with `cargo build`.

### Piece 2 — SQLite storage layer (`db.rs`)
Create SQLite DB with `jobs` and `dead_letters` tables; implement enqueue, fetch-due, mark-attempt, schedule-next, move-to-dlq, list-dlq, redeliver. Unit-testable against in-memory SQLite.

### Piece 3 — HTTP server + `/webhook` endpoint (`webhook.rs`, `error.rs`, `main.rs`)
Axum server with `POST /webhook`, validation (auth + input), DB enqueue, returns 202. `cargo run` smoke test with curl.

### Piece 4 — Delivery worker + retries + DLQ (`worker.rs`)
Background tokio worker pops due jobs, POSTs to destination via reqwest, applies exponential backoff, routes failures to DLQ. Unit tests with a local mock destination (tiny axum app) for success, failure, retry count, DLQ routing.

### Piece 5 — Security hardening + admin DLQ endpoints (`security.rs`, `dlq.rs`)
Add auth middleware to all endpoints, SSRF destination-host guarding, rate/body-limit, admin endpoints to list/redeliver DLQ, TLS outbound. Integration tests in `tests/integration.rs`.

### Piece 6 — Integration tests + polish
Full end-to-end tests: happy path, at-least-once under worker restart (persistence), retry then DLQ, auth rejection, SSRF rejection, redelivery. `cargo test`, README, `.env.example`.
