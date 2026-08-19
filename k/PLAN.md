# Webhook Delivery Service — Build Plan

## Goal
A Rust HTTP service exposing `POST /webhook` that accepts `{"data": <any JSON>, "destination": "<url>"}`,
durably persists the job, and guarantees **at-least-once delivery** to the destination with:
- Exponential-backoff retries
- A dead letter queue (DLQ) for jobs that exhaust retries
- Security: SSRF protection (URL validation / IP-range blocking), payload size limits, request timeouts,
  optional HMAC signature header so receivers can verify authenticity
- DLQ inspection & manual retry endpoints

## Tech Stack (fixed — all steps must use these exact versions/crates)
- Rust edition 2021, tokio (full), axum 0.7, serde/serde_json, sqlx 0.8 (sqlite, runtime-tokio),
  reqwest 0.12 (rustls, json), uuid v4, chrono, tracing/tracing-subscriber, url 2, thiserror, anyhow,
  ipnetwork 0.20, hmac 0.12 + sha2 0.10 + hex (signatures), tokio-util (cancellation), tower-http (trace)

## Project Layout (created in Step 1; later steps only edit named files)
```
webhook-delivery/
├── Cargo.toml
├── migrations/0001_init.sql
├── src/
│   ├── main.rs        # bootstrap: config, db, worker spawn, router
│   ├── lib.rs         # re-exports modules so integration tests can use them
│   ├── config.rs      # env-based config
│   ├── db.rs          # sqlx pool + queries (enqueue, claim, reschedule, dead-letter)
│   ├── models.rs      # WebhookRequest, Job, JobStatus, DLQ views
│   ├── security.rs    # SSRF validation, size limits, HMAC signing
│   ├── worker.rs      # background delivery loop, retry/backoff, DLQ moves
│   ├── routes.rs      # axum handlers: /webhook, /health, /dlq endpoints
│   └── error.rs       # ApiError + IntoResponse
└── tests/
    ├── webhook_api.rs
    └── delivery.rs
```

## Key Design Decisions (apply to every step)
1. **Durability first**: `POST /webhook` INSERTs the job into SQLite (`status='pending'`) *before*
   returning `202 Accepted` with a job id. Delivery never happens before persistence → at-least-once.
2. **Delivery loop**: background worker claims pending jobs whose `next_attempt_at <= now`
   (BEGIN IMMEDIATE tx: SELECT due pending rows, UPDATE them to `in_flight` with `attempts+1`, COMMIT).
   After HTTP attempt: success → `delivered`; failure → reschedule with
   `next_attempt_at = now + backoff(attempts)`; `attempts >= max_attempts` → `dead` (DLQ).
3. **Backoff**: `min(base_delay * 2^(attempts-1), max_delay)` with ±20% jitter.
   Defaults: base=1s, max=5min, max_attempts=8.
4. **Security**:
   - `destination` must be an absolute `http(s)://` URL, no userinfo credentials.
   - Resolve host; reject private/loopback/link-local/multicast/unspecified IPs (SSRF guard), including
     IPv4-mapped IPv6. Config flag `ALLOW_PRIVATE_DESTINATIONS=true` relaxes this for dev/tests.
   - Max payload 256 KiB, 10s request timeout, redirects disabled (`redirect::Policy::none()`).
   - Each delivery sends `X-Webhook-Signature: sha256=<hmac_sha256(secret, body)>` + `X-Webhook-Id: <uuid>`.
5. **Tests** use wiremock (or a tiny axum sink) as the destination; DLQ endpoints list/retry dead jobs.

## Definition of Done
`cargo test` green; `cargo clippy` clean; manual smoke: start server, POST a webhook to a local sink,
see delivery; POST to an unreachable host with low max_attempts and watch it land in the DLQ, then retry it.

---

# STEP PROMPTS (run each in a NEW context window, in order)
# Every step prompt must start with: "Read PLAN.md in the project root for stack/layout/decisions."
# Steps run inside the project dir: webhook-delivery/

## Step 1 — Project scaffold + config + models
Read PLAN.md. Create the cargo project `webhook-delivery` in the current working directory.
- `Cargo.toml` with exactly the crates from "Tech Stack" (pin: tokio 1 full, axum 0.7, sqlx 0.8 with
  features ["runtime-tokio","sqlite","chrono","uuid","migrate"], reqwest 0.12 with
  default-features=false + ["rustls-tls","json"], serde with derive, serde_json,
  uuid {version=1, features=["v4","serde"]}, chrono {version=0.4, features=["serde"]}, tracing,
  tracing-subscriber with env-filter, url 2, thiserror, anyhow, ipnetwork 0.20, hmac 0.12, sha2 0.10,
  hex, fastrand 2, tokio-util 0.7, tower-http 0.5 with trace; dev-deps: wiremock 0.6).
- `src/lib.rs` declaring all modules (empty stubs allowed so it compiles).
- `src/config.rs`: `Config::from_env()` → database_url (default `sqlite://webhook.db?mode=rwc`),
  bind_addr (`0.0.0.0:3000`), max_attempts=8, base_delay_ms=1000, max_delay_ms=300000,
  request_timeout_secs=10, max_payload_bytes=262144, hmac_secret (dev default + tracing::warn if default),
  allow_private_destinations=false, worker_poll_ms=500, worker_concurrency=4.
- `src/models.rs`: `WebhookRequest { data: serde_json::Value, destination: String }` (Deserialize),
  `WebhookAccepted { id: Uuid }` (Serialize), `Job { id: Uuid, destination: String,
  payload: serde_json::Value, status: JobStatus, attempts: i64, max_attempts: i64,
  next_attempt_at: DateTime<Utc>, last_error: Option<String>, created_at, updated_at }`,
  `enum JobStatus { Pending, InFlight, Delivered, Dead }` with as_str()/FromStr,
  `DlqEntry { id, destination, attempts, last_error, updated_at }` (Serialize, From<Job>).
- `src/error.rs`: `ApiError` enum (Validation(String), PayloadTooLarge, Internal(anyhow::Error))
  implementing IntoResponse with JSON body `{"error": "..."}` and correct status codes.
- Verify: `cargo check` passes. Report file tree + check output.

## Step 2 — Database layer + migration
Read PLAN.md. Work in `webhook-delivery/`. Implement persistence.
- `migrations/0001_init.sql`: table `jobs(id TEXT PRIMARY KEY, destination TEXT NOT NULL,
  payload TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL, next_attempt_at TEXT NOT NULL, last_error TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`; index `idx_jobs_due` on `(status, next_attempt_at)`.
- `src/db.rs`: `#[derive(Clone)] pub struct Db(SqlitePool)`; `Db::connect(&Config)` sets
  `PRAGMA journal_mode=WAL`, `PRAGMA busy_timeout=5000`, runs `sqlx::migrate!()`. Methods:
  - `insert_job(&self, id: Uuid, destination: &str, payload: &serde_json::Value, max_attempts: i64)`
  - `claim_due_jobs(&self, limit: i64) -> Vec<Job>` — BEGIN IMMEDIATE tx; SELECT due pending rows
    ORDER BY next_attempt_at LIMIT ?; UPDATE → status='in_flight', attempts=attempts+1, updated_at=now;
    COMMIT; deserialize payload JSON.
  - `mark_delivered(&self, id)`, `reschedule_job(&self, id, next_attempt_at, error: &str)`,
    `mark_dead(&self, id, error: &str)`, `list_dead(&self, limit) -> Vec<Job>`,
    `requeue_dead(&self, id) -> bool` (status pending, attempts=0, next_attempt_at=now; false if not found/not dead).
  - Timestamps: chrono UTC RFC3339 strings.
- Unit tests in `db.rs` (`#[cfg(test)]`, `sqlite::memory:`): insert→claim→mark_delivered;
  claim marks in_flight and increments attempts; reschedule→not-due-yet→not claimed;
  mark_dead→list_dead→requeue_dead→claimed again.
- Verify: `cargo test db::` passes.

## Step 3 — Security module (SSRF guard + HMAC + limits)
Read PLAN.md. Work in `webhook-delivery/`. Implement `src/security.rs`.
- `pub async fn validate_destination(url_str: &str, allow_private: bool) -> Result<Url, SecurityError>`:
  parse with `url::Url`; scheme must be http/https; host present; empty username and no password;
  if host is an IP literal check ranges directly; if a domain, resolve via `tokio::net::lookup_host`
  using port 443 (https) or 80 (http); reject if ANY resolved IP is loopback, private, link-local,
  multicast, or unspecified — include IPv4-mapped IPv6 (`::ffff:a.b.c.d` → check the v4). Skip range
  checks when allow_private=true. SecurityError variants: InvalidUrl, SchemeNotAllowed,
  CredentialsNotAllowed, UnresolvableHost, PrivateAddressBlocked.
- `pub fn sign_body(secret: &str, body: &[u8]) -> String` → `format!("sha256={}", hex(HMAC_SHA256(secret, body)))`.
- `pub fn enforce_size(len: usize, max: usize) -> Result<(), SecurityError>` (PayloadTooLarge variant).
- Unit tests (no DNS in tests — only IP literals + parse-level checks, plus one allow_private=true case):
  rejects `http://127.0.0.1/x`, `http://[::1]/`, `http://10.0.0.5/`, `http://169.254.169.254/latest/meta-data`
  (cloud metadata!), `http://user:pass@example.com/`, `ftp://example.com/`, relative URLs;
  accepts `http://127.0.0.1:9000/hook` with allow_private=true;
  HMAC matches a known test vector; enforce_size errors at max+1.
- Verify: `cargo test security::` passes.

## Step 4 — HTTP API: POST /webhook, /health, DLQ endpoints
Read PLAN.md. Work in `webhook-delivery/`. Implement `src/routes.rs`; wire `src/main.rs`; add `src/lib.rs` re-exports.
- `#[derive(Clone)] AppState { db: Db, config: Arc<Config> }`.
- Handlers:
  - `POST /webhook`: read body as `Bytes` with a manual size check (disable axum's DefaultBodyLimit on this
    route and enforce `config.max_payload_bytes` → 413); parse `WebhookRequest` (400 on bad JSON);
    `security::validate_destination` (400 on failure); serialize `data`; `db.insert_job`; return
    `202 Accepted` + `WebhookAccepted` JSON.
  - `GET /health` → `{"status":"ok"}`.
  - `GET /dlq` → `Vec<DlqEntry>` from `db.list_dead(100)`.
  - `POST /dlq/{id}/retry` → 200 `{"requeued": true}` or 404.
- `pub fn build_router(state: AppState) -> Router` with TraceLayer. `main.rs`: load config, init tracing,
  connect db, bind `tokio::net::TcpListener`, serve (leave a marked TODO call site where Step 5 spawns the worker).
- Integration test `tests/webhook_api.rs`: helper spins `build_router` on an ephemeral port with
  in-memory db and allow_private_destinations=true (except one test that sets it false). Assert:
  202 + uuid for valid request; 400 for `{"destination":"http://127.0.0.1/x"}` when flag is false;
  400 for invalid JSON; 413 for oversize body (set max_payload_bytes small in test config);
  GET /dlq returns `[]`; POST /dlq/{random}/retry → 404.
- Verify: `cargo test` passes.

## Step 5 — Delivery worker with retries, backoff, DLQ
Read PLAN.md. Work in `webhook-delivery/`. Implement `src/worker.rs` and spawn it from `main.rs`.
- `pub fn spawn_workers(state: AppState, shutdown: CancellationToken) -> Vec<JoinHandle<()>>` — spawn
  `config.worker_concurrency` tasks; each loops: `claim_due_jobs(8)`; if empty, `tokio::select!` on
  sleep(worker_poll_ms) vs shutdown; else deliver each job (concurrently per task is fine with a small
  buffer or sequentially — keep it simple and correct).
- `deliver(client: &reqwest::Client, job: &Job, config: &Config) -> Result<(), DeliveryError>`: client built
  once per task (timeout from config, `redirect::Policy::none()`); POST serialized payload bytes with
  `Content-Type: application/json`, `X-Webhook-Id`, `X-Webhook-Signature` (from security::sign_body).
  2xx → Ok; anything else (status, transport, timeout) → Err with a short message (status code or error kind).
- Outcome handling: Ok → `mark_delivered`; Err and `attempts < max_attempts` → `reschedule_job` with
  `next_attempt_at = now + backoff(attempts, base_ms, max_ms)` where backoff = `base * 2^(attempts-1)`
  capped at max, ±20% jitter via `fastrand`; Err and `attempts >= max_attempts` → `mark_dead` (DLQ).
  Log each attempt with tracing (job id, attempt, destination, outcome) — never log payload bodies.
- `main.rs`: create CancellationToken, `spawn_workers`, `tokio::signal::ctrl_c` → cancel token →
  await worker handles after server shutdown (use `axum::serve(...).with_graceful_shutdown(...)`).
- Integration test `tests/delivery.rs`: start wiremock `MockServer`; config: allow_private_destinations=true,
  base_delay_ms=50, max_delay_ms=200, max_attempts=3, worker_poll_ms=50, worker_concurrency=1.
  Cases: (a) 200 sink → delivered, sink received exact body + valid signature header + X-Webhook-Id;
  (b) 500,500,200 → delivered on 3rd attempt, sink saw 3 requests; (c) always-500 → job dead,
  appears in GET /dlq with attempts==max_attempts, then POST /dlq/{id}/retry + sink now 200 → delivered.
  Drive the full app (router + worker) on ephemeral ports. Use generous timeouts with polling loops.
- Verify: `cargo test` passes.

## Step 6 — Hardening, docs, final verification
Read PLAN.md. Work in `webhook-delivery/`. Finish and polish.
- `cargo clippy --all-targets -- -D warnings` clean; `cargo fmt`.
- `README.md`: ASCII architecture diagram, API docs with curl examples, env var table, security notes
  (SSRF guard details, HMAC verification snippet in Python/Node for receivers), run instructions,
  and a short "Why at-least-once" section (persist-before-ack + redelivery; consumers must be idempotent).
- `.gitignore` (target/, *.db, *.db-shm, *.db-wal); multi-stage `Dockerfile` (rust:slim build →
  debian-slim or distroless runtime, EXPOSE 3000).
- `scripts/smoke.sh`: starts the server, runs a tiny sink (python3 http.server or nc), POSTs a webhook,
  polls /dlq, demonstrates the DLQ flow with an unreachable destination.
- Re-run the full suite: `cargo test` — paste results. Report any deviations from PLAN.md and why.
