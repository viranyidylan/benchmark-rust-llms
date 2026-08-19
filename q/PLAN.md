# Webhook Delivery Service — Build Plan

**Repo:** `/home/david/work/qwen38_27B/dylan/webhook-delivery` (cargo project; T0–T10 committed on `master`)
**Toolchain:** stable rustc 1.96.0, edition 2021
**Status tracker:** see [§9](#9-status-tracker) — update it as you go.
**Current state (2026-08-17):** **All tasks T0–T10 done and committed.** Full service wired end-to-end with 57 passing tests (56 unit + 1 end-to-end), clippy clean, fmt clean.

---

## 1. Goal

A Rust HTTP service that:

- Exposes `POST /webhook` accepting `{"data": <any JSON>, "destination": "<url>"}`.
- **Guarantees at-least-once delivery** of `data` to `destination` via HTTP POST.
- **Retries** transient failures with exponential backoff + jitter.
- **Dead-letter queue (DLQ)** for permanently failed / exhausted deliveries, with admin list + replay.
- **Security:** authenticated ingestion, rate limiting, payload size limits, SSRF protection,
  verified TLS outbound, separate admin credentials, constant-time comparisons.

## 2. Stack (verified to compile 2026-06-10 via scratch probe)

| Crate | Version | Notes |
|---|---|---|
| axum | 0.8 | HTTP server, router |
| tokio | 1 (features: full) | runtime, signals, sync |
| serde / serde_json | 1 | JSON |
| reqwest | 0.12 (`default-features = false`, features: `json`, `rustls-tls`) | outbound client, TLS-verified |
| rusqlite | 0.32 (`bundled`) | persistent queue (SQLite) |
| thiserror | 2 | error types |
| tracing / tracing-subscriber | 0.1 / 0.3 (`env-filter`) | structured logs |
| uuid | 1 (`v4`, `serde`) | delivery ids |
| tower | 0.5 (`util`) | test client (`ServiceExt::oneshot`) |
| tower-http | 0.6 (`limit`, `trace`) | body size limit, request tracing |
| hmac / sha2 | 0.12 / 0.10 | signature auth |
| rand | 0.8 | jitter |
| subtle | 2 | constant-time compare |
| url | 2 | URL parsing |
| dotenvy | 0.15 | `.env` support |

**Cargo.toml (exact, for T0):**

```toml
[package]
name = "webhook_delivery"
version = "0.1.0"
edition = "2021"

[dependencies]
axum = "0.8"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
rusqlite = { version = "0.32", features = ["bundled"] }
thiserror = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
uuid = { version = "1", features = ["v4", "serde"] }
tower = { version = "0.5", features = ["util"] }
tower-http = { version = "0.6", features = ["limit", "trace"] }
hmac = "0.12"
sha2 = "0.10"
rand = "0.8"
subtle = "2"
url = "2"
dotenvy = "0.15"

[dev-dependencies]
tower = { version = "0.5", features = ["util"] }
```

## 3. Architecture

```
                 ┌────────────────────────── service (single process) ──────────────────────────┐
 POST /webhook   │  api/                 security/               delivery/             db.rs   │
 ──────────────► │  webhook.rs  admin.rs ssrf.rs  auth.rs   worker.rs  backoff.rs    ─► SQLite  │
 (auth, rate     │  (router, state)      ratelimit.rs       classify.rs              (queue,    │
  limit, size,   │                                                              dlq, stats)    │
  validate,      └───────────────────────────────────────────────────────────────────────────────┘
  enqueue)                                                                                   │
                                                                                              ▼
                                                                                     HTTP POST (timeout,
                                                                                     rustls, no redirects)
```

**Components**

1. **Ingestion API** (`api/`) — validates + persists the submission, returns `202` immediately. Delivery is async.
2. **Queue** (`db.rs`, SQLite) — status machine `pending → in_flight → delivered | dead_letter`.
   Atomic claim: `UPDATE ... SET status='in_flight' WHERE id=? AND status='pending'` (rowcount decides winner).
   **Crash recovery:** on startup, rows stuck in `in_flight` longer than `STALE_IN_FLIGHT_MS` are reset to
   `pending` and redelivered. This is what makes delivery *at-least-once* (a send that succeeded but wasn't
   recorded before a crash is sent again).
3. **Worker pool** (`delivery/worker.rs`) — `WORKER_COUNT` tokio tasks poll for due rows, claim, POST, classify.
4. **Retries** (`delivery/backoff.rs`) — exponential backoff, full jitter, capped.
   Retryable: `5xx`, `429`, timeouts, connection/DNS/TLS transport errors. Permanent: other `4xx`.
5. **DLQ** (`db.rs` + `api/admin.rs`) — rows hitting `MAX_ATTEMPTS` (or a permanent failure) are moved to a
   `dead_letters` table; listable and replayable via admin API.
6. **Security** (`security/`) — bearer API keys **or** HMAC-SHA256 body signature (constant-time compare),
   per-key sliding-window rate limit, body size limit, SSRF policy, TLS-verified outbound, distinct admin key.

**At-least-once semantics (document this in the README):**
- Submission is persisted *before* the `202` is returned.
- A delivery is marked `delivered` only after a `2xx` response.
- Crash between send and mark ⇒ redelivery ⇒ receivers **may see duplicates** and must be idempotent.
- `Idempotency-Key` header dedupes *submissions* (same key ⇒ original id returned), not redeliveries.

## 4. API contract

| Method | Path | Auth | Body / Query | Response |
|---|---|---|---|---|
| POST | `/webhook` | bearer key **or** HMAC sig | `{"data": <any JSON>, "destination": "https://..."}`, optional `Idempotency-Key` header | `202 {"id":"<uuid>","status":"pending"}`; `200` + `duplicate:true` on idempotency hit |
| GET | `/deliveries/{id}` | admin | — | `200` full record; `404` |
| GET | `/admin/dead-letters` | admin | `?limit=&offset=` | `200` list |
| POST | `/admin/dead-letters/{id}/replay` | admin | — | `202` requeued; `404` |
| GET | `/admin/stats` | admin | — | `200` counters |
| GET | `/healthz` | none | — | `200 "ok"` |
| GET | `/readyz` | none | — | `200` if DB ping ok, else `503` |

**Error codes (ingestion):** `400` malformed JSON / missing fields / bad scheme, `401` bad/missing auth,
`403` SSRF-blocked destination, `413` body too large, `429` rate limited.
Error bodies: `{"error":"<short reason>"}` — never leak internals.

**Outbound delivery request** (what the destination receives):
- `POST <destination>`, body = the original `data` JSON, `Content-Type: application/json`
- Headers: `X-Webhook-Id: <delivery id>`, `X-Webhook-Attempt: <n>`, `X-Webhook-Timestamp: <unix-sec>`,
  and if `HMAC_SECRET` is set: `X-Webhook-Signature: sha256=<hex(hmac_sha256(secret, body))>`

## 5. Data model & schema (SQLite)

```sql
CREATE TABLE IF NOT EXISTS deliveries (
  id              TEXT PRIMARY KEY,           -- uuid v4
  idempotency_key TEXT UNIQUE,               -- nullable
  destination     TEXT NOT NULL,
  payload         BLOB NOT NULL,             -- raw JSON of `data`
  status          TEXT NOT NULL DEFAULT 'pending',  -- pending|in_flight|delivered|dead_letter
  attempts        INTEGER NOT NULL DEFAULT 0,
  max_attempts    INTEGER NOT NULL DEFAULT 8,
  next_retry_at   INTEGER NOT NULL,          -- unix epoch ms
  last_error      TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deliveries_poll ON deliveries (status, next_retry_at);

CREATE TABLE IF NOT EXISTS dead_letters (
  id               TEXT PRIMARY KEY,         -- uuid v4 (dlq entry id)
  delivery_id      TEXT NOT NULL,
  destination      TEXT NOT NULL,
  payload          BLOB NOT NULL,
  attempts         INTEGER NOT NULL,
  last_error       TEXT,
  dead_lettered_at INTEGER NOT NULL
);
```

`Db` API (rusqlite `Connection` behind `std::sync::Mutex`, all calls synchronous — callers in async code use
`tokio::task::spawn_blocking` or call from sync contexts; the worker is async so wrap in `spawn_blocking`):

- `new(path: &str) -> Result<Db>` — open (or `:memory:`), run migrations
- `insert(d: &NewDelivery) -> Result<(), DbError>` — `DbError::IdempotencyConflict(existing_id)` on unique hit
- `find(id) -> Option<Delivery>`, `list_due(now_ms, limit) -> Vec<Delivery>` (`status='pending' AND next_retry_at <= now`)
- `claim(id) -> bool` — atomic pending→in_flight
- `mark_delivered(id)`, `schedule_retry(id, next_ms, err)`, `dead_letter(id, err) -> DqEntry`
- `list_dead_letters(limit, offset) -> Vec<DlqEntry>`, `replay_dead_letter(delivery_id) -> bool` (resets attempts=0, pending, now)
- `reset_stale_in_flight(now_ms, stale_ms) -> usize`
- `stats() -> Stats { submitted, delivered, dead_lettered, pending, in_flight, dead_letters }`
- `ping() -> bool`

## 6. Configuration (env, parsed in `config.rs`)

| Var | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` | `127.0.0.1:8080` | bind address |
| `WEBHOOK_API_KEYS` | *(required)* | comma-separated bearer keys for `/webhook` |
| `WEBHOOK_ADMIN_KEY` | *(required)* | bearer key for admin endpoints |
| `HMAC_SECRET` | *(optional)* | if set, accept/emit HMAC-SHA256 signatures |
| `DATABASE_PATH` | `./data/webhook.db` | sqlite path (`:memory:` in tests) |
| `WORKER_COUNT` | `4` | delivery worker tasks |
| `POLL_INTERVAL_MS` | `500` | worker poll period |
| `MAX_ATTEMPTS` | `8` | total attempts before DLQ |
| `BASE_RETRY_DELAY_MS` | `5000` | backoff base |
| `MAX_RETRY_DELAY_MS` | `3600000` | backoff cap |
| `REQUEST_TIMEOUT_MS` | `10000` | outbound timeout |
| `MAX_PAYLOAD_BYTES` | `1048576` | inbound body limit (tower-http `Limit`) |
| `ALLOW_PRIVATE_DESTINATIONS` | `false` | SSRF escape hatch for tests/dev |
| `RATE_LIMIT_PER_MIN` | `120` | per-key sliding window |
| `STALE_IN_FLIGHT_MS` | `300000` | crash-recovery threshold |

`Config::from_env() -> Result<Config, ConfigError>` — validates all values; `Config::test_defaults()` helper
for tests (in-memory DB, 10 ms delays, `allow_private = true`, fixed keys).

## 7. Task breakdown

**How to run a task in a fresh context window:** paste this prompt:

> Read `/home/david/work/qwen38_27B/dylan/webhook-delivery/PLAN.md` (sections 1–6 give full context).
> Execute the first task marked ⬜ in §9, in order T0→T10. Follow its spec exactly; do NOT start later
> tasks. Iterate until its verification commands pass. Then update §9 (✅ + one-line note) and
> `git commit -m "Tn: <title>"`. Report a short summary.

Each task below is self-contained: goal → files → spec → verification → definition of done.

---

### T0 — Scaffold & dependencies

- **Files:** `Cargo.toml` (exact contents from §2), create empty module skeleton so the build passes:
  `src/main.rs` (fn main stub), `src/config.rs`, `src/model.rs`, `src/db.rs`, `src/api/mod.rs`,
  `src/security/mod.rs`, `src/delivery/mod.rs` (empty files / `pub mod` wiring as needed).
  Keep `.gitignore` (`/target`).
- **Spec:** edition 2021. No logic yet.
- **Verification:** `cargo build` && `cargo clippy` (no warnings) && `cargo test`.
- **DoD:** green; commit `T0: scaffold + dependencies`.

### T1 — Configuration

- **Files:** `src/config.rs`
- **Spec:** `Config` struct with every field from §6; `from_env()` reads env (dotenvy already loaded in T9's
  main; here just read `std::env`), validates (keys non-empty, numbers > 0, `LISTEN_ADDR` parses,
  `ALLOW_PRIVATE_DESTINATIONS` is "true"/"false"). `ConfigError` via thiserror. `Config::test_defaults()`.
- **Verification:** `cargo test config` — unit tests: defaults, env overrides, each invalid case → error.
- **DoD:** green; commit `T1: config`.

### T2 — Data model & DB layer

- **Files:** `src/model.rs`, `src/db.rs`
- **Spec:** types from §5 (`Delivery`, `NewDelivery`, `DeliveryStatus`, `DlqEntry`, `Stats`, `DbError`).
  Exact DDL from §5. Implement every `Db` method listed in §5. All timestamps unix epoch ms (`i64`).
  `next_retry_at` for new rows = now.
- **Verification:** `cargo test db` — in-memory DB tests:
  insert→list_due→claim (second claim returns false); `schedule_retry` moves row out of `list_due` until
  time passes; `mark_delivered`; `dead_letter` + `list_dead_letters` + `replay_dead_letter`;
  idempotency conflict returns existing id; `reset_stale_in_flight` only touches old rows; `stats` counts.
- **DoD:** green; commit `T2: model + db`.

### T3 — Backoff & outcome classification (pure logic)

- **Files:** `src/delivery/backoff.rs`, `src/delivery/classify.rs`
- **Spec:**
  - `backoff::next_delay_ms(attempt: u32, base_ms: u64, max_ms: u64, rng: &mut impl rand::RngCore) -> u64`
    — `exp = (attempt - 1).min(20); cap = min(base * 2^exp, max); rng.random_range(0..=cap)` (full jitter).
  - `classify::Outcome { Delivered, Retryable(String), Permanent(String) }`;
    `classify(status: u16, transport_err: Option<&reqwest::Error>) -> Outcome`
    — 2xx ⇒ Delivered; 429/5xx ⇒ Retryable; other 4xx ⇒ Permanent; transport error ⇒ Retryable(msg).
- **Verification:** `cargo test delivery` — jitter bounds (10k samples ∈ [0, cap] and > 0 with high
  probability), cap respected at high attempt counts, classification table (200/204/404/429/500/503 + timeout err).
- **DoD:** green; commit `T3: backoff + classify`.

### T4 — SSRF protection

- **Files:** `src/security/ssrf.rs`
- **Spec:**
  - `SsrfPolicy { allow_private: bool, allowed_ports: Vec<u16> }` (default ports `[80, 443]`).
  - `SsrfError` (thiserror): `BadScheme, MissingHost, Userinfo, BadPort, PrivateIp(IpAddr), ResolutionFailed(String)`.
  - `trait IpResolver { fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, String>; }` (sync; run inside
    `spawn_blocking` from async code) + `SystemResolver` via `std::net::ToSocketAddrs`.
  - `validate_url(url: &Url) -> Result<(), SsrfError>`: scheme must be http/https; host present;
    no userinfo; explicit port (if any) ∈ allowed_ports.
  - `validate(&self, url: &Url, resolver: &dyn IpResolver) -> Result<Vec<IpAddr>, SsrfError>`:
    `validate_url` + resolve; if `!allow_private`, every resolved IP must pass `is_blocked_ip`.
  - `is_blocked_ip(ip: IpAddr) -> bool`: block 0.0.0.0/8, 10/8, 100.64/10 (CGNAT), 127/8, 169.254/16,
    172.16/12, 192.168/16, 255/8 (broadcast), `::`, `::1`, `fc00::/7` (ULA), `fe80::/10` (link-local),
    and IPv4-mapped IPv6 (`::ffff:a.b.c.d` → check embedded IPv4).
- **Verification:** `cargo test ssrf` — `FakeResolver` returning fixed IPs: public IP allowed, each blocked
  range rejected (incl. IPv4-mapped), `allow_private` bypass, scheme/userinfo/port cases, `ftp://` rejected.
- **DoD:** green; commit `T4: ssrf`.

### T5 — Ingestion API (`POST /webhook`)

- **Files:** `src/api/mod.rs`, `src/api/webhook.rs`
- **Spec:**
  - `AppState { db: Db, cfg: Config, metrics: Metrics, ssrf: SsrfPolicy }` + `Metrics` struct of
    `Arc<AtomicU64>` counters (submitted, delivered, dead_lettered, permanent_failures, retryable_failures).
  - `router(state: AppState) -> Router` — routes from §4 (admin/health routes stubbed until T8/T9),
    `tower_http::limit::RequestBodyLayer::new(MAX_PAYLOAD_BYTES)`, `TraceLayer`.
  - Handler: parse body → SSRF `validate` (spawn_blocking) → `db.insert` → `202`.
    `Idempotency-Key` header → conflict returns `200 {"id": <orig>, "status": ..., "duplicate": true}`.
    Error mapping per §4 (400/403/413). Auth is NOT applied yet (T6 wraps it).
- **Verification:** `cargo test api` — axum test client (`tower::ServiceExt::oneshot`) with in-memory DB,
  `ALLOW_PRIVATE_DESTINATIONS = false`: happy path 202 + row in DB; bad JSON 400; `ftp://` 400;
  `http://127.0.0.1:9/x` 403; duplicate idempotency key → 200 duplicate; 2 MiB body → 413.
- **DoD:** green; commit `T5: ingestion api`.

### T6 — Auth & rate limiting

- **Files:** `src/security/auth.rs`, `src/security/ratelimit.rs`, extend `src/api/mod.rs`
- **Spec:**
  - `auth::constant_time_eq(a: &[u8], b: &[u8]) -> bool` (subtle); `check_bearer(headers, keys: &[String]) -> bool`;
    `check_hmac(headers, raw_body: &[u8], secret: &str) -> bool` for `X-Webhook-Signature: sha256=<hex>`
    (HMAC-SHA256 over the **raw** body, constant-time hex compare).
  - `ratelimit::RateLimiter` — per-key sliding window over `RATE_LIMIT_PER_MIN` (`check(key) -> bool`),
    `Arc`-shareable, time-based pruning.
  - Apply to `/webhook`: no valid auth ⇒ `401`; rate limit exceeded ⇒ `429`. Helper
    `admin_authorized(headers, admin_key) -> bool` for T8.
- **Verification:** `cargo test security` — bearer accept/reject (incl. wrong key, missing header, empty keys list),
  HMAC accept + tampered-body reject + missing-header fallback to bearer, rate limiter trips at N+1 and
  recovers after window, per-key isolation.
- **DoD:** green; commit `T6: auth + ratelimit`.

### T7 — Delivery worker

- **Files:** `src/delivery/worker.rs`
- **Spec:**
  - `build_client(cfg) -> reqwest::Client`: `REQUEST_TIMEOUT_MS` timeout, **no redirects**,
    `User-Agent: webhook-delivery/0.1`, rustls.
  - `send(client, d: &Delivery, attempt: u32) -> Outcome`: POST `d.destination` with body = payload,
    headers from §4 (signature only if `HMAC_SECRET` set). Map response/transport error via `classify`.
  - `Worker::run(&self, shutdown: &watch::Receiver<bool>)`: on start `reset_stale_in_flight`; loop:
    if shutdown break; `list_due(now, 20)`; per row: re-validate SSRF (fail ⇒ `dead_letter("ssrf")`),
    `claim` (skip if false), `send`, then per `Outcome`: Delivered ⇒ `mark_delivered`;
    Retryable ⇒ attempts+1, `>= max_attempts` ⇒ `dead_letter` else `schedule_retry(next_delay)`;
    Permanent ⇒ `dead_letter`. Update metrics. Sleep `POLL_INTERVAL_MS`.
- **Verification:** `cargo test worker` — integration tests: in-memory DB + `Config::test_defaults()`
  (10 ms base delay, `allow_private = true`) + a mock destination (axum on `127.0.0.1:0` with a scripted
  `VecDeque<u16>` of status codes, `Arc<Mutex<..>>`). Cases: `200` ⇒ delivered attempts=1;
  `500,500,200` ⇒ delivered attempts=3; `404` ⇒ dead_lettered; stale in_flight row gets reset+redelivered.
- **DoD:** green; commit `T7: delivery worker`.

### T8 — Dead-letter queue & admin API

- **Files:** `src/api/admin.rs`, extend router
- **Spec:** endpoints from §4, all guarded by `admin_authorized` (401 otherwise):
  `GET /admin/dead-letters?limit=&offset=`, `POST /admin/dead-letters/{id}/replay` (resets delivery row to
  pending/attempts=0/now; DLQ row kept for audit), `GET /deliveries/{id}`, `GET /admin/stats`.
- **Verification:** `cargo test admin` — always-500 destination with `MAX_ATTEMPTS=2` ⇒ row appears in
  dead-letters list; replay ⇒ status pending & attempts 0; stats reflect counts; 401 without admin key;
  404 for unknown id.
- **DoD:** green; commit `T8: dlq + admin api`.

### T9 — Observability, health, main wiring

- **Files:** `src/main.rs`, extend router
- **Spec:** `dotenvy::dotenv().ok()`; tracing-subscriber with `EnvFilter` (`RUST_LOG`, default `info`);
  build Config/Db/AppState/client; spawn `WORKER_COUNT` workers + shutdown `watch` channel;
  `tokio::select!` over ctrl_c/SIGTERM and `axum::serve`; on shutdown: set watch, let workers drain,
  drop DB cleanly. `GET /healthz` ⇒ 200; `GET /readyz` ⇒ 200 if `db.ping()` else 503.
- **Verification (manual smoke):** `ALLOW_PRIVATE_DESTINATIONS=true WEBHOOK_API_KEYS=k WEBHOOK_ADMIN_KEY=a \
  cargo run` in one terminal; in another: `curl -s localhost:8080/healthz` (200), `/readyz` (200),
  submit webhook to a local mock (`python3 -m http.server` won't do POST — use a 5-line python socket or
  nc) or accept that delivery fails and check `/admin/stats` shows the attempt; `kill -TERM` ⇒ clean exit.
  Plus `cargo clippy` clean.
- **DoD:** smoke passes; commit `T9: observability + main`.

### T10 — End-to-end test, README, final pass

- **Files:** `tests/e2e.rs`, `README.md`
- **Spec:** single in-process e2e (router + worker + in-memory DB + mock destination, `test_defaults`):
  1. happy path 202→delivered; 2. `500,500,200` ⇒ delivered attempts=3; 3. always-500, `MAX_ATTEMPTS=2`
  ⇒ dead-lettered → listed → replayed → delivered; 4. security: 401 no key, 403 loopback dest
  (`allow_private=false`), 400 `ftp://`, 429 with tiny rate limit, 413 oversized; 5. idempotency dedupe;
  6. crash recovery: force `in_flight` + old `updated_at` ⇒ redelivered after `reset_stale_in_flight`.
  README: overview, quickstart, config table (§6), API reference with curl examples, security model,
  at-least-once semantics + limitations, scaling notes (multi-instance ⇒ swap SQLite for Postgres;
  schema is portable), ops notes (backup = copy the SQLite file, `RUST_LOG` levels).
- **Verification:** `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test` (all green).
- **DoD:** all green; commit `T10: e2e + readme`.

---

## 8. Known limitations (document, don't block on)

- SQLite ⇒ single-instance queue. Multi-instance needs Postgres (schema is portable) — out of scope.
- SSRF TOCTOU: DNS is validated at enqueue **and** at delivery, but the client re-resolves; full IP pinning
  (custom connector) is a stretch goal.
- Rate limiting and metrics are in-memory (per-process).
- No per-destination dedupe at delivery time — at-least-once ⇒ duplicates possible by design.

## 9. Status tracker

| Task | Status | Note |
|---|---|---|
| T0 scaffold | ✅ | Exact §2 Cargo.toml (edition 2021) + empty module skeleton (main/config/model/db/api/security/delivery); build, clippy, test all green |
| T1 config | ✅ | `Config` struct (all §6 fields), `from_env()` + validation, `ConfigError` (thiserror), `test_defaults()`; 10 unit tests (defaults, overrides, each invalid case) |
| T2 model + db | ✅ | `model.rs` domain types + `now_ms()`; `db.rs` `Db` (Mutex<Connection>), exact §5 DDL + all methods (insert/find/list_due/claim/mark_delivered/schedule_retry/dead_letter/list_dead_letters/replay_dead_letter/reset_stale_in_flight/stats/ping); 7 in-memory tests |
| T3 backoff + classify | ✅ | `delivery/backoff.rs` full-jitter `next_delay_ms` (rand 0.8 `RngCore` has no `random_range` — manual 64-bit uniform over `0..=cap`); `delivery/classify.rs` `Outcome` + `classify(status, transport_err)`; 5 tests (jitter bounds 10k samples, cap at high attempts, classification table, transport err) |
| T4 ssrf | ✅ | `security/ssrf.rs`: `SsrfPolicy` (validate_url + validate), `IpResolver` trait + `SystemResolver`, `is_blocked_ip` (all spec ranges incl. CGNAT/ULA/link-local/IPv4-mapped); 5 tests with `FixedResolver` |
| T5 ingestion api | ✅ | `api/mod.rs` (`AppState`, `Metrics` Arc<AtomicU64> counters, `ApiError` → JSON `{"error"}`, `router()` with RequestBodyLimitLayer + TraceLayer); `api/webhook.rs` `POST /webhook` (RawValue payload stored verbatim, SSRF validate + insert in spawn_blocking, idempotency conflict → 200 duplicate); 6 tests (202+row, bad JSON 400, ftp 400, private 403, duplicate 200, 2 MiB → 413) |
| T6 auth + ratelimit | ✅ | `security/auth.rs`: `constant_time_eq` (subtle), `check_bearer`, `check_hmac` (`X-Webhook-Signature: sha256=<hex>` over raw body), `authorized` (HMAC when header present + secret set, else bearer fallback), `admin_authorized` (T8); `security/ratelimit.rs`: `RateLimiter` sliding window (check/prune/active_keys); wired into `/webhook` (401/429); 14 tests |
| T7 delivery worker | ✅ | `delivery/worker.rs`: `build_client` (timeout, no redirects, UA `webhook-delivery/0.1`, rustls), `send` (POST payload + §4 headers, optional `X-Webhook-Signature`), `Worker::run` (stale in_flight reset on start; loop: shutdown check, `list_due(now, 20)`, per row SSRF re-validate → claim → send → classify → `mark_delivered`/`schedule_retry`/`dead_letter` + metrics, poll `POLL_INTERVAL_MS` with `tokio::select` shutdown); `mark_delivered` now counts the final successful send (PLAN T7: `200` ⇒ attempts=1, `500,500,200` ⇒ attempts=3); 4 integration tests vs axum mock with scripted `VecDeque<u16>` (200⇒delivered, 500,500,200⇒delivered attempts=3, 404⇒DLQ, stale in_flight reset+redelivered) |
| T8 dlq + admin api | ✅ | `api/admin.rs`: `GET /admin/dead-letters?limit=&offset=` (oldest first, default 50 / cap 1000), `POST /admin/dead-letters/{id}/replay` (id = DLQ entry id; resets delivery to pending/attempts=0/due-now, DLQ row kept for audit; 404 unknown), `GET /deliveries/{id}` (full record, 404 unknown), `GET /admin/stats` (DB queue counters + process Metrics snapshot); all guarded by `admin_authorized` (401); `Db::find_dlq_entry`; `ApiError::not_found`; routes wired in `router()` (axum 0.8 `{id}` capture syntax); 3 tests (always-500 + MAX_ATTEMPTS=2 ⇒ DLQ row, replay ⇒ pending/attempts 0 + audit row kept, stats counts; 401 all 4 endpoints; 404 unknown ids) |
| T9 observability + main | ✅ | `main.rs`: `dotenvy::dotenv().ok()`, tracing-subscriber + `EnvFilter` (`RUST_LOG`, default `info`), Config/Db/AppState/client build, DB parent-dir creation, bind `LISTEN_ADDR`, spawn `WORKER_COUNT` workers (own shutdown `watch` channel each), `tokio::select!` over ctrl_c/SIGTERM and `axum::serve`, on shutdown set watch → await worker drain → clean DB drop, periodic rate-limiter prune task; `api/health.rs`: `GET /healthz` (200), `GET /readyz` (200 if `db.ping()` else 503); 2 tests; live smoke: healthz/readyz 200, unauth webhook 401, authed webhook 202 (refused destination ⇒ retryable; stats show submitted=1/pending=1/retryable_failures=1), SSRF 403 on disallowed port, unauth stats 401, stats 200 with counters, SIGTERM ⇒ clean exit 0 with worker drain; clippy fully clean (dead code gone) |
| T10 e2e + readme | ✅ | `tests/e2e.rs`: single in-process e2e (real router + worker + in-memory DB + scripted mock destination) covering all six scenarios — happy path 202⇒delivered attempts=1, `500,500,200`⇒delivered attempts=3, always-500 + MAX_ATTEMPTS=2 ⇒ dead-lettered → listed → replayed ⇒ delivered, security battery (401 no key / 403 loopback dest / 400 `ftp://` / 429 tiny limit / 413 oversized), idempotency dedupe, crash recovery (stale in_flight reset ⇒ redelivered attempts=2); `README.md` (quickstart, §6 config table, API reference with curl, security model, at-least-once semantics, scaling + ops notes); `src/lib.rs` created (pub modules + `run()`, thin `main.rs`) so `tests/` can link the crate; `test_defaults`/`set_in_flight_stale_for_test` ungated for integration tests; 57 tests green (56 unit + 1 e2e), clippy 0 warnings, fmt clean |
