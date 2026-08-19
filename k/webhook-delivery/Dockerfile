# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM rust:1-slim AS builder
WORKDIR /app

# Compile dependencies first for better layer caching.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && touch src/lib.rs \
    && cargo build --release \
    && rm -rf src

# Now build the real binary.
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release

# ---- Runtime stage ----
FROM debian:bookworm-slim
RUN useradd --system --uid 10001 webhook && mkdir -p /app && chown webhook /app
WORKDIR /app
COPY --from=builder /app/target/release/webhook-delivery /usr/local/bin/webhook-delivery
USER webhook

ENV BIND_ADDR=0.0.0.0:3000 \
    DATABASE_URL=sqlite:///app/webhook.db?mode=rwc \
    MAX_ATTEMPTS=8 \
    BASE_DELAY_MS=1000 \
    MAX_DELAY_MS=300000 \
    REQUEST_TIMEOUT_SECS=10 \
    MAX_PAYLOAD_BYTES=262144 \
    WORKER_POLL_MS=500 \
    WORKER_CONCURRENCY=4
# HMAC_SECRET has no safe default -> pass -e HMAC_SECRET=... at runtime.

EXPOSE 3000
CMD ["webhook-delivery"]
