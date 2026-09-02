FROM rust:1.85-slim-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY dashboard ./dashboard
RUN cargo build --release --bin mandatepay

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/* \
    && groupadd -r app && useradd -r -g app app
WORKDIR /app
COPY --from=builder /app/target/release/mandatepay /usr/local/bin/mandatepay
COPY .env.example .env.example
RUN chown -R app:app /app
USER app
EXPOSE 8080
ENV RUST_LOG=info
ENV BIND_HOST=0.0.0.0
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD curl -f http://localhost:8080/health || exit 1
CMD ["mandatepay"]
