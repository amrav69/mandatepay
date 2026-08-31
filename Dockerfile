FROM rust:1-slim AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY dashboard ./dashboard
RUN cargo build --release --bin mandatepay

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/mandatepay /usr/local/bin/mandatepay
COPY .env.example .env.example
EXPOSE 8080
ENV RUST_LOG=info
CMD ["mandatepay"]
