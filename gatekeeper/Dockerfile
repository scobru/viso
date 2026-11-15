FROM rust:1-slim AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p viso-gatekeeper

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/viso-gatekeeper /usr/local/bin/viso-gatekeeper
WORKDIR /app
ENV BIND_ADDR=0.0.0.0:8080
ENV DATA_DIR=/data
ENV ISSUERS_CONFIG=/data/issuers.json
ENV AUTO_INIT_ISSUER=1
EXPOSE 8080
CMD ["viso-gatekeeper"]
