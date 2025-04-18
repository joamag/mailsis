FROM rust:latest as builder

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cargo build --all-targets --release

FROM rust:slim

EXPOSE 2525 1430

ENV HOST=0.0.0.0
ENV PORT=2525

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/mailsis-imap /usr/local/bin/mailsis-imap
COPY --from=builder /app/target/release/mailsis-smtp /usr/local/bin/mailsis-smtp
COPY --from=builder /app/certs /usr/local/bin/certs

WORKDIR /usr/local/bin

ENTRYPOINT ["/usr/local/bin/mailsis-smtp"]