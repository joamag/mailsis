FROM rust:alpine as builder
RUN apk add --no-cache musl-dev gcc pkgconf openssl openssl-dev musl-dev openssl-libs-static

WORKDIR /app
COPY . .

RUN cargo build --all-targets --release

FROM alpine:latest

EXPOSE 2525 1430

ENV HOST=0.0.0.0
ENV PORT=2525

RUN apk add --no-cache libc6-compat ca-certificates

COPY --from=builder /app/target/release/mailsis-imap /usr/local/bin/mailsis-imap
COPY --from=builder /app/target/release/mailsis-smtp /usr/local/bin/mailsis-smtp
COPY --from=builder /app/certs /usr/local/bin/certs

WORKDIR /usr/local/bin

ENTRYPOINT ["/usr/local/bin/mailsis-smtp"]
