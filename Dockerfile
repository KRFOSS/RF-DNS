FROM rust:alpine as builder

WORKDIR /app

COPY . .

RUN apk update --no-cache && apk upgrade --no-cache

RUN cargo build --release

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk update --no-cache && apk add --no-cache ca-certificates

# Create a non-root user
RUN addgroup -g 1000 rfdns && \
    adduser -D -s /bin/sh -u 1000 -G rfdns rfdns

# Copy the binary from builder stage
COPY --from=builder /app/target/release/rfdns /usr/local/bin/rfdns

# Copy configuration files if they exist
COPY --from=builder /app/named.root /etc/rfdns/
COPY --from=builder /app/cert.pem /etc/rfdns/
COPY --from=builder /app/key.pem /etc/rfdns/

# Create directories
RUN mkdir -p /etc/rfdns && \
    chown -R rfdns:rfdns /etc/rfdns

# Switch to non-root user
USER rfdns

# Expose ports (assuming DNS ports)
EXPOSE 53/udp 53/tcp 853/tcp 443/tcp

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/rfdns"]

