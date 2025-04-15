# Build stage
FROM rust:1.81-slim-bullseye as builder

# Install build dependencies including OpenSSL
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
COPY . .

# Build the application (skip benchmarks)
RUN cargo build --release --bins

# Runtime stage
FROM debian:bullseye-slim

WORKDIR /usr/local/bin

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl1.1 \
    && rm -rf /var/lib/apt/lists/*

# Copy the built binary from builder
COPY --from=builder /usr/src/app/target/release/ddos_protection_service .

# Copy configuration files
COPY --from=builder /usr/src/app/config /usr/local/etc/ddos_protection

# Set environment variables
ENV RUST_LOG=info
ENV CONFIG_FILE=/usr/local/etc/ddos_protection/default.toml

# Expose the port
EXPOSE 8080

# Run the application
CMD ["./ddos_protection_service"] 