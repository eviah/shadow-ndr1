# Multistage Rust Builder for Shadow NDR Sensor
FROM rust:1.94-slim-bullseye AS builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsasl2-dev \
    cmake \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Build the enhanced sensor binary with all features
RUN cargo build --release --bin sensor-enhanced --features "full"

# Final runtime image
FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y \
    libssl1.1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/sensor-enhanced ./shadow-sensor

# Expose UDP port for Ads-B data
EXPOSE 9999/udp

# Run the sensor
CMD ["./shadow-sensor", "--sensor-id", "sensor-prod-1", "--kafka-brokers", "kafka:9092"]
