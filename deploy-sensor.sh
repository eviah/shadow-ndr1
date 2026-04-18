#!/bin/bash

# Shadow NDR Sensor Deployment Script v11.0

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  SHADOW NDR SENSOR v11.0 - DEPLOYMENT SCRIPT                  ║"
echo "╚════════════════════════════════════════════════════════════════╝"

# Configuration
SENSOR_BINARY="/c/Users/liorh/shadow-ndr/shadow-parsers/target/release/shadow-sensor.exe"
UDP_PORT=9999
KAFKA_BROKERS="localhost:9092"
WORKERS=4
SENSOR_ID="sensor-primary"

# Check binary exists
if [ ! -f "$SENSOR_BINARY" ]; then
    echo "❌ Binary not found: $SENSOR_BINARY"
    exit 1
fi

echo "✅ Binary found: $(ls -lh $SENSOR_BINARY | awk '{print $5, $9}')"

# Check if Kafka is running
echo ""
echo "🔍 Checking Kafka connectivity..."
if nc -z localhost 9092 2>/dev/null; then
    echo "✅ Kafka is running on localhost:9092"
else
    echo "⚠️  Kafka may not be running. Starting sensor anyway..."
fi

# Create log file
LOG_FILE="/c/Users/liorh/shadow-ndr/sensor.log"

echo ""
echo "📡 Starting Shadow-Sensor v11.0..."
echo "   UDP Port: $UDP_PORT"
echo "   Kafka Brokers: $KAFKA_BROKERS"
echo "   Workers: $WORKERS"
echo "   Sensor ID: $SENSOR_ID"
echo "   Log: $LOG_FILE"
echo ""

# Start sensor in background
"$SENSOR_BINARY" \
  --udp-port $UDP_PORT \
  --kafka-brokers $KAFKA_BROKERS \
  --workers $WORKERS \
  --sensor-id $SENSOR_ID \
  --verbose > "$LOG_FILE" 2>&1 &

SENSOR_PID=$!
echo "✅ Sensor started (PID: $SENSOR_PID)"

# Give it time to start
sleep 2

# Verify it's running
if kill -0 $SENSOR_PID 2>/dev/null; then
    echo "✅ Sensor is running"
else
    echo "❌ Sensor failed to start"
    cat "$LOG_FILE"
    exit 1
fi

echo ""
echo "🎉 Sensor deployment complete!"
echo ""
echo "📊 Monitor sensor:"
echo "   tail -f $LOG_FILE"
echo ""
echo "📤 Send test ADS-B frame:"
echo "   echo -n '8D3C5EF83FFEF85CFFF27CDACFC1' | xxd -r -p | nc -u localhost $UDP_PORT"
echo ""
echo "📡 Watch threats:"
echo "   kafka-console-consumer --bootstrap-server localhost:9092 --topic shadow.threats"
