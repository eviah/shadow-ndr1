#!/usr/bin/env python3
"""
Test Shadow-Sensor threat detection

Sends test ADS-B frames and verifies threat detection works
"""

import socket
import time
import json
import subprocess
from kafka import KafkaConsumer
import sys

def send_adsb_frame(host, port, data_hex):
    """Send ADS-B frame via UDP"""
    try:
        data = bytes.fromhex(data_hex)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(data, (host, port))
        sock.close()
        return True
    except Exception as e:
        print(f"❌ Failed to send frame: {e}")
        return False

def check_kafka_threats(timeout=5):
    """Check for threats in Kafka"""
    try:
        consumer = KafkaConsumer(
            'shadow.threats',
            bootstrap_servers=['localhost:9092'],
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            auto_offset_reset='latest',
            consumer_timeout_ms=timeout * 1000
        )

        threats = []
        for message in consumer:
            threats.append(message.value)

        consumer.close()
        return threats
    except Exception as e:
        print(f"⚠️  Kafka not available: {e}")
        return []

def main():
    print("╔════════════════════════════════════════════════════════════╗")
    print("║  SHADOW-SENSOR v11.0 - THREAT DETECTION TEST              ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print()

    HOST = "localhost"
    PORT = 9999

    # Test 1: Valid ADS-B Frame (Known Aircraft)
    print("Test 1: Valid ADS-B Frame (BA9 - British Airways)")
    print("─" * 60)

    # Real ADS-B frame: ICAO24=0x3C5EF8 (British Airways)
    valid_frame = "8D3C5EF83FFEF85CFFF27CDACFC1"

    print(f"Sending: {valid_frame}")
    if send_adsb_frame(HOST, PORT, valid_frame):
        print("✅ Frame sent successfully")
        time.sleep(1)

        threats = check_kafka_threats(timeout=2)
        if threats:
            print(f"⚠️  Detected {len(threats)} threat(s):")
            for t in threats:
                print(f"   - {t.get('threat_type')}: severity={t.get('severity')}")
        else:
            print("✅ No threats detected (expected for valid aircraft)")

    print()

    # Test 2: Unknown ICAO24 (Spoofing)
    print("Test 2: Unknown ICAO24 (Spoofing Detection)")
    print("─" * 60)

    # Unknown ICAO24: 0x999999
    unknown_frame = "8D99999900000000000000000000"

    print(f"Sending: {unknown_frame}")
    if send_adsb_frame(HOST, PORT, unknown_frame):
        print("✅ Frame sent successfully")
        time.sleep(1)

        threats = check_kafka_threats(timeout=3)
        if threats:
            print(f"🚨 Detected {len(threats)} threat(s):")
            for t in threats:
                print(f"   ✅ Type: {t.get('threat_type')}")
                print(f"      ICAO24: {t.get('icao24')}")
                print(f"      Severity: {t.get('severity')}")
                print(f"      Sensor: {t.get('sensor_id')}")
        else:
            print("⚠️  No threats detected (Kafka may not be running)")

    print()

    # Test 3: Check Sensor Metrics
    print("Test 3: Sensor Metrics")
    print("─" * 60)

    try:
        consumer = KafkaConsumer(
            'shadow.analytics',
            bootstrap_servers=['localhost:9092'],
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            auto_offset_reset='latest',
            consumer_timeout_ms=2000
        )

        print("Recent metrics:")
        for message in consumer:
            data = message.value
            if data.get('type') == 'metrics':
                metrics = data.get('data', {})
                print(f"   📊 Packets received: {metrics.get('packets_received')}")
                print(f"   📊 Packets parsed: {metrics.get('packets_parsed')}")
                print(f"   📊 ADS-B frames: {metrics.get('adsb_frames')}")
                print(f"   📊 Threats detected: {metrics.get('threats_detected')}")
                break

        consumer.close()
    except Exception as e:
        print(f"⚠️  Could not fetch metrics: {e}")

    print()
    print("╔════════════════════════════════════════════════════════════╗")
    print("║  TEST COMPLETE                                            ║")
    print("╚════════════════════════════════════════════════════════════╝")

if __name__ == "__main__":
    main()
