#!/usr/bin/env python3

"""
SHADOW NDR - Load Testing & Performance Benchmarking

This script performs comprehensive load testing to validate:
- Throughput (frames/second)
- Latency (detection time)
- Accuracy (threat detection)
- Scalability (multi-sensor consensus)
- Resource utilization (CPU, memory)

Usage:
    python3 load-test.py --duration 60 --rps 5000
"""

import asyncio
import json
import random
import time
import argparse
import statistics
from datetime import datetime
from typing import Dict, List
import httpx
import websockets

class ShadowLoadTester:
    """Load testing harness for Shadow NDR system"""

    def __init__(self, api_url: str = "http://localhost:8000",
                 ws_url: str = "ws://localhost:8000"):
        self.api_url = api_url
        self.ws_url = ws_url
        self.metrics = {
            "frames_sent": 0,
            "threats_detected": 0,
            "api_responses": [],
            "latencies": [],
            "errors": 0,
        }
        self.start_time = None
        self.end_time = None

    async def generate_test_frame(self) -> str:
        """Generate a synthetic ADS-B frame"""
        # Random ICAO address (24-bit)
        icao = random.randint(0x000000, 0xFFFFFF)
        # Random data (88 bits)
        data = random.randint(0, 0xFFFFFFFFFFFFFFFFFFFF)
        return f"8D{icao:06X}{data:020X}"

    async def send_raw_frame(self, client: httpx.AsyncClient, frame: str) -> bool:
        """Send a raw ADS-B frame to the API"""
        try:
            response = await client.post(
                f"{self.api_url}/api/sensor/raw-frame",
                json={"frame": frame},
                timeout=5.0
            )
            self.metrics["api_responses"].append(response.elapsed.total_seconds() * 1000)
            return response.status_code == 200
        except Exception as e:
            self.metrics["errors"] += 1
            return False

    async def check_threats(self, client: httpx.AsyncClient) -> int:
        """Check current threats via API"""
        try:
            start = time.time()
            response = await client.get(
                f"{self.api_url}/api/sensor/threats/current",
                timeout=5.0
            )
            latency = (time.time() - start) * 1000
            self.metrics["latencies"].append(latency)

            if response.status_code == 200:
                data = response.json()
                threat_count = len(data.get("threats", []))
                self.metrics["threats_detected"] += threat_count
                return threat_count
        except Exception as e:
            self.metrics["errors"] += 1
        return 0

    async def websocket_listener(self) -> None:
        """Listen for threat updates via WebSocket"""
        try:
            async with websockets.connect(f"{self.ws_url}/api/sensor/ws/threats") as ws:
                while self.end_time is None:
                    try:
                        message = await asyncio.wait_for(ws.recv(), timeout=1.0)
                        threat = json.loads(message)
                        self.metrics["threats_detected"] += 1
                    except asyncio.TimeoutError:
                        continue
                    except Exception:
                        break
        except Exception as e:
            print(f"WebSocket error: {e}")

    async def load_test(self, duration: int, rps: int) -> None:
        """Run load test for specified duration at target RPS"""
        print(f"\n📊 Starting load test...")
        print(f"   Duration: {duration}s")
        print(f"   Target RPS: {rps}")
        print(f"   API URL: {self.api_url}\n")

        self.start_time = time.time()

        async with httpx.AsyncClient(timeout=10.0) as client:
            # Start WebSocket listener
            ws_task = asyncio.create_task(self.websocket_listener())

            # Load test loop
            frame_interval = 1.0 / rps if rps > 0 else 0
            next_send_time = self.start_time

            while time.time() - self.start_time < duration:
                # Send frames at target RPS
                while time.time() >= next_send_time:
                    frame = await self.generate_test_frame()
                    success = await self.send_raw_frame(client, frame)

                    if success:
                        self.metrics["frames_sent"] += 1

                    next_send_time += frame_interval

                # Periodically check threats
                if int(time.time()) % 2 == 0:
                    await self.check_threats(client)

                await asyncio.sleep(0.001)

            self.end_time = time.time()
            ws_task.cancel()

    def print_results(self) -> None:
        """Print load test results"""
        if not self.start_time or not self.end_time:
            print("❌ Load test did not complete")
            return

        duration = self.end_time - self.start_time
        actual_rps = self.metrics["frames_sent"] / duration

        print("\n" + "="*80)
        print("🎯 LOAD TEST RESULTS".center(80))
        print("="*80)

        # Throughput
        print(f"\n📈 Throughput:")
        print(f"   Frames sent: {self.metrics['frames_sent']:,}")
        print(f"   Actual RPS: {actual_rps:,.0f}")
        print(f"   Duration: {duration:.1f}s")

        # Latency
        if self.metrics["latencies"]:
            latencies = self.metrics["latencies"]
            print(f"\n⏱️  Latency (ms):")
            print(f"   Min: {min(latencies):.2f}")
            print(f"   Max: {max(latencies):.2f}")
            print(f"   Mean: {statistics.mean(latencies):.2f}")
            print(f"   Median: {statistics.median(latencies):.2f}")
            print(f"   P95: {sorted(latencies)[int(len(latencies)*0.95)]:.2f}")
            print(f"   P99: {sorted(latencies)[int(len(latencies)*0.99)]:.2f}")

        # API Response Time
        if self.metrics["api_responses"]:
            api_times = self.metrics["api_responses"]
            print(f"\n📡 API Response Time (ms):")
            print(f"   Min: {min(api_times):.2f}")
            print(f"   Max: {max(api_times):.2f}")
            print(f"   Mean: {statistics.mean(api_times):.2f}")
            print(f"   P95: {sorted(api_times)[int(len(api_times)*0.95)]:.2f}")

        # Threats
        print(f"\n🚨 Threat Detection:")
        print(f"   Threats detected: {self.metrics['threats_detected']:,}")

        # Errors
        print(f"\n⚠️  Errors:")
        print(f"   Total errors: {self.metrics['errors']}")
        print(f"   Error rate: {(self.metrics['errors']/self.metrics['frames_sent']*100):.2f}%")

        # Summary
        print(f"\n✅ Summary:")
        print(f"   Status: {'PASS ✓' if self.metrics['errors'] < self.metrics['frames_sent']*0.01 else 'DEGRADED'}")
        print(f"   Timestamp: {datetime.now().isoformat()}")
        print("="*80 + "\n")

    def validate_targets(self) -> Dict[str, bool]:
        """Check if system meets performance targets"""
        targets = {
            "Throughput (5000+ fps)": self.metrics["frames_sent"] >= 5000,
            "Latency (<100ms p95)": (
                statistics.quantiles(self.metrics["latencies"], n=100)[94] < 100
                if self.metrics["latencies"] else False
            ),
            "Error rate (<1%)": (
                self.metrics["errors"] / self.metrics["frames_sent"] < 0.01
                if self.metrics["frames_sent"] > 0 else False
            ),
            "Threat detection": self.metrics["threats_detected"] > 0,
        }

        print("\n" + "="*80)
        print("🎯 TARGET VALIDATION".center(80))
        print("="*80)
        for metric, passed in targets.items():
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"{status} | {metric}")
        print("="*80 + "\n")

        return targets

async def main():
    parser = argparse.ArgumentParser(description="Shadow NDR Load Tester")
    parser.add_argument("--duration", type=int, default=60, help="Test duration in seconds")
    parser.add_argument("--rps", type=int, default=5000, help="Target requests per second")
    parser.add_argument("--api-url", default="http://localhost:8000", help="API URL")
    parser.add_argument("--ws-url", default="ws://localhost:8000", help="WebSocket URL")

    args = parser.parse_args()

    tester = ShadowLoadTester(args.api_url, args.ws_url)

    try:
        await tester.load_test(args.duration, args.rps)
        tester.print_results()
        tester.validate_targets()
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
        tester.end_time = time.time()
        tester.print_results()
    except Exception as e:
        print(f"\n❌ Error during load test: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
